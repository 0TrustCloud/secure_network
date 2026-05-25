package secure_network

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/ultimate_db"
	"github.com/quic-go/quic-go"
)

const (
	ConfigPageID ultimate_db.PageID = 99
	TaskPageID   ultimate_db.PageID = 100
)

// NOTE: APIPayload has been removed from this file to prevent redeclaration 
// conflicts since it is already defined in gateway.go.

type MeshNode struct {
	db        *ultimate_db.DB
	noisePriv []byte
	noisePub  []byte
	dbscPriv  ed25519.PrivateKey
	gatePub   []byte
	cipher    noise.CipherSuite
	stream    quic.Stream // Clean interface allocation (not a pointer-to-interface)
	csSend    *noise.CipherState
	csRecv    *noise.CipherState
	writeMu   sync.Mutex  // Guards concurrent stream serialization
}

func loadOrGenerateKeys(db *ultimate_db.DB) ([]byte, []byte, ed25519.PrivateKey, error) {
	txn := db.BeginTxn()
	defer db.CommitTxn(txn)

	noisePriv, err1 := db.Read(ConfigPageID, txn, []byte("mesh_noise_priv"))
	noisePub, err2 := db.Read(ConfigPageID, txn, []byte("mesh_noise_pub"))
	dbscPrivRaw, err3 := db.Read(ConfigPageID, txn, []byte("mesh_dbsc_priv"))

	if err1 == nil && err2 == nil && err3 == nil {
		return noisePriv, noisePub, ed25519.PrivateKey(dbscPrivRaw), nil
	}

	log.Println("[SECURE_MESH] No local identity found. Generating new node keys...")

	cipher := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	kp, err := cipher.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	_, dbscPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	db.Write(ConfigPageID, txn, []byte("mesh_noise_priv"), kp.Private, 0)
	db.Write(ConfigPageID, txn, []byte("mesh_noise_pub"), kp.Public, 0)
	db.Write(ConfigPageID, txn, []byte("mesh_dbsc_priv"), []byte(dbscPriv), 0)

	return kp.Private, kp.Public, dbscPriv, nil
}

func (m *MeshNode) GetNoisePubKey() []byte {
	return m.noisePub
}

func (m *MeshNode) GetDBSCPrivKey() ed25519.PrivateKey {
	return m.dbscPriv
}

func NewMeshNode(db *ultimate_db.DB, gatePub []byte) (*MeshNode, error) {
	nPriv, nPub, dPriv, err := loadOrGenerateKeys(db)
	if err != nil {
		return nil, fmt.Errorf("failed to init local keys: %w", err)
	}

	return &MeshNode{
		db:        db,
		noisePriv: nPriv,
		noisePub:  nPub,
		dbscPriv:  dPriv,
		gatePub:   gatePub,
		cipher:    noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
	}, nil
}

func (m *MeshNode) Connect(gatewayAddr string) error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"secure-overlay"},
	}

	conn, err := quic.DialAddr(context.Background(), gatewayAddr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("mesh quic dial failed: %w", err)
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("mesh stream open failed: %w", err)
	}
	m.stream = stream

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   m.cipher,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Private: m.noisePriv, Public: m.noisePub},
		PeerStatic:    m.gatePub,
	})
	if err != nil {
		return fmt.Errorf("mesh handshake init failed: %w", err)
	}

	msg, csSend, csRecv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return fmt.Errorf("mesh write message failed: %w", err)
	}

	// Frame and write the initial Noise handshake frame
	if err = m.writeFramed(msg); err != nil {
		return fmt.Errorf("mesh stream write failed: %w", err)
	}

	// Read and resolve the response handshake frame safely
	respBuf, err := m.readFramed()
	if err != nil {
		return fmt.Errorf("mesh stream read failed: %w", err)
	}

	if _, _, _, err = hs.ReadMessage(nil, respBuf); err != nil {
		return fmt.Errorf("mesh handshake rejected by Gateway: %w", err)
	}

	m.csSend = csSend
	m.csRecv = csRecv
	log.Printf("[SECURE_MESH] Overlay connected. Node PubKey: %x", m.noisePub[:8])

	go m.listen()

	return nil
}

func (m *MeshNode) SendAction(payload APIPayload) error {
	// Clean interface check against nil
	if m.csSend == nil || m.stream == nil {
		return fmt.Errorf("mesh tunnel is not established")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	encrypted, err := m.csSend.Encrypt(nil, nil, data)
	if err != nil {
		return fmt.Errorf("mesh encryption failed: %w", err)
	}

	return m.writeFramed(encrypted)
}

func (m *MeshNode) listen() {
	for {
		buf, err := m.readFramed()
		if err != nil {
			log.Printf("[SECURE_MESH] Stream closed or read error: %v", err)
			break
		}

		decrypted, err := m.csRecv.Decrypt(nil, nil, buf)
		if err != nil {
			log.Printf("[SECURE_MESH] Decryption failed on incoming message: %v", err)
			continue
		}

		var req APIPayload
		if err := json.Unmarshal(decrypted, &req); err != nil {
			continue
		}

		if req.Action == "dbsc_heartbeat_req" {
			challenge := []byte(req.Content)
			signature := ed25519.Sign(m.dbscPriv, challenge)
			encodedSig := base64.StdEncoding.EncodeToString(signature)

			m.SendAction(APIPayload{
				Action:  "dbsc_heartbeat_resp",
				Content: encodedSig,
			})
			continue
		}

		txnID := m.db.BeginTxn()
		taskID := fmt.Sprintf("task:%d", time.Now().UnixNano()) 
		
		err = m.db.Write(TaskPageID, txnID, []byte(taskID), decrypted, 0)
		m.db.CommitTxn(txnID)

		if err != nil {
			log.Printf("[SECURE_MESH] Failed to persist task %s: %v", taskID, err)
		} else {
			log.Printf("[SECURE_MESH] Ingress task written to DB. Action: %s", req.Action)
		}
	}
}

// Helper: Thread-safe, length-prefixed stream framing writer
func (m *MeshNode) writeFramed(data []byte) error {
	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	length := uint32(len(data))
	if err := binary.Write(m.stream, binary.BigEndian, length); err != nil {
		return err
	}

	_, err := m.stream.Write(data)
	return err
}

// Helper: Length-prefixed stream framing reader
func (m *MeshNode) readFramed() ([]byte, error) {
	var length uint32
	if err := binary.Read(m.stream, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(m.stream, buf); err != nil {
		return nil, err
	}

	return buf, nil
}
