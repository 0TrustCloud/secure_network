package secure_network

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/ultimate_db"
	"github.com/quic-go/quic-go"
)

const (
	ConfigPageID ultimate_db.PageID = 99
	TaskPageID   ultimate_db.PageID = 100
)

type MeshNode struct {
	db        *ultimate_db.DB
	noisePriv []byte
	noisePub  []byte
	dbscPriv  ed25519.PrivateKey
	gatePub   []byte
	cipher    noise.CipherSuite
	stream    *quic.Stream // Keeping the pointer here
	csSend    *noise.CipherState
	csRecv    *noise.CipherState
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
// Add these to secure_network/mesh.go
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
	// ✨ FIX: Removed the '&' because OpenStreamSync already returns the pointer type we need
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

	// ✨ FIX: Call stream functions directly
	if _, err = m.stream.Write(msg); err != nil {
		return fmt.Errorf("mesh stream write failed: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := m.stream.Read(buf)
	if err != nil {
		return fmt.Errorf("mesh stream read failed: %w", err)
	}

	if _, _, _, err = hs.ReadMessage(nil, buf[:n]); err != nil {
		return fmt.Errorf("mesh handshake rejected by Gateway: %w", err)
	}

	m.csSend = csSend
	m.csRecv = csRecv
	log.Printf("[SECURE_MESH] Overlay connected. Node PubKey: %x", m.noisePub[:8])

	go m.listen()

	return nil
}

func (m *MeshNode) SendAction(payload APIPayload) error {
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

	// ✨ FIX: Call stream functions directly
	_, err = m.stream.Write(encrypted)
	return err
}

func (m *MeshNode) listen() {
	buf := make([]byte, 4096)
	for {
		// ✨ FIX: Call stream functions directly
		n, err := m.stream.Read(buf)
		if err != nil {
			log.Printf("[SECURE_MESH] Stream closed or read error: %v", err)
			break
		}

		decrypted, err := m.csRecv.Decrypt(nil, nil, buf[:n])
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
