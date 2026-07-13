package secure_network

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/0TrustCloud/auth_provider"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/flynn/noise"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/quic-go/quic-go"
)

type MeshNode struct {
	SdfEngine *secure_data_format.SecureDataEngine
	noisePriv []byte
	noisePub  []byte

	dbscPriv ed25519.PrivateKey
	gatePub  []byte

	cipher noise.CipherSuite

	conn   *quic.Conn
	stream *quic.Stream

	csSend *noise.CipherState
	csRecv *noise.CipherState

	writeMu sync.Mutex
	readMu  sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc

	rpc *RPCManager

	inboundHandlers map[string]PacketHandler

	Logger *logger.LogDispatcher
}

func loadOrGenerateKeys(sdf *secure_data_format.SecureDataEngine, sysLog *logger.LogDispatcher) ([]byte, []byte, ed25519.PrivateKey, error) {
	txn := sdf.Store.Begin()
	noisePriv, err1 := sdf.Store.Get(txn, []byte("data:mesh_noise_priv"))
	noisePub, err2 := sdf.Store.Get(txn, []byte("data:mesh_noise_pub"))
	dbscPrivRaw, err3 := sdf.Store.Get(txn, []byte("data:mesh_dbsc_priv"))
	txn.Commit()

	if err1 == nil && err2 == nil && err3 == nil {
		return noisePriv, noisePub, ed25519.PrivateKey(dbscPrivRaw), nil
	}

	if sysLog != nil {
		sysLog.Info("No mesh identity attributes discovered. Generating fresh keypair rows...")
	}

	cipher := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	kp, err := cipher.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	_, dbscPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	wTxn := sdf.Store.Begin()
	_ = sdf.Store.Put(wTxn, []byte("data:mesh_noise_priv"), kp.Private, 0)
	_ = sdf.Store.Put(wTxn, []byte("data:mesh_noise_pub"), kp.Public, 0)
	_ = sdf.Store.Put(wTxn, []byte("data:mesh_dbsc_priv"), []byte(dbscPriv), 0)
	if err := wTxn.Commit(); err != nil {
		return nil, nil, nil, err
	}

	return kp.Private, kp.Public, dbscPriv, nil
}

func NewMeshNode(sdf *secure_data_format.SecureDataEngine, gatePub []byte, sysLog *logger.LogDispatcher) (*MeshNode, error) {
	nPriv, nPub, dPriv, err := loadOrGenerateKeys(sdf, sysLog)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize mesh identity: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &MeshNode{
		SdfEngine: sdf,
		noisePriv: nPriv,
		noisePub:  nPub,
		dbscPriv:  dPriv,
		gatePub:   gatePub,
		cipher:    noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Logger:    sysLog,
		ctx:       ctx,
		cancel:          cancel,
		inboundHandlers: make(map[string]PacketHandler),
	}, nil
}

func (m *MeshNode) RegisterInbound(action string, handler PacketHandler) {
	if m.inboundHandlers == nil {
		m.inboundHandlers = make(map[string]PacketHandler)
	}
	m.inboundHandlers[action] = handler
}

func (m *MeshNode) SetRPCManager(rpc *RPCManager) { m.rpc = rpc }
func (m *MeshNode) GetNoisePubKey() []byte      { return m.noisePub }
func (m *MeshNode) GetDBSCPrivKey() ed25519.PrivateKey { return m.dbscPriv }

func (m *MeshNode) Connected() bool {
	return m.stream != nil && m.csSend != nil
}

func (m *MeshNode) Connect(ctx context.Context, gatewayAddr string) error {
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"secure-overlay"}}
	conn, err := quic.DialAddr(ctx, gatewayAddr, tlsConf, nil)
	if err != nil {
		return fmt.Errorf("mesh QUIC pipe initiation failed: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "failed opening initial stream frame")
		return err
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   m.cipher,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Private: m.noisePriv, Public: m.noisePub},
		PeerStatic:    m.gatePub,
	})
	if err != nil {
		conn.CloseWithError(0, "noise engine instantiation fault")
		return err
	}

	msg, csSend, csRecv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		conn.CloseWithError(0, "handshake serialization error")
		return err
	}

	script := fmt.Sprintf(`protocol:handshake(stage("initiator") status("transmitting"))`)
	tx := secure_data_format.DataInvocation{
		TargetAddress: "protocol:handshake:outbound",
		Caller:        base64.StdEncoding.EncodeToString(m.noisePub),
		Nonce:         0,
		Method:        "START_HANDSHAKE",
		Profile:       secure_data_format.ProfileProofOfPoss,
	}
	if _, err := m.SdfEngine.CompileSecureData(script, tx); err != nil {
		conn.CloseWithError(0, "policy constraint rejected transition")
		return fmt.Errorf("messaging state machine rejected protocol handshake context: %w", err)
	}

	if err := WriteFrame(stream, msg); err != nil {
		conn.CloseWithError(0, "failed flushing wire payload")
		return err
	}

	resp, err := ReadFrame(stream, MaxFrameSize)
	if err != nil {
		conn.CloseWithError(0, "failed extraction of responder stream context")
		return err
	}

	if _, _, _, err := hs.ReadMessage(nil, resp); err != nil {
		conn.CloseWithError(0, "handshake failed validation")
		return fmt.Errorf("remote gateway rejected Noise payload sequence: %w", err)
	}

	m.conn = conn
	m.stream = stream
	m.csSend = csSend
	m.csRecv = csRecv

	if m.Logger != nil {
		m.Logger.Info(fmt.Sprintf("Noise protocol handshake completed. Active Node ID: %x", m.noisePub[:8]))
	}

	go m.listenLoop()
	return nil
}

func (m *MeshNode) Close() error {
	m.cancel()
	if m.conn != nil {
		return m.conn.CloseWithError(0, "shutdown requested")
	}
	return nil
}

func (m *MeshNode) SendAction(payload APIPayload) error {
	if m.stream == nil || m.csSend == nil {
		return fmt.Errorf("mesh tunnel context unavailable")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	encrypted, err := m.csSend.Encrypt(nil, nil, data)
	if err != nil {
		return fmt.Errorf("frame layer cipher operation fault: %w", err)
	}

	return WriteFrame(m.stream, encrypted)
}

func (m *MeshNode) listenLoop() {
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		frame, err := ReadFrame(m.stream, MaxFrameSize)
		if err != nil {
			if m.Logger != nil {
				m.Logger.Error(fmt.Sprintf("Mesh stream session frame terminated: %v", err))
			}
			return
		}

		decrypted, err := m.csRecv.Decrypt(nil, nil, frame)
		if err != nil {
			if m.Logger != nil {
				m.Logger.Error(fmt.Sprintf("Noise protocol layer decryption failure: %v", err))
			}
			continue
		}

		var req APIPayload
		if err := json.Unmarshal(decrypted, &req); err != nil {
			continue
		}

		switch req.Action {
		case "dbsc_heartbeat_req":
			m.handleHeartbeat(req.Content)
		case "rpc":
			if m.rpc != nil {
				m.rpc.handleIngress(context.Background(), []byte(req.Content))
			}
		default:
			if handler, ok := m.inboundHandlers[req.Action]; ok && handler != nil {
				_ = handler.HandlePacket(m.ctx, req.Content)
			}
		}
	}
}

func (m *MeshNode) handleHeartbeat(challenge string) {
	hash := sha256.Sum256([]byte(challenge))
	sig, err := rsa.SignPKCS1v15(rand.Reader, nil, crypto.SHA256, hash[:])
	if err != nil {
		if m.Logger != nil {
			m.Logger.Error(fmt.Sprintf("Heartbeat signing operation failed: %v", err))
		}
		return
	}

	payload := APIPayload{
		Action:  "dbsc_heartbeat_resp",
		Content: base64.StdEncoding.EncodeToString(sig),
	}
	_ = m.SendAction(payload)
}

func (m *MeshNode) VerifyMachineIdentity(username string, nonce string, signature string, scope string) error {
	dataKey := "data:user:" + username
	txn := m.SdfEngine.Store.Begin()
	userBytes, err := m.SdfEngine.Store.Get(txn, []byte(dataKey))
	txn.Commit()

	if err != nil {
		return err
	}

	var user auth_provider.PasskeyUser
	if err := json.Unmarshal(userBytes, &user); err != nil {
		return err
	}

	tpmPubKey, err := tpm2.DecodePublic(user.ID)
	if err != nil {
		return err
	}

	cryptoKey, err := tpmPubKey.Key()
	if err != nil {
		return err
	}

	rsaKey, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid RSA hardware identity profile layout")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	payload := fmt.Sprintf("%s|%s", nonce, scope)
	hash := sha256.Sum256([]byte(payload))

	script := fmt.Sprintf(`identity:verification(user("%s") verification_type("machine_attestation"))`, username)
	tx := secure_data_format.DataInvocation{
		TargetAddress: "identity:check:hardware:" + username,
		Caller:        "mesh-network-verification-kernel",
		Nonce:         0,
		Method:        "VERIFY_MACHINE",
		Profile:       secure_data_format.ProfileProofOfPoss,
	}
	if _, err := m.SdfEngine.CompileSecureData(script, tx); err != nil {
		return fmt.Errorf("secure dataframe rule evaluation blocked authentication pipeline: %w", err)
	}

	return rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], sigBytes)
}
