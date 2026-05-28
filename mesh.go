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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/flynn/noise"
	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/quic-go/quic-go"
)

const (
	ConfigPageID ultimate_db.PageID = 99
	TaskPageID   ultimate_db.PageID = 100
)

type MeshNode struct {
	db *ultimate_db.DB

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

	serviceKeys *service_keys.ServiceKeyManager

	Logger *logger.LogDispatcher
}

func loadOrGenerateKeys(
	db *ultimate_db.DB,
	sysLog *logger.LogDispatcher,
) ([]byte, []byte, ed25519.PrivateKey, error) {

	txn := db.BeginTxn()
	defer db.CommitTxn(txn)

	noisePriv, err1 := db.Read(
		ConfigPageID,
		txn,
		[]byte("mesh_noise_priv"),
	)

	noisePub, err2 := db.Read(
		ConfigPageID,
		txn,
		[]byte("mesh_noise_pub"),
	)

	dbscPrivRaw, err3 := db.Read(
		ConfigPageID,
		txn,
		[]byte("mesh_dbsc_priv"),
	)

	if err1 == nil &&
		err2 == nil &&
		err3 == nil {

		return noisePriv,
			noisePub,
			ed25519.PrivateKey(dbscPrivRaw),
			nil
	}

	if sysLog != nil {
		sysLog.Info(
			"No mesh identity found. Generating new node keys...",
		)
	}

	cipher := noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherAESGCM,
		noise.HashSHA256,
	)

	kp, err := cipher.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	_, dbscPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := db.Write(
		ConfigPageID,
		txn,
		[]byte("mesh_noise_priv"),
		kp.Private,
		0,
	); err != nil {
		return nil, nil, nil, err
	}

	if err := db.Write(
		ConfigPageID,
		txn,
		[]byte("mesh_noise_pub"),
		kp.Public,
		0,
	); err != nil {
		return nil, nil, nil, err
	}

	if err := db.Write(
		ConfigPageID,
		txn,
		[]byte("mesh_dbsc_priv"),
		[]byte(dbscPriv),
		0,
	); err != nil {
		return nil, nil, nil, err
	}

	return kp.Private,
		kp.Public,
		dbscPriv,
		nil
}

func NewMeshNode(
	db *ultimate_db.DB,
	gatePub []byte,
	skm *service_keys.ServiceKeyManager,
	sysLog *logger.LogDispatcher,
) (*MeshNode, error) {

	nPriv,
		nPub,
		dPriv,
		err := loadOrGenerateKeys(
		db,
		sysLog,
	)

	if err != nil {
		return nil,
			fmt.Errorf(
				"failed to initialize mesh identity: %w",
				err,
			)
	}

	ctx, cancel := context.WithCancel(
		context.Background(),
	)

	node := &MeshNode{
		db:          db,
		noisePriv:   nPriv,
		noisePub:    nPub,
		dbscPriv:    dPriv,
		gatePub:     gatePub,
		cipher:      noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		serviceKeys: skm,
		Logger:      sysLog,
		ctx:         ctx,
		cancel:      cancel,
	}

	return node, nil
}

func (m *MeshNode) SetRPCManager(
	rpc *RPCManager,
) {
	m.rpc = rpc
}

func (m *MeshNode) GetNoisePubKey() []byte {
	return m.noisePub
}

func (m *MeshNode) GetDBSCPrivKey() ed25519.PrivateKey {
	return m.dbscPriv
}

func (m *MeshNode) Connect(
	ctx context.Context,
	gatewayAddr string,
) error {

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"secure-overlay"},
	}

	conn, err := quic.DialAddr(
		ctx,
		gatewayAddr,
		tlsConf,
		nil,
	)

	if err != nil {
		return fmt.Errorf(
			"mesh QUIC dial failed: %w",
			err,
		)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return err
	}

	hs, err := noise.NewHandshakeState(
		noise.Config{
			CipherSuite: m.cipher,
			Random:      rand.Reader,
			Pattern:     noise.HandshakeIK,
			Initiator:   true,
			StaticKeypair: noise.DHKey{
				Private: m.noisePriv,
				Public:  m.noisePub,
			},
			PeerStatic: m.gatePub,
		},
	)

	if err != nil {
		conn.CloseWithError(0, "noise init failed")
		return err
	}

	msg, csSend, csRecv, err := hs.WriteMessage(
		nil,
		nil,
	)

	if err != nil {
		conn.CloseWithError(0, "noise write failed")
		return err
	}

	if err := WriteFrame(
		stream,
		msg,
	); err != nil {

		conn.CloseWithError(
			0,
			"handshake send failed",
		)

		return err
	}

	resp, err := ReadFrame(
		stream,
		MaxFrameSize,
	)

	if err != nil {
		conn.CloseWithError(
			0,
			"handshake read failed",
		)

		return err
	}

	if _, _, _, err := hs.ReadMessage(
		nil,
		resp,
	); err != nil {

		conn.CloseWithError(
			0,
			"handshake rejected",
		)

		return fmt.Errorf(
			"gateway rejected Noise handshake: %w",
			err,
		)
	}

	m.conn = &conn
	m.stream = &stream
	m.csSend = csSend
	m.csRecv = csRecv

	if m.Logger != nil {

		m.Logger.Info(
			fmt.Sprintf(
				"Mesh overlay connected. Node: %x",
				m.noisePub[:8],
			),
		)
	}

	go m.listenLoop()

	return nil
}

func (m *MeshNode) Close() error {

	m.cancel()

	if m.conn != nil {

		return (*m.conn).CloseWithError(
			0,
			"shutdown",
		)
	}

	return nil
}

func (m *MeshNode) SendAction(
	payload APIPayload,
) error {

	if m.stream == nil ||
		m.csSend == nil {

		return fmt.Errorf(
			"mesh tunnel not established",
		)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	m.writeMu.Lock()
	defer m.writeMu.Unlock()

	encrypted, err := m.csSend.Encrypt(
		nil,
		nil,
		data,
	)

	if err != nil {

		return fmt.Errorf(
			"noise encryption failed: %w",
			err,
		)
	}

	return WriteFrame(
		m.stream,
		encrypted,
	)
}

func (m *MeshNode) listenLoop() {

	for {

		select {

		case <-m.ctx.Done():
			return

		default:
		}

		frame, err := ReadFrame(
			m.stream,
			MaxFrameSize,
		)

		if err != nil {

			if m.Logger != nil {

				m.Logger.Error(
					fmt.Sprintf(
						"Mesh stream closed: %v",
						err,
					),
				)
			}

			return
		}

		decrypted, err := m.csRecv.Decrypt(
			nil,
			nil,
			frame,
		)

		if err != nil {

			if m.Logger != nil {

				m.Logger.Error(
					fmt.Sprintf(
						"Noise decrypt failed: %v",
						err,
					),
				)
			}

			continue
		}

		var req APIPayload

		if err := json.Unmarshal(
			decrypted,
			&req,
		); err != nil {

			continue
		}

		switch req.Action {

		case "dbsc_heartbeat_req":

			m.handleHeartbeat(
				req.Content,
			)

		case "rpc":

			if m.rpc != nil {

				m.rpc.handleIngress(
					context.Background(),
					[]byte(req.Content),
				)
			}
		}
	}
}

func (m *MeshNode) handleHeartbeat(
	challenge string,
) {

	hash := sha256.Sum256(
		[]byte(challenge),
	)

	sig, err := rsa.SignPKCS1v15(
		rand.Reader,
		nil,
		crypto.SHA256,
		hash[:],
	)

	if err != nil {

		if m.Logger != nil {

			m.Logger.Error(
				fmt.Sprintf(
					"Heartbeat signing failed: %v",
					err,
				),
			)
		}

		return
	}

	payload := APIPayload{
		Action: "dbsc_heartbeat_resp",
		Content: base64.StdEncoding.EncodeToString(
			sig,
		),
	}

	_ = m.SendAction(payload)
}

func (m *MeshNode) VerifyMachineIdentity(
	username string,
	nonce string,
	signature string,
	scope string,
) error {

	txn := m.db.BeginTxn()
	defer m.db.CommitTxn(txn)

	userBytes, err := m.db.Read(
		IdentityPageID,
		txn,
		[]byte("user:"+username),
	)

	if err != nil {
		return err
	}

	var user webauthnext.PasskeyUser

	if err := json.Unmarshal(
		userBytes,
		&user,
	); err != nil {
		return err
	}

	tpmPubKey, err := tpm2.DecodePublic(
		user.ID,
	)

	if err != nil {
		return err
	}

	cryptoKey, err := tpmPubKey.Key()
	if err != nil {
		return err
	}

	rsaKey, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid RSA public key")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(
		signature,
	)

	if err != nil {
		return err
	}

	hash := sha256.Sum256(
		[]byte(
			fmt.Sprintf(
				"%s|%s",
				nonce,
				scope,
			),
		),
	)

	return rsa.VerifyPKCS1v15(
		rsaKey,
		crypto.SHA256,
		hash[:],
		sigBytes,
	)
}

func WriteFrame(
	w io.Writer,
	payload []byte,
) error {

	size := uint32(len(payload))

	var hdr [4]byte

	binary.BigEndian.PutUint32(
		hdr[:],
		size,
	)

	if _, err := w.Write(
		hdr[:],
	); err != nil {

		return err
	}

	_, err := w.Write(payload)

	return err
}

func ReadFrame(
	r io.Reader,
	maxSize uint32,
) ([]byte, error) {

	var hdr [4]byte

	if _, err := io.ReadFull(
		r,
		hdr[:],
	); err != nil {

		return nil, err
	}

	size := binary.BigEndian.Uint32(
		hdr[:],
	)

	if size == 0 {

		return nil,
			fmt.Errorf(
				"empty frame",
			)
	}

	if size > maxSize {

		return nil,
			fmt.Errorf(
				"frame exceeds max size",
			)
	}

	buf := make([]byte, size)

	_, err := io.ReadFull(
		r,
		buf,
	)

	return buf, err
}
