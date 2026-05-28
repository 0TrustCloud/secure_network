package secure_network

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/quic-go/quic-go"
)

type Mesh struct {
	conn quic.Conn

	cipher noise.CipherSuite

	staticPriv []byte
	staticPub  []byte

	rpc *RPCManager

	sendCipher *noise.CipherState
	recvCipher *noise.CipherState

	sessionMutex sync.RWMutex

	connected bool
}

func NewMesh(
	rpc *RPCManager,
	staticPriv []byte,
	staticPub []byte,
) *Mesh {

	return &Mesh{
		rpc: rpc,

		staticPriv: staticPriv,
		staticPub:  staticPub,

		cipher: noise.NewCipherSuite(
			noise.DH25519,
			noise.CipherAESGCM,
			noise.HashSHA256,
		),
	}
}

func (m *Mesh) Connect(
	addr string,
	tlsConfig *tls.Config,
) error {

	conn, err := quic.DialAddr(
		context.Background(),
		addr,
		tlsConfig,
		nil,
	)

	if err != nil {
		return err
	}

	m.conn = conn

	stream, err := conn.OpenStreamSync(
		context.Background(),
	)

	if err != nil {
		return err
	}

	hs, err := noise.NewHandshakeState(
		noise.Config{
			CipherSuite: m.cipher,
			Pattern:     noise.HandshakeIK,
			Initiator:   true,
			StaticKeypair: noise.DHKey{
				Private: m.staticPriv,
				Public:  m.staticPub,
			},
		},
	)

	if err != nil {
		return err
	}

	msg, csSend, csRecv, err := hs.WriteMessage(
		nil,
		nil,
	)

	if err != nil {
		return err
	}

	_, err = stream.Write(msg)

	if err != nil {
		return err
	}

	resp := make([]byte, 4096)

	n, err := stream.Read(resp)

	if err != nil {
		return err
	}

	_, _, _, err = hs.ReadMessage(
		nil,
		resp[:n],
	)

	if err != nil {
		return err
	}

	m.sendCipher = csSend
	m.recvCipher = csRecv

	m.connected = true

	go m.readLoop(stream)

	return nil
}

func (m *Mesh) readLoop(
	stream quic.Stream,
) {

	buf := make([]byte, MaxFrameSize)

	for {

		n, err := stream.Read(buf)

		if err != nil {
			m.connected = false
			return
		}

		decrypted, err := m.recvCipher.Decrypt(
			nil,
			nil,
			buf[:n],
		)

		if err != nil {
			continue
		}

		var envelope map[string]interface{}

		if err := json.Unmarshal(
			decrypted,
			&envelope,
		); err != nil {
			continue
		}

		if action, ok := envelope["action"].(string); ok {

			switch action {

			case "heartbeat":

				m.handleHeartbeat(
					stream,
				)

				continue

			case "signed_rpc":

				payloadBase64, ok :=
					envelope["payload"].(string)

				if !ok {
					continue
				}

				payload, err :=
					base64.StdEncoding.DecodeString(
						payloadBase64,
					)

				if err != nil {
					continue
				}

				m.rpc.handleIngress(
					context.Background(),
					payload,
				)

				continue
			}
		}
	}
}

func (m *Mesh) handleHeartbeat(
	stream quic.Stream,
) {

	resp := map[string]interface{}{
		"action": "heartbeat_ack",
		"time":   time.Now().Unix(),
	}

	raw, _ := json.Marshal(resp)

	enc, err := m.sendCipher.Encrypt(
		nil,
		nil,
		raw,
	)

	if err != nil {
		return
	}

	_, _ = stream.Write(enc)
}

func (m *Mesh) SendRPC(
	payload []byte,
) error {

	if !m.connected {
		return errors.New("mesh not connected")
	}

	stream, err := m.conn.OpenStreamSync(
		context.Background(),
	)

	if err != nil {
		return err
	}

	defer stream.Close()

	envelope := map[string]interface{}{
		"action": "signed_rpc",
		"payload": base64.StdEncoding.EncodeToString(
			payload,
		),
	}

	raw, err := json.Marshal(envelope)

	if err != nil {
		return err
	}

	enc, err := m.sendCipher.Encrypt(
		nil,
		nil,
		raw,
	)

	if err != nil {
		return err
	}

	_, err = stream.Write(enc)

	return err
}

func (m *Mesh) VerifySignedPayload(
	publicKey *rsa.PublicKey,
	payload []byte,
	signature []byte,
) error {

	hash := sha256.Sum256(payload)

	return rsa.VerifyPKCS1v15(
		publicKey,
		crypto.SHA256,
		hash[:],
		signature,
	)
}

func GenerateMeshNonce() string {

	buf := make([]byte, 32)

	_, _ = rand.Read(buf)

	return base64.StdEncoding.EncodeToString(
		buf,
	)
}

func (m *Mesh) Disconnect() error {

	m.connected = false

	if m.conn != nil {
		return m.conn.CloseWithError(
			0,
			"disconnect",
		)
	}

	return nil
}

func (m *Mesh) IsConnected() bool {
	return m.connected
}

func (m *Mesh) WaitForConnection(
	timeout time.Duration,
) error {

	start := time.Now()

	for {

		if m.connected {
			return nil
		}

		if time.Since(start) > timeout {
			return errors.New(
				"connection timeout",
			)
		}

		time.Sleep(
			100 * time.Millisecond,
		)
	}
}

func (m *Mesh) SendHeartbeat() error {

	if !m.connected {
		return errors.New(
			"mesh disconnected",
		)
	}

	stream, err := m.conn.OpenStreamSync(
		context.Background(),
	)

	if err != nil {
		return err
	}

	defer stream.Close()

	payload := map[string]interface{}{
		"action": "heartbeat",
		"time":   time.Now().Unix(),
	}

	raw, err := json.Marshal(payload)

	if err != nil {
		return err
	}

	enc, err := m.sendCipher.Encrypt(
		nil,
		nil,
		raw,
	)

	if err != nil {
		return err
	}

	_, err = stream.Write(enc)

	return err
}

func (m *Mesh) SecureBroadcast(
	payload []byte,
	privateKey *rsa.PrivateKey,
) ([]byte, error) {

	hash := sha256.Sum256(payload)

	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		crypto.SHA256,
		hash[:],
	)

	if err != nil {
		return nil, err
	}

	packet := map[string]interface{}{
		"payload": base64.StdEncoding.EncodeToString(
			payload,
		),
		"signature": base64.StdEncoding.EncodeToString(
			signature,
		),
		"timestamp": time.Now().Unix(),
	}

	return json.Marshal(packet)
}

func (m *Mesh) ValidateBroadcast(
	publicKey *rsa.PublicKey,
	packet []byte,
) error {

	var parsed map[string]interface{}

	if err := json.Unmarshal(
		packet,
		&parsed,
	); err != nil {
		return err
	}

	payloadEncoded, ok :=
		parsed["payload"].(string)

	if !ok {
		return errors.New(
			"missing payload",
		)
	}

	signatureEncoded, ok :=
		parsed["signature"].(string)

	if !ok {
		return errors.New(
			"missing signature",
		)
	}

	payload, err :=
		base64.StdEncoding.DecodeString(
			payloadEncoded,
		)

	if err != nil {
		return err
	}

	signature, err :=
		base64.StdEncoding.DecodeString(
			signatureEncoded,
		)

	if err != nil {
		return err
	}

	return m.VerifySignedPayload(
		publicKey,
		payload,
		signature,
	)
}
