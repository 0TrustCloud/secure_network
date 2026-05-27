package secure_network

import (
	"context"
	"crypto" // Added
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/quic-go/quic-go"
)

// streamConn adapts a quic.Stream to the net.Conn interface for ReverseProxy
type streamConn struct {
	quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s *streamConn) LocalAddr() net.Addr            { return s.localAddr }
func (s *streamConn) RemoteAddr() net.Addr           { return s.remoteAddr }
func (s *streamConn) SetDeadline(t time.Time) error  { return nil }
func (s *streamConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *streamConn) SetWriteDeadline(t time.Time) error { return nil }

type TunnelAuthPayload struct {
	Subdomain    string `json:"subdomain"`
	IdentityType string `json:"identity_type"`
	Identifier   string `json:"identifier"`
	Credential   string `json:"credential"`
	Nonce        string `json:"nonce"`
}

type TunnelManager struct {
	router     *Router
	db         *ultimate_db.DB
	pe         *secure_policy.PolicyEngine
	sm         *secure_policy.SessionManager
	Logger     *logger.LogDispatcher
	PublicPort string

	mu      sync.RWMutex
	tunnels map[string]quic.Connection
}

func NewTunnelManager(publicPort string, sysLog *logger.LogDispatcher) *TunnelManager {
	return &TunnelManager{
		PublicPort: publicPort,
		Logger:     sysLog,
		tunnels:    make(map[string]quic.Connection),
	}
}

func (t *TunnelManager) Name() string { return "mesh_tunnel" }

func (t *TunnelManager) Init(r *Router) error {
	t.router = r
	t.db = r.DB
	t.pe = r.PolicyEngine
	t.sm = r.SessionManager
	return nil
}

func (t *TunnelManager) Start() error {
	go t.listenPublicHTTP()
	return nil
}

func (t *TunnelManager) RegisterTunnel(conn quic.Connection, authMsg []byte) error {
	var msg TunnelAuthPayload
	if err := json.Unmarshal(authMsg, &msg); err != nil {
		return fmt.Errorf("malformed tunnel auth payload")
	}

	subjectID, err := t.authenticate(msg)
	if err != nil {
		return err
	}

	if !t.pe.Evaluate([]byte(subjectID), "bind", "tunnel:"+msg.Subdomain, nil) {
		return fmt.Errorf("forbidden")
	}

	t.mu.Lock()
	t.tunnels[msg.Subdomain] = conn
	t.mu.Unlock()

	go func() {
		<-conn.Context().Done()
		t.mu.Lock()
		delete(t.tunnels, msg.Subdomain)
		t.mu.Unlock()
	}()
	return nil
}

func (t *TunnelManager) authenticate(msg TunnelAuthPayload) (string, error) {
	if msg.IdentityType == "human" {
		return t.sm.ValidateCookieToken(msg.Credential)
	}

	// Machine Auth
	var timestamp int64
	fmt.Sscanf(msg.Nonce, "%d", &timestamp)
	
	txn := t.db.BeginTxn()
	userBytes, _ := t.db.Read(1, txn, []byte("user:"+msg.Identifier))
	t.db.CommitTxn(txn)
	
	var user webauthnext.PasskeyUser
	json.Unmarshal(userBytes, &user)
	tpmPubKey, _ := tpm2.DecodePublic(user.ID)
	cryptoKey, _ := tpmPubKey.Key()
	
	sig, _ := base64.StdEncoding.DecodeString(msg.Credential)
	payloadHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s", msg.Nonce, msg.Subdomain)))

	rsaKey := cryptoKey.(*rsa.PublicKey)
	err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, payloadHash[:], sig)
	if err != nil { return "", err }
	return msg.Identifier, nil
}

func (t *TunnelManager) listenPublicHTTP() {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				sub := strings.Split(addr, ".")[0]
				t.mu.RLock()
				conn, ok := t.tunnels[sub]
				t.mu.RUnlock()
				if !ok { return nil, fmt.Errorf("offline") }

				stream, err := conn.OpenStreamSync(ctx)
				if err != nil { return nil, err }
				
				return &streamConn{
					Stream:     stream, 
					localAddr:  conn.LocalAddr(), 
					remoteAddr: conn.RemoteAddr(),
				}, nil
			},
		},
	}
	http.ListenAndServe(":"+t.PublicPort, proxy)
}

func proxyStreamToLocal(stream quic.Stream, localAddr string) {
	defer stream.Close()
	local, err := net.Dial("tcp", localAddr)
	if err != nil { return }
	defer local.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	// Explicitly cast to interface
	go func() { defer wg.Done(); io.Copy(local, stream) }()
	go func() { defer wg.Done(); io.Copy(stream, local) }()
	wg.Wait()
}
