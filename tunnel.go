package secure_network

import (
	"context"
	"crypto"
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

// streamConn adapts a quic.Stream to the net.Conn interface for the ReverseProxy
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

// TunnelAuthPayload bridges machine and human identities for secure overlay routing.
type TunnelAuthPayload struct {
	Subdomain    string `json:"subdomain"`
	IdentityType string `json:"identity_type"` // "machine" or "human"
	Identifier   string `json:"identifier"`    // Service Name or Subject ID
	Credential   string `json:"credential"`    // DBSC Base64 Sig OR Session Cookie
	Nonce        string `json:"nonce"`         // Unix timestamp
}

// TunnelManager implements the Module interface
type TunnelManager struct {
	router     *Router
	db         *ultimate_db.DB
	pe         *secure_policy.PolicyEngine
	sm         *secure_policy.SessionManager
	Logger     *logger.LogDispatcher
	PublicPort string

	mu      sync.RWMutex
	tunnels map[string]quic.Conn
}

func NewTunnelManager(publicPort string, sysLog *logger.LogDispatcher) *TunnelManager {
	return &TunnelManager{
		PublicPort: publicPort,
		Logger:     sysLog,
		tunnels:    make(map[string]quic.Conn),
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
	if t.Logger != nil {
		t.Logger.Info(fmt.Sprintf("Mesh Tunnel proxy online. Public Ingress: :%s", t.PublicPort))
	}
	go t.listenPublicHTTP()
	return nil
}

// RegisterTunnel is called by the Gateway to bind a QUIC connection to a subdomain.
func (t *TunnelManager) RegisterTunnel(conn quic.Conn, authMsg []byte) error {
	var msg TunnelAuthPayload
	if err := json.Unmarshal(authMsg, &msg); err != nil {
		return fmt.Errorf("malformed tunnel auth payload")
	}

	subjectID, err := t.authenticate(msg)
	if err != nil {
		if t.Logger != nil {
			t.Logger.Audit(msg.Identifier, "TUNNEL_AUTH_FAILED", fmt.Sprintf("Rejected %s: %v", msg.Subdomain, err))
		}
		return err
	}

	resource := "tunnel:" + msg.Subdomain
	if !t.pe.Evaluate([]byte(subjectID), "bind", resource, nil) {
		return fmt.Errorf("forbidden by policy")
	}

	t.mu.Lock()
	if existing, ok := t.tunnels[msg.Subdomain]; ok {
		existing.CloseWithError(0, "Subdomain claimed by new session")
	}
	t.tunnels[msg.Subdomain] = conn
	t.mu.Unlock()

	if t.Logger != nil {
		t.Logger.Audit(subjectID, "TUNNEL_ESTABLISHED", "Bound to "+msg.Subdomain)
	}

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

	if msg.IdentityType == "machine" {
		var timestamp int64
		fmt.Sscanf(msg.Nonce, "%d", &timestamp)
		if time.Now().Unix()-timestamp > 60 {
			return "", fmt.Errorf("DBSC proof expired")
		}

		txn := t.db.BeginTxn()
		userBytes, err := t.db.Read(1, txn, []byte("user:"+msg.Identifier))
		t.db.CommitTxn(txn)
		if err != nil || len(userBytes) == 0 {
			return "", fmt.Errorf("identity not found")
		}

		var user webauthnext.PasskeyUser
		json.Unmarshal(userBytes, &user)

		tpmPubKey, err := tpm2.DecodePublic(user.ID)
		if err != nil { return "", err }

		cryptoKey, err := tpmPubKey.Key()
		if err != nil { return "", err }

		sig, err := base64.StdEncoding.DecodeString(msg.Credential)
		if err != nil { return "", err }

		payloadHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s", msg.Nonce, msg.Subdomain)))

		rsaKey := cryptoKey.(*rsa.PublicKey)
		err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, payloadHash[:], sig)
		if err != nil { return "", err }
		return msg.Identifier, nil
	}
	return "", fmt.Errorf("unknown identity")
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

func RunMeshTunnelAgent(ctx context.Context, cfg TunnelAgentConfig, tlsConfig *tls.Config) error {
	tlsConfig.NextProtos = []string{"secure-overlay"}
	for {
		conn, err := quic.DialAddr(ctx, cfg.GatewayAddr, tlsConfig, &quic.Config{KeepAlivePeriod: 30 * time.Second})
		if err != nil { time.Sleep(5 * time.Second); continue }

		stream, err := conn.OpenStreamSync(ctx)
		if err != nil { conn.CloseWithError(0, ""); continue }

		nonce := fmt.Sprintf("%d", time.Now().Unix())
		msg := TunnelAuthPayload{
			Subdomain: cfg.Subdomain, IdentityType: cfg.IdentityType, Identifier: cfg.Identifier, Nonce: nonce,
		}

		if cfg.IdentityType == "machine" && cfg.Signer != nil {
			msg.Credential, _ = cfg.Signer(fmt.Sprintf("%s|%s", nonce, cfg.Subdomain))
		} else {
			msg.Credential = cfg.SessionToken
		}

		authBytes, _ := json.Marshal(msg)
		reqBytes, _ := json.Marshal(map[string]string{"action": "tunnel_bind", "content": string(authBytes)})
		stream.Write(reqBytes)

		for {
			incStream, err := conn.AcceptStream(ctx)
			if err != nil { break }
			go proxyStreamToLocal(incStream, cfg.LocalAddr)
		}
	}
}

type TunnelAgentConfig struct {
	GatewayAddr  string
	LocalAddr    string
	Subdomain    string
	IdentityType string
	Identifier   string
	SessionToken string
	Signer       func(payload string) (string, error)
}

func proxyStreamToLocal(stream quic.Stream, localAddr string) {
	defer stream.Close()
	local, err := net.Dial("tcp", localAddr)
	if err != nil { return }
	defer local.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	// Cast stream to interface for io.Copy compatibility
	go func() { defer wg.Done(); io.Copy(local, stream.(io.Reader)) }()
	go func() { defer wg.Done(); io.Copy(stream.(io.Writer), local) }()
	wg.Wait()
}
