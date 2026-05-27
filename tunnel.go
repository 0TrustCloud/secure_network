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

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/quic-go/quic-go"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

// TunnelAuthPayload bridges machine and human identities for secure overlay routing.
type TunnelAuthPayload struct {
	Subdomain    string `json:"subdomain"`
	IdentityType string `json:"identity_type"` // "machine" or "human"
	Identifier   string `json:"identifier"`    // Service Name or Subject ID
	Credential   string `json:"credential"`    // DBSC Base64 Sig OR Session Cookie
	Nonce        string `json:"nonce"`         // Unix timestamp for replay protection
}

// streamConn adapts a quic.Stream to the net.Conn interface for the HTTP ReverseProxy.
type streamConn struct {
	quic.Stream
	conn quic.Connection
}

func (s *streamConn) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *streamConn) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// TunnelManager implements the Module interface to run alongside the Aura Microkernel.
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

// NewTunnelManager creates the mesh-native reverse tunnel module.
func NewTunnelManager(publicPort string, sysLog *logger.LogDispatcher) *TunnelManager {
	return &TunnelManager{
		PublicPort: publicPort,
		Logger:     sysLog,
		tunnels:    make(map[string]quic.Connection),
	}
}

// Name satisfies the Module interface.
func (t *TunnelManager) Name() string { return "mesh_tunnel" }

// Init satisfies the Module interface.
func (t *TunnelManager) Init(r *Router) error {
	t.router = r
	t.db = r.DB
	t.pe = r.PolicyEngine
	t.sm = r.SessionManager
	return nil
}

// Start satisfies the Module interface, launching the Public Ingress listener.
func (t *TunnelManager) Start() error {
	if t.Logger != nil {
		t.Logger.Info(fmt.Sprintf("Mesh Tunnel proxy online. Public Ingress: :%s", t.PublicPort))
	}

	go t.listenPublicHTTP()
	return nil
}

// ==========================================
// SERVER LOGIC (MESH PROXY & AUTH)
// ==========================================

// RegisterTunnel is called by the Gateway when a client requests a tunnel bind.
func (t *TunnelManager) RegisterTunnel(conn quic.Connection, authMsg []byte) error {
	var msg TunnelAuthPayload
	if err := json.Unmarshal(authMsg, &msg); err != nil {
		return fmt.Errorf("malformed tunnel auth payload")
	}

	// 1. Authenticate Identity
	subjectID, err := t.authenticate(msg)
	if err != nil {
		if t.Logger != nil {
			t.Logger.Audit(msg.Identifier, "TUNNEL_AUTH_FAILED", fmt.Sprintf("Rejected %s: %v", msg.Subdomain, err))
		}
		return err
	}

	// 2. Authorize via PBAC Zero-Trust Policy Engine
	resource := "tunnel:" + msg.Subdomain
	if !t.pe.Evaluate([]byte(subjectID), "bind", resource, nil) {
		if t.Logger != nil {
			t.Logger.Audit(subjectID, "TUNNEL_BIND_DENIED", fmt.Sprintf("Policy denied tunnel bind for subdomain: %s", msg.Subdomain))
		}
		return fmt.Errorf("forbidden by policy")
	}

	// 3. Register QUIC Connection
	t.mu.Lock()
	if existing, ok := t.tunnels[msg.Subdomain]; ok {
		existing.CloseWithError(0, "Subdomain claimed by new session")
	}
	t.tunnels[msg.Subdomain] = conn
	t.mu.Unlock()

	if t.Logger != nil {
		t.Logger.Audit(subjectID, "TUNNEL_ESTABLISHED", fmt.Sprintf("Native QUIC tunnel bound to %s.localhost", msg.Subdomain))
	}

	// Monitor disconnect
	go func() {
		<-conn.Context().Done()
		t.mu.Lock()
		if t.tunnels[msg.Subdomain] == conn {
			delete(t.tunnels, msg.Subdomain)
		}
		t.mu.Unlock()
		if t.Logger != nil {
			t.Logger.Info(fmt.Sprintf("Tunnel disconnected: %s", msg.Subdomain))
		}
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
		userBytes, err := t.db.Read(1 /* AuthPageID */, txn, []byte("user:"+msg.Identifier))
		t.db.CommitTxn(txn)

		if err != nil || len(userBytes) == 0 {
			return "", fmt.Errorf("machine identity not found")
		}

		var user webauthnext.PasskeyUser
		if err := json.Unmarshal(userBytes, &user); err != nil {
			return "", fmt.Errorf("corrupted identity record")
		}

		tpmPubKey, err := tpm2.DecodePublic(user.ID)
		if err != nil {
			return "", fmt.Errorf("failed to parse TPM key")
		}

		cryptoKey, err := tpmPubKey.Key()
		if err != nil {
			return "", fmt.Errorf("failed to extract crypto key")
		}

		signature, err := base64.StdEncoding.DecodeString(msg.Credential)
		if err != nil {
			return "", fmt.Errorf("invalid signature encoding")
		}

		payload := fmt.Sprintf("%s|%s", msg.Nonce, msg.Subdomain)
		payloadHash := sha256.Sum256([]byte(payload))

		rsaPubKey, ok := cryptoKey.(*rsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("unsupported TPM key type")
		}

		if err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, payloadHash[:], signature); err != nil {
			return "", fmt.Errorf("hardware signature verification failed")
		}

		return msg.Identifier, nil
	}

	return "", fmt.Errorf("unknown identity type")
}

func (t *TunnelManager) listenPublicHTTP() {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = req.Host
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				sub := strings.Split(strings.Split(addr, ":")[0], ".")[0]

				t.mu.RLock()
				conn, ok := t.tunnels[sub]
				t.mu.RUnlock()

				if !ok {
					return nil, fmt.Errorf("tunnel '%s' offline", sub)
				}

				// Multiplexing magic: Opens a new QUIC stream for this HTTP request
				stream, err := conn.OpenStreamSync(ctx)
				if err != nil {
					return nil, err
				}
				return &streamConn{Stream: stream, conn: conn}, nil
			},
		},
	}

	server := &http.Server{
		Addr: ":" + t.PublicPort,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub := strings.Split(r.Host, ".")[0]

			t.mu.RLock()
			_, ok := t.tunnels[sub]
			t.mu.RUnlock()

			if !ok {
				http.Error(w, fmt.Sprintf("Aura Mesh Tunnel '%s' offline", sub), http.StatusNotFound)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}

	server.ListenAndServe()
}

// ==========================================
// CLIENT AGENT (Embeddable)
// ==========================================

type TunnelAgentConfig struct {
	GatewayAddr  string
	LocalAddr    string
	Subdomain    string
	IdentityType string
	Identifier   string
	SessionToken string
	Signer       func(payload string) (string, error)
}

// RunMeshTunnelAgent connects the local application to the Aura Microkernel using native QUIC streams.
func RunMeshTunnelAgent(ctx context.Context, cfg TunnelAgentConfig, tlsConfig *tls.Config) error {
	tlsConfig.NextProtos = []string{"secure-overlay"}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := quic.DialAddr(context.Background(), cfg.GatewayAddr, tlsConfig, &quic.Config{
			KeepAlivePeriod: 30 * time.Second,
		})
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		stream, err := conn.OpenStreamSync(context.Background())
		if err != nil {
			conn.CloseWithError(0, "")
			continue
		}

		nonce := fmt.Sprintf("%d", time.Now().Unix())
		msg := TunnelAuthPayload{
			Subdomain:    cfg.Subdomain,
			IdentityType: cfg.IdentityType,
			Identifier:   cfg.Identifier,
			Nonce:        nonce,
		}

		if cfg.IdentityType == "machine" && cfg.Signer != nil {
			payload := fmt.Sprintf("%s|%s", nonce, cfg.Subdomain)
			sig, err := cfg.Signer(payload)
			if err != nil {
				conn.CloseWithError(0, "")
				return fmt.Errorf("failed to generate DBSC hardware proof: %w", err)
			}
			msg.Credential = sig
		} else {
			msg.Credential = cfg.SessionToken
		}

		// Send Bind Request over the initial stream
		authBytes, _ := json.Marshal(msg)
		apiReq := map[string]string{"action": "tunnel_bind", "content": string(authBytes)}
		reqBytes, _ := json.Marshal(apiReq)
		
		stream.Write(reqBytes)

		// Await streams from the Gateway
		for {
			incStream, err := conn.AcceptStream(context.Background())
			if err != nil {
				break // Connection dropped, reconnect loop triggers
			}
			go proxyStreamToLocal(incStream, cfg.LocalAddr)
		}
	}
}

func proxyStreamToLocal(stream quic.Stream, localAddr string) {
	defer stream.Close()

	local, err := net.Dial("tcp", localAddr)
	if err != nil {
		stream.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nLocal application offline."))
		return
	}
	defer local.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(local, stream) }()
	go func() { defer wg.Done(); io.Copy(stream, local) }()
	wg.Wait()
}
