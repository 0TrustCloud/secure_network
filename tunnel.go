package secure_network

import (
	"context"
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

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/service_keys"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/quic-go/quic-go"
)

type streamConn struct {
	*quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (s *streamConn) LocalAddr() net.Addr {
	return s.localAddr
}

func (s *streamConn) RemoteAddr() net.Addr {
	return s.remoteAddr
}

func (s *streamConn) SetDeadline(t time.Time) error {
	return nil
}

func (s *streamConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (s *streamConn) SetWriteDeadline(t time.Time) error {
	return nil
}

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
	skm        *service_keys.ServiceKeyManager
	Logger     *logger.LogDispatcher
	PublicPort string

	mu      sync.RWMutex
	tunnels map[string]quic.Conn
}

func NewTunnelManager(
	publicPort string,
	sysLog *logger.LogDispatcher,
) *TunnelManager {
	return &TunnelManager{
		PublicPort: publicPort,
		Logger:     sysLog,
		tunnels:    make(map[string]quic.Conn),
	}
}

func (t *TunnelManager) Name() string {
	return "mesh_tunnel"
}

func (t *TunnelManager) Init(r *Router) error {
	t.router = r
	t.db = r.DB
	t.pe = r.PolicyEngine
	t.sm = r.SessionManager
	t.skm = r.ServiceKeyManager
	return nil
}

func (t *TunnelManager) Start() error {
	if t.Logger != nil {
		t.Logger.Info(
			fmt.Sprintf(
				"Mesh Tunnel proxy online. Public Ingress: :%s",
				t.PublicPort,
			),
		)
	}

	go t.listenPublicHTTP()

	return nil
}

func (t *TunnelManager) RegisterTunnel(
	conn quic.Conn,
	authMsg []byte,
) error {

	var msg TunnelAuthPayload

	if err := json.Unmarshal(authMsg, &msg); err != nil {
		return fmt.Errorf("malformed tunnel auth payload")
	}

	subjectID, err := t.authenticate(msg)
	if err != nil {
		return err
	}

	if !t.pe.Evaluate(
		[]byte(subjectID),
		"bind",
		"tunnel:"+msg.Subdomain,
		nil,
	) {
		return fmt.Errorf("forbidden")
	}

	t.mu.Lock()

	if existing, ok := t.tunnels[msg.Subdomain]; ok {
		existing.CloseWithError(
			0,
			"subdomain claimed by new session",
		)
	}

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

func (t *TunnelManager) authenticate(
	msg TunnelAuthPayload,
) (string, error) {

	if msg.IdentityType == "human" {
		return t.sm.ValidateCookieToken(msg.Credential)
	}

	if msg.IdentityType == "machine" {
		var timestamp int64
		fmt.Sscanf(msg.Nonce, "%d", &timestamp)

		if time.Now().Unix()-timestamp > 60 {
			return "", fmt.Errorf("DBSC proof expired")
		}

		if t.skm == nil {
			return "", fmt.Errorf("service key manager uninitialized")
		}

		sig, err := base64.StdEncoding.DecodeString(msg.Credential)
		if err != nil {
			return "", err
		}

		payload := []byte(fmt.Sprintf("%s|%s", msg.Nonce, msg.Subdomain))

		if !t.skm.VerifySignature(msg.Identifier, payload, sig) {
			return "", fmt.Errorf("hardware signature verification failed")
		}

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
			DialContext: func(
				ctx context.Context,
				network string,
				addr string,
			) (net.Conn, error) {

				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}

				sub := strings.Split(host, ".")[0]

				t.mu.RLock()
				conn, ok := t.tunnels[sub]
				t.mu.RUnlock()

				if !ok {
					return nil, fmt.Errorf("tunnel offline")
				}

				stream, err := conn.OpenStreamSync(ctx)
				if err != nil {
					return nil, err
				}

				return &streamConn{
					Stream:     stream,
					localAddr:  conn.LocalAddr(),
					remoteAddr: conn.RemoteAddr(),
				}, nil
			},
		},
	}

	server := &http.Server{
		Addr:    ":" + t.PublicPort,
		Handler: proxy,
	}

	if err := server.ListenAndServe(); err != nil {
		if t.Logger != nil {
			t.Logger.Error(err.Error())
		}
	}
}

func RunMeshTunnelAgent(
	ctx context.Context,
	cfg TunnelAgentConfig,
	tlsConfig *tls.Config,
) error {

	tlsConfig.NextProtos = []string{"secure-overlay"}

	for {

		conn, err := quic.DialAddr(
			ctx,
			cfg.GatewayAddr,
			tlsConfig,
			&quic.Config{
				KeepAlivePeriod: 30 * time.Second,
			},
		)

		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		stream, err := conn.OpenStreamSync(ctx)
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

			msg.Credential, err = cfg.Signer(
				fmt.Sprintf("%s|%s", nonce, cfg.Subdomain),
			)

			if err != nil {
				conn.CloseWithError(0, "signing failed")
				continue
			}

		} else {

			msg.Credential = cfg.SessionToken
		}

		authBytes, err := json.Marshal(msg)
		if err != nil {
			conn.CloseWithError(0, "marshal failed")
			continue
		}

		reqBytes, err := json.Marshal(
			map[string]string{
				"action":  "tunnel_bind",
				"content": string(authBytes),
			},
		)

		if err != nil {
			conn.CloseWithError(0, "marshal failed")
			continue
		}

		_, err = stream.Write(reqBytes)
		if err != nil {
			conn.CloseWithError(0, "write failed")
			continue
		}

		for {

			incStream, err := conn.AcceptStream(ctx)
			if err != nil {
				break
			}

			go proxyStreamToLocal(incStream, cfg.LocalAddr)
		}

		time.Sleep(2 * time.Second)
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

func proxyStreamToLocal(
	stream *quic.Stream,
	localAddr string,
) {

	defer stream.Close()

	local, err := net.Dial("tcp", localAddr)
	if err != nil {
		return
	}

	defer local.Close()

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(local, stream)
	}()

	go func() {
		defer wg.Done()
		io.Copy(stream, local)
	}()

	wg.Wait()
}
