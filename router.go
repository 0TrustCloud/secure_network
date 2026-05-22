package secure_network

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/gddisney/guikit"
	"github.com/gddisney/ultimate_db"
)

type Module interface {
	Name() string
	Init(router *Router) error
	Start() error
}

// ✨ FIX: Renamed to SystemEvent to prevent collision with gateway.go
type SystemEvent struct {
	Topic   string
	Payload []byte
}

// ✨ FIX: Added APIPayload universally so mesh.go, gateway.go, and tests can use it
type APIPayload struct {
	Action  string `json:"action"`
	Content string `json:"content"`
}

type Router struct {
	mu        sync.RWMutex
	Port      string
	TLSConfig *tls.Config

	Mux    *http.ServeMux
	GUIKit *guikit.GUIKit
	DB     *ultimate_db.DB

	TargetCookie string
	RouteMap     map[string]string

	Modules  map[string]Module
	LocalBus chan SystemEvent // ✨ FIX: Updated to SystemEvent
}

func NewRouter(db *ultimate_db.DB, gk *guikit.GUIKit, targetCookie string) (*Router, error) {
	tlsConf, err := generateEphemeralTLS()
	if err != nil {
		return nil, err
	}

	return &Router{
		TLSConfig:    tlsConf,
		Mux:          http.NewServeMux(),
		GUIKit:       gk,
		DB:           db,
		TargetCookie: targetCookie,
		RouteMap:     make(map[string]string),
		Modules:      make(map[string]Module),
		LocalBus:     make(chan SystemEvent, 2048), // ✨ FIX: Updated to SystemEvent
	}, nil
}

func (r *Router) Attach(mod Module) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Modules[mod.Name()] = mod
}

func (r *Router) Boot() {
	log.Println("[AURA] Booting Microkernel...")

	for name, mod := range r.Modules {
		if err := mod.Init(r); err != nil {
			log.Fatalf("[AURA] Kernel Panic: Module '%s' failed to init: %v", name, err)
		}
		go func(m Module, n string) {
			log.Printf("[AURA] Starting daemon: %s", n)
			if err := m.Start(); err != nil {
				log.Printf("[AURA] Module '%s' crashed: %v", n, err)
			}
		}(mod, name)
	}

	r.setupDBSCRoutes()
	if r.GUIKit != nil {
		r.Mux.Handle("/", r.GUIKit.Mux)
	}

	go r.startQUICTunnel()
	r.startDualStackIngress()
}

type dbscInterceptor struct {
	http.ResponseWriter
	router *Router
	req    *http.Request
	wrote  bool
}

func (w *dbscInterceptor) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true

	for _, cookie := range w.req.Cookies() {
		if cookie.Name == w.router.TargetCookie {
			yamlDomain := getDBSCDomain(w.router.RouteMap, w.req)
			w.Header().Set("Secure-Session-Registration", `(ES256 RS256); path="/StartSession"`)
			log.Printf("[DBSC] Injected Secure-Session-Registration for %s (Domain: %s)", cookie.Name, yamlDomain)
			break
		}
	}
	
	for _, cookieStr := range w.Header()["Set-Cookie"] {
		if strings.HasPrefix(cookieStr, w.router.TargetCookie+"=") {
			w.Header().Set("Secure-Session-Registration", `(ES256 RS256); path="/StartSession"`)
			break
		}
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *dbscInterceptor) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

func (w *dbscInterceptor) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying server does not support connection hijacking")
}

func (r *Router) startQUICTunnel() {
	tunnelPort := "9000"
	listener, err := quic.ListenAddr(":"+tunnelPort, r.TLSConfig, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	})
	if err != nil {
		log.Fatalf("[AURA] Failed to bind QUIC Tunnel backplane: %v", err)
	}

	log.Printf("[TUNNEL] QUIC Backplane active on UDP :%s", tunnelPort)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			continue
		}

		log.Printf("[TUNNEL] Secure QUIC connection established from %s", conn.RemoteAddr())

		r.mu.Lock()
		if r.ActiveTunnel != nil {
			r.ActiveTunnel.CloseWithError(0, "New tunnel took over")
		}
		r.ActiveTunnel = conn
		r.mu.Unlock()
	}
}

func (r *Router) proxyToTunnel(w http.ResponseWriter, req *http.Request) bool {
	r.mu.RLock()
	tunnel := r.ActiveTunnel
	r.mu.RUnlock()

	if tunnel == nil {
		return false
	}

	stream, err := tunnel.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("[TUNNEL] Failed to open QUIC stream: %v", err)
		return false
	}

	isWebSocket := strings.ToLower(req.Header.Get("Upgrade")) == "websocket"

	err = req.Write(stream)
	if err != nil {
		http.Error(w, "Failed to write to tunnel", http.StatusBadGateway)
		stream.Close()
		return true
	}

	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		http.Error(w, "Failed to read from tunnel", http.StatusBadGateway)
		stream.Close()
		return true
	}

	if isWebSocket && resp.StatusCode == http.StatusSwitchingProtocols {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Server doesn't support hijacking", http.StatusInternalServerError)
			stream.Close()
			return true
		}

		clientConn, clientBufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, "Hijack failed", http.StatusInternalServerError)
			stream.Close()
			return true
		}

		resp.Write(clientConn)

		go func() {
			defer clientConn.Close()
			defer stream.Close()
			if clientBufrw.Reader.Buffered() > 0 {
				io.CopyN(stream, clientBufrw.Reader, int64(clientBufrw.Reader.Buffered()))
			}
			io.Copy(stream, clientConn)
		}()

		go func() {
			defer clientConn.Close()
			defer stream.Close()
			if br.Buffered() > 0 {
				io.CopyN(clientConn, br, int64(br.Buffered()))
			}
			io.Copy(clientConn, stream)
		}()

		return true
	}

	defer resp.Body.Close()
	defer stream.Close()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	
	return true
}

func (r *Router) setupDBSCRoutes() {
	r.Mux.HandleFunc("/StartSession", func(w http.ResponseWriter, req *http.Request) {
		yamlDomain := getDBSCDomain(r.RouteMap, req)
		var cookieValue string
		if c, err := req.Cookie(r.TargetCookie); err == nil {
			cookieValue = c.Value
		}

		cookie := &http.Cookie{
			Name:     r.TargetCookie,
			Value:    cookieValue,
			MaxAge:   600,
			Domain:   yamlDomain,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)

		w.Header().Set("Content-Type", "application/json")
		jsonResponse := fmt.Sprintf(`{
			"session_identifier": "%s",
			"refresh_url": "/RefreshEndpoint",
			"credentials": [{"type": "cookie", "name": "%s", "attributes": "Domain=%s; Secure; SameSite=Lax"}]
		}`, cookieValue, r.TargetCookie, yamlDomain)
		w.Write([]byte(jsonResponse))
	})

	r.Mux.HandleFunc("/RefreshEndpoint", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if req.Header.Get("Secure-Session-Response") == "" {
			w.Header().Set("Secure-Session-Challenge", `"challenge_value_12345"`)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		yamlDomain := getDBSCDomain(r.RouteMap, req)
		var cookieValue string
		if c, err := req.Cookie(r.TargetCookie); err == nil {
			cookieValue = c.Value
		}

		cookie := &http.Cookie{
			Name:     r.TargetCookie,
			Value:    cookieValue,
			MaxAge:   600,
			Domain:   yamlDomain,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Session successfully bound and refreshed."))
	})
}

func (r *Router) startDualStackIngress() {
	masterHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		interceptor := &dbscInterceptor{ResponseWriter: w, router: r, req: req}

		var sessionCookie *http.Cookie
		for _, cookie := range req.Cookies() {
			if cookie.Name == r.TargetCookie {
				sessionCookie = cookie
				break
			}
		}
		if sessionCookie != nil {
			req.Header.Set("X-Secure-Session-Id", sessionCookie.Value)
		}

		if !r.proxyToTunnel(interceptor, req) {
			r.Mux.Serve
