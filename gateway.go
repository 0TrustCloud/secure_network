package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/flynn/noise"
	"github.com/quic-go/quic-go"
)

type APIPayload struct {
	Action  string `json:"action"`
	Content string `json:"content,omitempty"`
	Target  string `json:"target,omitempty"`
	Value   int    `json:"value,omitempty"`
}

type ContentMeta struct {
	Signer    []byte `json:"signer"`
	Content   string `json:"content,omitempty"`
	Target    string `json:"target,omitempty"`
	Value     int    `json:"value,omitempty"`
	CreatedAt int64  `json:"created_at"`
}

type hostPeer struct {
	stream *quic.Stream
	csSend *noise.CipherState
	signer []byte
}

type Gateway struct {
	router         *Router
	peerMesh       *PeerRoute
	cipher         noise.CipherSuite
	sPriv          []byte
	sPub           []byte
	Logger         *logger.LogDispatcher
	activeSessions sync.Map
	hostSessions   sync.Map
}

func NewGateway(r *Router, peerMesh *PeerRoute, sPriv, sPub []byte, sysLog *logger.LogDispatcher) *Gateway {
	return &Gateway{
		router:   r,
		peerMesh: peerMesh,
		cipher:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		sPriv:    sPriv,
		sPub:     sPub,
		Logger:   sysLog,
	}
}

func (g *Gateway) SetApplicationHandler(handler http.HandlerFunc) {
	if g.router != nil {
		g.router.Mux.Handle("/", handler)
	}
}

func (g *Gateway) ListenAndServe(port string, tlsConfig *tls.Config) error {
	if g.router != nil {
		g.router.Port = port
		if tlsConfig != nil {
			g.router.TLSConfig = tlsConfig
		}
		g.router.Boot()
	}
	return nil
}

func (g *Gateway) HandleSecureStream(conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   g.cipher,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: g.sPriv, Public: g.sPub},
	})
	if err != nil {
		if g.Logger != nil {
			g.Logger.Error(fmt.Sprintf("Gateway handshake creation failed: %v", err))
		}
		return
	}

	frame, err := ReadFrame(stream, MaxFrameSize)
	if err != nil {
		return
	}

	_, _, _, err = hs.ReadMessage(nil, frame)
	if err != nil {
		return
	}

	remoteKey := hs.PeerStatic()
	if !g.isIdentityValid(remoteKey) {
		if g.Logger != nil {
			g.Logger.Audit("system_gateway", "TUNNEL_REJECTED", fmt.Sprintf("Revoked context public key: %x", remoteKey[:8]))
		}
		return
	}

	respMsg, csSend, csRecv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return
	}

	script := fmt.Sprintf(`protocol:handshake(stage("responder") status("established"))`)
	tx := secure_data_format.DataInvocation{
		TargetAddress: "protocol:handshake:inbound",
		Caller:        base64.StdEncoding.EncodeToString(remoteKey),
		Nonce:         uint64(time.Now().UnixNano()),
		Method:        "ESTABLISH_TUNNEL",
		Profile:       secure_data_format.ProfileProofOfPoss,
	}
	if _, err := g.router.SdfEngine.CompileSecureData(script, tx); err != nil {
		if g.Logger != nil {
			g.Logger.Error(fmt.Sprintf("SDF dataframe validation failed to clear tunnel binding for %x", remoteKey[:8]))
		}
		return
	}

	if err := WriteFrame(stream, respMsg); err != nil {
		return
	}

	sessionID := string(remoteKey)
	g.activeSessions.Store(sessionID, time.Now().Unix())

	stopHeartbeat := make(chan struct{})
	defer close(stopHeartbeat)

	go g.monitorHeartbeat(stream, csSend, remoteKey, stopHeartbeat)

	if g.Logger != nil {
		g.Logger.Audit(fmt.Sprintf("%x", remoteKey[:8]), "TUNNEL_ESTABLISHED", "Secure QUIC tunnel verified via dynamic messaging state machine")
	}

	for {
		frame, err := ReadFrame(stream, MaxFrameSize)
		if err != nil {
			break
		}

		decrypted, err := csRecv.Decrypt(nil, nil, frame)
		if err != nil {
			continue
		}

		var req APIPayload
		if err := json.Unmarshal(decrypted, &req); err == nil {
			if req.Action == "tunnel_bind" {
				if mod, exists := g.router.Modules["mesh_tunnel"]; exists {
					tunnelManager, ok := mod.(*TunnelManager)
					if !ok {
						continue
					}

					err := tunnelManager.RegisterTunnel(conn, []byte(req.Content))
					if err != nil {
						_ = WriteFrame(stream, []byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
					}
					return
				}
			}
		}

		g.routeToAPI(remoteKey, decrypted, stream, csSend)
	}

	g.activeSessions.Delete(sessionID)
	g.clearHostSessions(remoteKey)
}

func (g *Gateway) isIdentityValid(pubKey []byte) bool {
	return g.router.PolicyEngine.HasPermission(pubKey, "network:connect")
}

func (g *Gateway) monitorHeartbeat(stream *quic.Stream, csSend *noise.CipherState, signer []byte, stop <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lastSeen, ok := g.activeSessions.Load(string(signer))
			if !ok || time.Now().Unix()-lastSeen.(int64) > 180 {
				stream.Close()
				return
			}

			challenge := make([]byte, 32)
			_, _ = rand.Read(challenge)

			payload := APIPayload{Action: "dbsc_heartbeat_req", Content: string(challenge)}
			data, _ := json.Marshal(payload)
			enc, _ := csSend.Encrypt(nil, nil, data)

			if err := WriteFrame(stream, enc); err != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func (g *Gateway) routeToAPI(signer []byte, payload []byte, stream *quic.Stream, csSend *noise.CipherState) {
	var req APIPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		return
	}

	if req.Action == "mesh_register" {
		var reg struct {
			HostID string `json:"host_id"`
		}
		if json.Unmarshal([]byte(req.Content), &reg) == nil && reg.HostID != "" {
			g.hostSessions.Store(reg.HostID, &hostPeer{stream: stream, csSend: csSend, signer: signer})
			if g.Logger != nil {
				g.Logger.Info(fmt.Sprintf("Mesh host registered: %s (%x)", reg.HostID, signer[:8]))
			}
		}
		return
	}

	contextData := map[string]string{"target": req.Target}
	resource := req.Target
	if strings.HasPrefix(resource, "host:") {
		switch req.Action {
		case "ssh_proto":
			resource = "ssh:exec"
		case "k8s_proto":
			resource = "k8s:exec"
		}
	}
	if resource == "" {
		resource = "*"
	}

	if !g.router.PolicyEngine.Evaluate(signer, req.Action, resource, contextData) {
		if g.Logger != nil {
			g.Logger.Audit(fmt.Sprintf("%x", signer[:8]), "MESH_DENIED", "Gateway security evaluation block intercepted action: "+req.Action)
		}
		return
	}

	if strings.HasPrefix(req.Target, "host:") {
		hostID := strings.TrimPrefix(req.Target, "host:")
		if g.forwardToHost(hostID, payload) {
			return
		}
	}

	if g.router.DispatchProtocol(context.Background(), signer, req.Action, req.Content) {
		return
	}

	now := time.Now().Unix()

	switch req.Action {
	case "dbsc_heartbeat_resp":
		g.activeSessions.Store(string(signer), now)

	case "post":
		postID := fmt.Sprintf("post:%d:%x", time.Now().UnixNano(), signer[:4])
		meta := ContentMeta{Signer: signer, Content: req.Content, CreatedAt: now}
		val, _ := json.Marshal(meta)

		txn := g.router.SdfEngine.Store.Begin()
		_ = g.router.SdfEngine.Store.Put(txn, []byte("data:"+postID), val, 0)
		_ = txn.Commit()

		if g.Logger != nil {
			g.Logger.Info(fmt.Sprintf("Mesh dynamic content frame provisioned: %s", postID))
		}

	case "karma":
		if req.Target == "" {
			return
		}
		karmaKey := fmt.Sprintf("karma:%s:%x", req.Target, signer[:8])
		meta := ContentMeta{Signer: signer, Target: req.Target, Value: req.Value, CreatedAt: now}
		val, _ := json.Marshal(meta)

		txn := g.router.SdfEngine.Store.Begin()
		_ = g.router.SdfEngine.Store.Put(txn, []byte("data:"+karmaKey), val, 0)
		_ = txn.Commit()

	case "rpc":
		var rpcPayload map[string]interface{}
		if err := json.Unmarshal([]byte(req.Content), &rpcPayload); err != nil {
			return
		}
		rpcPayload["signer"] = signer
		enrichedPayload, _ := json.Marshal(rpcPayload)

		g.router.LocalBus <- SystemEvent{Topic: "rpc_ingress", Payload: enrichedPayload}
	}
}

func (g *Gateway) forwardToHost(hostID string, payload []byte) bool {
	val, ok := g.hostSessions.Load(hostID)
	if !ok {
		return false
	}
	peer, ok := val.(*hostPeer)
	if !ok || peer.stream == nil || peer.csSend == nil {
		return false
	}
	enc, err := peer.csSend.Encrypt(nil, nil, payload)
	if err != nil {
		return false
	}
	return WriteFrame(peer.stream, enc) == nil
}

func (g *Gateway) clearHostSessions(signer []byte) {
	g.hostSessions.Range(func(key, value any) bool {
		if peer, ok := value.(*hostPeer); ok && string(peer.signer) == string(signer) {
			g.hostSessions.Delete(key)
		}
		return true
	})
}
