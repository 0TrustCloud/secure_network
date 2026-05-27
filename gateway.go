package secure_network

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/logger"
	"github.com/gddisney/ultimate_db"
	"github.com/quic-go/quic-go"
)

const (
	IdentityPageID ultimate_db.PageID = 1
	ContentPageID  ultimate_db.PageID = 2
	StatsPageID    ultimate_db.PageID = 3
)

type Gateway struct {
	router         *Router
	peerMesh       *PeerRoute
	cipher         noise.CipherSuite
	sPriv          []byte
	sPub           []byte
	Logger         *logger.LogDispatcher
	activeSessions sync.Map
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

func (g *Gateway) HandleSecureStream(stream quic.Stream) {
	defer stream.Close()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   g.cipher,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: g.sPriv, Public: g.sPub},
	})
	if err != nil {
		if g.Logger != nil {
			g.Logger.Error(fmt.Sprintf("Gateway handshake init failed: %v", err))
		}
		return
	}

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return
	}

	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		if g.Logger != nil {
			g.Logger.Error(fmt.Sprintf("Gateway handshake failed: %v", err))
		}
		return
	}

	remoteKey := hs.PeerStatic()

	if !g.isIdentityValid(remoteKey) {
		if g.Logger != nil {
			g.Logger.Audit("system_gateway", "TUNNEL_REJECTED", fmt.Sprintf("Revoked or unknown key attempted connection: %x", remoteKey[:8]))
		}
		return
	}

	respMsg, csSend, csRecv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return
	}

	if _, err = stream.Write(respMsg); err != nil {
		return
	}

	sessionID := string(remoteKey)
	g.activeSessions.Store(sessionID, time.Now().Unix())

	stopHeartbeat := make(chan struct{})
	defer close(stopHeartbeat)
	go g.monitorHeartbeat(stream, csSend, remoteKey, stopHeartbeat)

	if g.Logger != nil {
		g.Logger.Audit(fmt.Sprintf("%x", remoteKey[:8]), "TUNNEL_ESTABLISHED", "Secure QUIC tunnel established")
	}

	for {
		n, err := stream.Read(buf)
		if err != nil {
			break
		}
		decrypted, err := csRecv.Decrypt(nil, nil, buf[:n])
		if err != nil {
			continue
		}
		g.routeToAPI(remoteKey, decrypted)
	}

	g.activeSessions.Delete(sessionID)
}

func (g *Gateway) isIdentityValid(pubKey []byte) bool {
	return g.router.PolicyEngine.HasPermission(pubKey, "network:connect")
}

func (g *Gateway) monitorHeartbeat(stream quic.Stream, csSend *noise.CipherState, signer []byte, stop <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lastSeen, ok := g.activeSessions.Load(string(signer))
			if !ok || time.Now().Unix()-lastSeen.(int64) > 180 {
				if g.Logger != nil {
					g.Logger.Info(fmt.Sprintf("Tunnel timed out for %x. Closing.", signer[:8]))
				}
				stream.Close()
				return
			}
			challenge := make([]byte, 32)
			rand.Read(challenge)
			payload := APIPayload{Action: "dbsc_heartbeat_req", Content: string(challenge)}
			data, _ := json.Marshal(payload)
			enc, _ := csSend.Encrypt(nil, nil, data)
			stream.Write(enc)
		case <-stop:
			return
		}
	}
}

func (g *Gateway) ScrubbingCycle() {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		if g.router.GUIKit == nil {
			continue
		}
		if g.Logger != nil {
			g.Logger.Info("Starting global revocation scrub...")
		}

		tree := ultimate_db.NewBTree(g.router.GUIKit.BP, 2)
		cursor, _ := ultimate_db.NewBTreeCursor(tree)

		for {
			key, val, err := cursor.Next()
			if err != nil {
				break
			}
			var meta struct {
				Signer []byte
			}
			json.Unmarshal(val, &meta)

			if len(meta.Signer) > 0 && !g.isIdentityValid(meta.Signer) {
				txn := g.router.DB.BeginTxn()
				g.router.DB.Write(ContentPageID, txn, key, nil, time.Nanosecond)
				g.router.DB.CommitTxn(txn)
				
				if g.Logger != nil {
					g.Logger.Audit("system_scrubber", "REVOKE_DATA", fmt.Sprintf("Revoked data for identity: %x", meta.Signer[:8]))
				}
			}
		}
		cursor.Close()
	}
}

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

func (g *Gateway) routeToAPI(signer []byte, payload []byte) {
	var req APIPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		if g.Logger != nil {
			g.Logger.Error(fmt.Sprintf("Invalid API payload from %x: %v", signer[:8], err))
		}
		return
	}

	contextData := map[string]string{"target": req.Target}
	resource := req.Target
	if resource == "" {
		resource = "*"
	}

	if !g.router.PolicyEngine.Evaluate(signer, req.Action, resource, contextData) {
		if g.Logger != nil {
			g.Logger.Audit(fmt.Sprintf("%x", signer[:8]), "MESH_DENIED", "Gateway blocked unauthorized action: "+req.Action)
		}
		return
	}

	txnID := g.router.DB.BeginTxn()
	defer g.router.DB.CommitTxn(txnID)
	now := time.Now().Unix()

	switch req.Action {
	case "dbsc_heartbeat_resp":
		g.activeSessions.Store(string(signer), now)

	case "post":
		postID := fmt.Sprintf("post:%d:%x", time.Now().UnixNano(), signer[:4])
		meta := ContentMeta{Signer: signer, Content: req.Content, CreatedAt: now}
		val, _ := json.Marshal(meta)
		_ = g.router.DB.Write(ContentPageID, txnID, []byte(postID), val, 0)
		if g.Logger != nil {
			g.Logger.Info(fmt.Sprintf("Mesh Post created by %x: %s", signer[:8], postID))
		}

	case "karma":
		if req.Target == "" {
			return
		}
		karmaKey := fmt.Sprintf("karma:%s:%x", req.Target, signer[:8])
		meta := ContentMeta{Signer: signer, Target: req.Target, Value: req.Value, CreatedAt: now}
		val, _ := json.Marshal(meta)
		_ = g.router.DB.Write(StatsPageID, txnID, []byte(karmaKey), val, 0)
		if g.Logger != nil {
			g.Logger.Info(fmt.Sprintf("Karma (%d) applied to %s by %x", req.Value, req.Target, signer[:8]))
		}

	case "rpc":
		var rpcPayload map[string]interface{}
		json.Unmarshal([]byte(req.Content), &rpcPayload)
		rpcPayload["signer"] = signer
		enrichedPayload, _ := json.Marshal(rpcPayload)
		g.router.LocalBus <- SystemEvent{Topic: "rpc_ingress", Payload: enrichedPayload}
	}
}
