package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/flynn/noise"
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
	
	activeSessions sync.Map 
}

func NewGateway(r *Router, peerMesh *PeerRoute, sPriv, sPub []byte) *Gateway {
	return &Gateway{
		router:   r,
		peerMesh: peerMesh,
		cipher:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		sPriv:    sPriv,
		sPub:     sPub,
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
		Random:        nil,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: g.sPriv, Public: g.sPub},
	})
	if err != nil {
		log.Printf("[GATEWAY] Failed to initialize handshake state: %v", err)
		return
	}

	buf := make([]byte, 4096)
	n, err := stream.Read(buf)
	if err != nil {
		return
	}

	_, _, _, err = hs.ReadMessage(nil, buf[:n])
	if err != nil {
		log.Printf("[GATEWAY] Handshake failed: %v", err)
		return
	}

	remoteKey := hs.PeerStatic()
	
	if !g.isIdentityValid(remoteKey) {
		log.Printf("[GATEWAY] Revoked or unknown key attempted connection. Dropping stream.")
		return
	}

	respMsg, csSend, csRecv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Printf("[GATEWAY] Failed to complete handshake: %v", err)
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

	log.Printf("[GATEWAY] Secure Tunnel established for identity: %x", remoteKey[:8])

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
	txn := g.router.DB.BeginTxn()
	defer g.router.DB.CommitTxn(txn)
	
	_, err := g.router.DB.Read(IdentityPageID, txn, pubKey)
	return err == nil
}

func (g *Gateway) monitorHeartbeat(stream quic.Stream, csSend *noise.CipherState, signer []byte, stop <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			lastSeen, ok := g.activeSessions.Load(string(signer))
			if !ok || time.Now().Unix()-lastSeen.(int64) > 180 {
				log.Printf("[GATEWAY] Tunnel timed out for %x. Closing.", signer[:8])
				stream.Close()
				return
			}

			challenge := make([]byte, 32)
			rand.Read(challenge)

			payload := APIPayload{
				Action:  "dbsc_heartbeat_req",
				Content: string(challenge),
			}
			
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
		log.Println("[CLEANUP] Starting global revocation scrub...")
		if g.router.GUIKit == nil {
			continue
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
				log.Printf("[CLEANUP] Revoked data for identity: %x", meta.Signer[:8])
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

type Event struct {
	Topic   string
	Payload []byte
}

func (g *Gateway) routeToAPI(signer []byte, payload []byte) {
	var req APIPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		log.Printf("[GATEWAY] Invalid API payload from %x: %v", signer[:8], err)
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
		meta := ContentMeta{
			Signer:    signer,
			Content:   req.Content,
			CreatedAt: now,
		}
		val, _ := json.Marshal(meta)
		err := g.router.DB.Write(ContentPageID, txnID, []byte(postID), val, 0)
		if err != nil {
			log.Printf("[GATEWAY] DB Write Failed (Post): %v", err)
			return
		}
		log.Printf("[GATEWAY] Post created by %x: %s", signer[:8], postID)

	case "karma":
		if req.Target == "" {
			return
		}
		karmaKey := fmt.Sprintf("karma:%s:%x", req.Target, signer[:8])
		meta := ContentMeta{
			Signer:    signer,
			Target:    req.Target,
			Value:     req.Value,
			CreatedAt: now,
		}
		val, _ := json.Marshal(meta)
		err := g.router.DB.Write(StatsPageID, txnID, []byte(karmaKey), val, 0)
		if err == nil {
			log.Printf("[GATEWAY] Karma (%d) applied to %s by %x", req.Value, req.Target, signer[:8])
		}

	case "share":
		if req.Target == "" {
			return
		}
		shareKey := fmt.Sprintf("share:%s:%x", req.Target, signer[:8])
		meta := ContentMeta{
			Signer:    signer,
			Target:    req.Target,
			CreatedAt: now,
		}
		val, _ := json.Marshal(meta)
		err := g.router.DB.Write(StatsPageID, txnID, []byte(shareKey), val, 0)
		if err == nil {
			log.Printf("[GATEWAY] Content %s shared by %x", req.Target, signer[:8])
		}

	case "rpc":
		var rpcPayload map[string]interface{}
		if err := json.Unmarshal([]byte(req.Content), &rpcPayload); err != nil {
			log.Printf("[GATEWAY] Invalid RPC content from %x: %v", signer[:8], err)
			return
		}

		rpcPayload["signer"] = signer
		enrichedPayload, _ := json.Marshal(rpcPayload)
		
		g.router.LocalBus <- SystemEvent{
			Topic:   "rpc_ingress",
			Payload: enrichedPayload,
		}

	default:
		log.Printf("[GATEWAY] Unknown action '%s' from %x", req.Action, signer[:8])
	}
}
