package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"okra/router"
	"github.com/gddisney/ultimate_db"
	
	"github.com/flynn/noise"
	"github.com/quic-go/quic-go"
)

type NoiseGateway struct {
	router *router.Router
	cipher noise.CipherSuite
	sPriv  []byte
	sPub   []byte
}

func NewNoiseGateway(r *router.Router) *NoiseGateway {
	return &NoiseGateway{
		router: r,
		cipher: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
	}
}

func (ng *NoiseGateway) HandleSecureStream(stream quic.Stream) {
	defer stream.Close()

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   ng.cipher,
		Random:        nil,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: ng.sPriv, Public: ng.sPub},
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
		log.Printf("[GATEWAY] Handshake failed (Potential Banned User Noise): %v", err)
		return
	}

	remoteKey := hs.PeerStatic()

	if !ng.isIdentityValid(remoteKey) {
		log.Printf("[GATEWAY] Revoked key attempted connection. Dropping stream.")
		return
	}

	respMsg, _, csRecv, err := hs.WriteMessage(nil, nil)
	if err != nil {
		log.Printf("[GATEWAY] Failed to complete handshake: %v", err)
		return
	}
	
	_, err = stream.Write(respMsg)
	if err != nil {
		return
	}

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

		ng.routeToAPI(remoteKey, decrypted)
	}
}

func (ng *NoiseGateway) isIdentityValid(pubKey []byte) bool {
	_, err := ng.router.DB.Read(1, ng.router.DB.BeginTxn(), pubKey)
	return err == nil
}

func (ng *NoiseGateway) ScrubbingCycle() {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		log.Println("[CLEANUP] Starting global revocation scrub...")
		
		tree := ultimate_db.NewBTree(ng.router.GUIKit.BP, 2)
		cursor, _ := ultimate_db.NewBTreeCursor(tree)
		
		for {
			key, val, err := cursor.Next()
			if err != nil {
				break
			}

			var meta struct { Signer []byte }
			json.Unmarshal(val, &meta)

			if len(meta.Signer) > 0 && !ng.isIdentityValid(meta.Signer) {
				ng.router.DB.Write(2, ng.router.DB.BeginTxn(), key, nil, time.Nanosecond)
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

func (ng *NoiseGateway) routeToAPI(signer []byte, payload []byte) {
	var req APIPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		log.Printf("[GATEWAY] Invalid API payload from %x: %v", signer[:8], err)
		return
	}

	txnID := ng.router.DB.BeginTxn()
	now := time.Now().Unix()

	switch req.Action {
	case "post":
		postID := fmt.Sprintf("post:%d:%x", time.Now().UnixNano(), signer[:4])
		
		meta := ContentMeta{
			Signer:    signer,
			Content:   req.Content,
			CreatedAt: now,
		}
		
		val, _ := json.Marshal(meta)
		
		err := ng.router.DB.Write(2, txnID, []byte(postID), val, 0)
		if err != nil {
			log.Printf("[GATEWAY] DB Write Failed (Post): %v", err)
			return
		}

		log.Printf("[GATEWAY] Post created by %x: %s", signer[:8], postID)
		if ng.router.GUIKit != nil {
			ng.router.GUIKit.Broadcast("new_post", meta)
		}

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
		
		err := ng.router.DB.Write(3, txnID, []byte(karmaKey), val, 0)
		if err == nil {
			log.Printf("[GATEWAY] Karma (%d) applied to %s by %x", req.Value, req.Target, signer[:8])
			if ng.router.GUIKit != nil {
				ng.router.GUIKit.Broadcast("karma_update", meta)
			}
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
		
		err := ng.router.DB.Write(3, txnID, []byte(shareKey), val, 0)
		if err == nil {
			log.Printf("[GATEWAY] Content %s shared by %x", req.Target, signer[:8])
		}

	default:
		log.Printf("[GATEWAY] Unknown action '%s' from %x", req.Action, signer[:8])
	}
}
