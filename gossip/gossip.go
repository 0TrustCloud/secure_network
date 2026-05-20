package secure_network

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"
	"sync/atomic"
    "github.com/gddisney/secure_network/route"
	"github.com/gddisney/ultimate_db"
	"github.com/flynn/noise"
)

// AuthPageID is strictly mapped to Page 1 for security and session state isolation.
const AuthPageID = 1

// GossipFrame represents the serialized state transition sent across the mesh.
type GossipFrame struct {
	Key         string `json:"k"`
	Value       []byte `json:"v"`
	LamportTime uint64 `json:"lt"`
	SignerKey   []byte `json:"sk"` 
}

// GossipManager handles the decentralized state sync over Noise IK.
type GossipManager struct {
	db        *ultimate_db.Database
	router    *PeerRoute
	clock     uint64
	framePool *sync.Pool
}

// NewGossipManager initializes the gossip protocol with zero-allocation buffers.
func NewGossipManager(db *ultimate_db.Database, router *PeerRoute) *GossipManager {
	return &GossipManager{
		db:     db,
		router: router,
		clock:  0,
		framePool: &sync.Pool{
			New: func() interface{} {
				return &GossipFrame{}
			},
		},
	}
}

// Tick increments and returns the local Lamport timestamp.
func (gm *GossipManager) Tick() uint64 {
	return atomic.AddUint64(&gm.clock, 1)
}

// updateClock synchronizes the local clock against an incoming frame's time.
func (gm *GossipManager) updateClock(incomingTime uint64) {
	for {
		current := atomic.LoadUint64(&gm.clock)
		if current >= incomingTime {
			break
		}
		if atomic.CompareAndSwapUint64(&gm.clock, current, incomingTime) {
			break
		}
	}
	atomic.AddUint64(&gm.clock, 1)
}

// BroadcastStateChange is triggered when ultimate_db commits a change to AuthPageID.
// For example, when an admin bans a user, it emits `banned:{username}`.
func (gm *GossipManager) BroadcastStateChange(ctx context.Context, key string, value []byte, signerPublicKey []byte) error {
	// 1. Pack the Wire Frame
	frame := gm.framePool.Get().(*GossipFrame)
	defer gm.framePool.Put(frame)

	frame.Key = key
	frame.Value = value
	frame.LamportTime = gm.Tick()
	frame.SignerKey = signerPublicKey

	payload, err := json.Marshal(frame)
	if err != nil {
		return err
	}

	// 2. Asynchronous Mesh Routing
	// The router pushes the frame out to all active QUIC streams wrapped in noise.HandshakeIK.
	go gm.router.Broadcast(ctx, payload)

	return nil
}

// HandleIngress is called by Peer_Route when a new Noise frame arrives over QUIC.
func (gm *GossipManager) HandleIngress(ctx context.Context, encryptedPayload []byte, peerNoiseState *noise.CipherState) error {
	// 1. Cryptographic Transport Decryption
	payload, err := peerNoiseState.Decrypt(nil, nil, encryptedPayload)
	if err != nil {
		return errors.New("gossip: noise payload decryption failed")
	}

	// Unpack the JSON wire frame
	frame := gm.framePool.Get().(*GossipFrame)
	defer gm.framePool.Put(frame)

	if err := json.Unmarshal(payload, frame); err != nil {
		return err
	}

	// 2. Zero-Trust Ingestion
	// Authenticate against authorized public keys stored in local PageID = 1.
	authKey := "user:" + string(frame.SignerKey)
	_, err = gm.db.Read(AuthPageID, []byte(authKey))
	if err != nil {
		// Key not found in local Page 1 map; discard untrusted frame.
		log.Printf("gossip: rejected untrusted frame from unverified key")
		return errors.New("unauthorized gossip origin")
	}

	// 3. Vector Clock Sync
	gm.updateClock(frame.LamportTime)

	// 4. Memory Integration
	// Write the gossiped state (e.g., banned:{username}) directly into ultimate_db.PageID = 1
	err = gm.db.Write(AuthPageID, []byte(frame.Key), frame.Value)
	if err != nil {
		return err
	}

	log.Printf("gossip: synchronized state %s at LamportTime %d", frame.Key, frame.LamportTime)
	return nil
}
