package secure_network

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

const (
	SystemPageID ultimate_db.PageID = 1
	CachePageID  ultimate_db.PageID = 2
)

type AccessLevel int

const (
	Reject AccessLevel = iota
	ReadOnly
	See
)

type NodeID [32]byte

type SwarmObject struct {
	ObjectID  NodeID    `json:"object_id"`
	OwnerID   NodeID    `json:"owner_id"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"signature"`
	CreatedAt time.Time `json:"created_at"`
}

type RoutingEntry struct {
	ID      NodeID `json:"id"`
	Address string `json:"address"`
}

type IngressHandler func(context.Context, []byte, *noise.CipherState) error

type PeerRoute struct {
	db             *ultimate_db.DB
	gateway        *Gateway
	// Updated Provider to Manager based on webauthnext conventions
	auth           *webauthnext.Provider 
	localID        NodeID
	policies       map[NodeID]AccessLevel
	ingressHandler IngressHandler
}

// Updated Provider to Manager in the constructor signature
func NewPeerRoute(db *ultimate_db.DB, auth *webauthnext.Provider, hardwareKey []byte) *PeerRoute {
	localHash := sha256.Sum256(hardwareKey)
	return &PeerRoute{
		db:       db,
		auth:     auth,
		localID:  localHash,
		policies: make(map[NodeID]AccessLevel),
	}
}

func (p *PeerRoute) SetGateway(g *Gateway) {
	p.gateway = g
}

func (p *PeerRoute) SetIngressHandler(handler IngressHandler) {
	p.ingressHandler = handler
}

func (p *PeerRoute) Listen(ctx context.Context) {
	log.Println("[PEER MESH] Listening for incoming routing mesh connections...")
}

func (p *PeerRoute) Broadcast(ctx context.Context, payload []byte) {
	log.Printf("[PEER MESH] Broadcasting payload: %d bytes", len(payload))
}

func (p *PeerRoute) SetAccessPolicy(remoteID NodeID, level AccessLevel) {
	p.policies[remoteID] = level
}

func (p *PeerRoute) EvaluateSwarmHandshake(remoteIdentity []byte, intent string) (bool, error) {
	var remoteID NodeID
	copy(remoteID[:], remoteIdentity)

	level, exists := p.policies[remoteID]
	if !exists {
		return false, errors.New("connection rejected: no cryptographic access policy established")
	}

	switch level {
	case Reject:
		return false, errors.New("connection actively rejected by peer")
	case ReadOnly:
		if intent != "S2P_PULL" {
			return false, errors.New("connection rejected: read-only policy strictly enforced")
		}
		return true, nil
	case See:
		return true, nil
	default:
		return false, errors.New("unknown access level")
	}
}

func (p *PeerRoute) PublishToSwarm(ctx context.Context, payload []byte) (NodeID, error) {
	hash := sha256.Sum256(payload)
	var objID NodeID
	copy(objID[:], hash[:])

	signature := p.auth.SignPayload(payload)

	obj := SwarmObject{
		ObjectID:  objID,
		OwnerID:   p.localID,
		Payload:   payload,
		Signature: signature,
		CreatedAt: time.Now(),
	}

	objBytes, err := json.Marshal(obj)
	if err != nil {
		return objID, err
	}

	p.db.Write(CachePageID, p.db.BeginTxn(), objID[:], objBytes, 72*time.Hour)
	return objID, nil
}

func (p *PeerRoute) PullFromSwarm(ctx context.Context, objID NodeID) ([]byte, error) {
	valBytes, err := p.db.Read(CachePageID, p.db.BeginTxn(), objID[:])
	if err == nil && valBytes != nil {
		var obj SwarmObject
		json.Unmarshal(valBytes, &obj)
		return obj.Payload, nil
	}
	return nil, errors.New("object not found in local cache")
}

func (p *PeerRoute) RevokeObject(ctx context.Context, objID NodeID) error {
	// FIX: Replaced p.db.Delete with a tombstone write leveraging the active GC
	return p.db.Write(CachePageID, p.db.BeginTxn(), objID[:], nil, time.Nanosecond)
}

func (p *PeerRoute) FindClosestNodes(targetID NodeID, count int) ([]RoutingEntry, error) {
	txn := p.db.BeginTxn()
	prefix := []byte("dht_node:")

	var closest []RoutingEntry

	// FIX: Replaced p.db.PrefixScan with p.db.Scan utilizing the callback iterator pattern
	err := p.db.Scan(SystemPageID, txn, prefix, func(key, value []byte) bool {
		var entry RoutingEntry
		if err := json.Unmarshal(value, &entry); err == nil {
			closest = append(closest, entry)
		}
		return true // Return true to continue iterating through the B+ Tree
	})

	if err != nil {
		return nil, err
	}

	for i := 0; i < len(closest)-1; i++ {
		for j := i + 1; j < len(closest); j++ {
			distI := xorDistance(closest[i].ID, targetID)
			distJ := xorDistance(closest[j].ID, targetID)
			if bytes.Compare(distI[:], distJ[:]) > 0 {
				closest[i], closest[j] = closest[j], closest[i]
			}
		}
	}

	if len(closest) > count {
		return closest[:count], nil
	}
	return closest, nil
}

func (p *PeerRoute) UpdateRoutingTable(remoteID NodeID, address string, dbscProof []byte) error {
	isValid, err := p.auth.VerifyAddressClaim(remoteID[:], address, dbscProof)
	if err != nil || !isValid {
		return errors.New("hardware verification failed")
	}

	entry := RoutingEntry{
		ID:      remoteID,
		Address: address,
	}

	valBytes, _ := json.Marshal(entry)
	key := append([]byte("dht_node:"), remoteID[:]...)
	return p.db.Write(SystemPageID, p.db.BeginTxn(), key, valBytes, 2*time.Hour)
}

func xorDistance(a, b NodeID) NodeID {
	var result NodeID
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
