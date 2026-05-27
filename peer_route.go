package secure_network

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/logger"
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
	auth           *webauthnext.Provider
	localID        NodeID
	policies       map[NodeID]AccessLevel
	ingressHandler IngressHandler
	Logger         *logger.LogDispatcher // Injected Logger
}

func NewPeerRoute(db *ultimate_db.DB, auth *webauthnext.Provider, hardwareKey []byte, sysLog *logger.LogDispatcher) *PeerRoute {
	localHash := sha256.Sum256(hardwareKey)
	return &PeerRoute{
		db:       db,
		auth:     auth,
		localID:  localHash,
		policies: make(map[NodeID]AccessLevel),
		Logger:   sysLog,
	}
}

func (p *PeerRoute) SetGateway(g *Gateway) {
	p.gateway = g
}

func (p *PeerRoute) SetIngressHandler(handler IngressHandler) {
	p.ingressHandler = handler
}

func (p *PeerRoute) Listen(ctx context.Context) {
	if p.Logger != nil {
		p.Logger.Info("Listening for incoming routing mesh connections...")
	}
}

func (p *PeerRoute) Broadcast(ctx context.Context, payload []byte) {
	if p.Logger != nil {
		p.Logger.Debug(fmt.Sprintf("Broadcasting payload: %d bytes", len(payload)))
	}
}

func (p *PeerRoute) SetAccessPolicy(remoteID NodeID, level AccessLevel) {
	p.policies[remoteID] = level
}

func (p *PeerRoute) EvaluateSwarmHandshake(remoteIdentity []byte, intent string) (bool, error) {
	var remoteID NodeID
	copy(remoteID[:], remoteIdentity)

	level, exists := p.policies[remoteID]
	if !exists {
		if p.Logger != nil {
			p.Logger.Audit(fmt.Sprintf("%x", remoteIdentity[:8]), "HANDSHAKE_REJECTED", "Connection rejected: no cryptographic access policy established")
		}
		return false, errors.New("connection rejected: no cryptographic access policy established")
	}

	switch level {
	case Reject:
		if p.Logger != nil {
			p.Logger.Audit(fmt.Sprintf("%x", remoteIdentity[:8]), "HANDSHAKE_REJECTED", "Connection actively rejected by peer policy")
		}
		return false, errors.New("connection actively rejected by peer")
	case ReadOnly:
		if intent != "S2P_PULL" {
			if p.Logger != nil {
				p.Logger.Audit(fmt.Sprintf("%x", remoteIdentity[:8]), "HANDSHAKE_REJECTED", "Connection rejected: read-only policy strictly enforced against write intent")
			}
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

	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	p.db.Write(CachePageID, txn, objID[:], objBytes, 72*time.Hour)
	
	if p.Logger != nil {
		p.Logger.Info(fmt.Sprintf("Published object %x to swarm cache", objID[:8]))
	}
	
	return objID, nil
}

func (p *PeerRoute) PullFromSwarm(ctx context.Context, objID NodeID) ([]byte, error) {
	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	valBytes, err := p.db.Read(CachePageID, txn, objID[:])
	if err == nil && valBytes != nil {
		var obj SwarmObject
		json.Unmarshal(valBytes, &obj)
		return obj.Payload, nil
	}
	return nil, errors.New("object not found in local cache")
}

func (p *PeerRoute) RevokeObject(ctx context.Context, objID NodeID) error {
	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	err := p.db.Write(CachePageID, txn, objID[:], nil, time.Nanosecond)
	if err == nil && p.Logger != nil {
		p.Logger.Info(fmt.Sprintf("Revoked object %x from swarm cache", objID[:8]))
	}
	return err
}

func (p *PeerRoute) FindClosestNodes(targetID NodeID, count int) ([]RoutingEntry, error) {
	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	prefix := []byte("dht_node:")
	var closest []RoutingEntry

	err := p.db.Scan(SystemPageID, txn, prefix, func(key, value []byte) bool {
		var entry RoutingEntry
		if err := json.Unmarshal(value, &entry); err == nil {
			closest = append(closest, entry)
		}
		return true 
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
		if p.Logger != nil {
			p.Logger.Audit(fmt.Sprintf("%x", remoteID[:8]), "ROUTING_REJECTED", "Hardware verification failed for address claim")
		}
		return errors.New("hardware verification failed")
	}

	entry := RoutingEntry{
		ID:      remoteID,
		Address: address,
	}
	valBytes, _ := json.Marshal(entry)
	key := append([]byte("dht_node:"), remoteID[:]...)

	txn := p.db.BeginTxn()
	defer p.db.CommitTxn(txn)

	err = p.db.Write(SystemPageID, txn, key, valBytes, 2*time.Hour)
	if err == nil && p.Logger != nil {
		p.Logger.Info(fmt.Sprintf("Routing table updated for node %x at %s", remoteID[:8], address))
	}
	return err
}

func xorDistance(a, b NodeID) NodeID {
	var result NodeID
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
