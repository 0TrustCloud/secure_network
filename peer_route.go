package peerroute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

const (
	SystemPageID ultimate_db.PageID = 1
	CachePageID  ultimate_db.PageID = 2 // Dedicated ultimate_db page for the Master Cache
)

// Access Control States
type AccessLevel int

const (
	Reject AccessLevel = iota
	ReadOnly
	See
)

// NodeID represents a 256-bit cryptographic identifier
type NodeID [32]byte

// SwarmObject represents a payload stored in the Master Cache
type SwarmObject struct {
	ObjectID  NodeID    `json:"object_id"`
	OwnerID   NodeID    `json:"owner_id"`
	Payload   []byte    `json:"payload"`
	Signature []byte    `json:"signature"` // DBSC Hardware proof of ownership
	CreatedAt time.Time `json:"created_at"`
}

// Node represents the PeerRoute orchestrator
type Node struct {
	db       *ultimate_db.Engine
	netGate  *secure_network.NoiseQUIC
	auth     *webauthnext.Manager
	localID  NodeID
	policies map[NodeID]AccessLevel // Local mapping of who is allowed to See/Read/Reject
}

// NewNode initializes the PeerRoute overlay orchestrator
func NewNode(db *ultimate_db.Engine, netGate *secure_network.NoiseQUIC, auth *webauthnext.Manager, hardwareKey []byte) *Node {
	localHash := sha256.Sum256(hardwareKey)

	node := &Node{
		db:       db,
		netGate:  netGate,
		auth:     auth,
		localID:  localHash,
		policies: make(map[NodeID]AccessLevel),
	}

	// Register the node's local identity and register the handshake interceptor
	node.netGate.SetHandshakeInterceptor(node.EvaluateSwarmHandshake)
	return node
}

// --- AIRGAPPED ACCESS CONTROL ---

// SetAccessPolicy allows the user to define their Swarm boundary rules for specific identities
func (n *Node) SetAccessPolicy(remoteID NodeID, level AccessLevel) {
	n.policies[remoteID] = level
}

// EvaluateSwarmHandshake intercepts the underlying Noise protocol connection before a socket is formed
func (n *Node) EvaluateSwarmHandshake(remoteIdentity []byte, intent string) (bool, error) {
	var remoteID NodeID
	copy(remoteID[:], remoteIdentity)

	level, exists := n.policies[remoteID]
	if !exists {
		// Default to Reject for unknown connections to prevent scraping/DDoS
		return false, errors.New("connection rejected: no cryptographic access policy established")
	}

	switch level {
	case Reject:
		// Kills the Noise handshake instantly at the UDP layer. No data transferred.
		return false, errors.New("connection actively rejected by peer")
	case ReadOnly:
		// Allows the handshake to complete strictly for S2P Master Cache requests
		if intent != "S2P_PULL" {
			return false, errors.New("connection rejected: read-only policy strictly enforced")
		}
		return true, nil
	case See:
		// Full mutual authentication for real-time bidirectional routing
		return true, nil
	default:
		return false, errors.New("unknown access level")
	}
}

// --- MASTER CACHE: P2S AND S2P ---

// PublishToSwarm (P2S) pushes an object to the k-closest nodes for offline persistence
func (n *Node) PublishToSwarm(ctx context.Context, payload []byte) (NodeID, error) {
	// 1. Hash the payload to create the ObjectID
	hash := sha256.Sum256(payload)
	var objID NodeID
	copy(objID[:], hash[:])

	// 2. Hardware sign the payload to prove ownership (Tombstone prep)
	signature := n.auth.SignPayload(payload)

	obj := SwarmObject{
		ObjectID:  objID,
		OwnerID:   n.localID,
		Payload:   payload,
		Signature: signature,
		CreatedAt: time.Now(),
	}

	objBytes, err := json.Marshal(obj)
	if err != nil {
		return objID, err
	}

	// 3. Find the k-closest nodes to the ObjectID to serve as the Master Cache
	closestPeers, err := n.FindClosestNodes(objID, 5)
	if err != nil {
		return objID, fmt.Errorf("failed to locate swarm cache peers: %v", err)
	}

	// 4. Push the object to the Swarm
	for _, peer := range closestPeers {
		go n.netGate.SendEncrypted(ctx, peer.Address, append([]byte("P2S_PUSH:"), objBytes...))
	}

	// 5. Write to local Master Cache block
	n.db.Write(CachePageID, n.db.BeginTxn(), objID[:], objBytes, 72*time.Hour)

	return objID, nil
}

// PullFromSwarm (S2P) requests a cached object from the network
func (n *Node) PullFromSwarm(ctx context.Context, objID NodeID) ([]byte, error) {
	// 1. Check local ultimate_db cache first
	valBytes, err := n.db.Read(CachePageID, n.db.BeginTxn(), objID[:])
	if err == nil && valBytes != nil {
		var obj SwarmObject
		json.Unmarshal(valBytes, &obj)
		return obj.Payload, nil
	}

	// 2. If not local, find closest caching peers
	closestPeers, err := n.FindClosestNodes(objID, 3)
	if err != nil || len(closestPeers) == 0 {
		return nil, errors.New("object not found in local or swarm routing table")
	}

	// 3. Execute S2P Pull with Intent flag to bypass 'See' requirement if 'Read-Only' is allowed
	for _, peer := range closestPeers {
		response, err := n.netGate.RequestEncrypted(ctx, peer.Address, append([]byte("S2P_PULL:"), objID[:]...), "S2P_PULL")
		if err == nil && response != nil {
			var obj SwarmObject
			json.Unmarshal(response, &obj)

			// Verify hardware signature of the object owner before accepting the data
			valid, _ := n.auth.VerifyPayloadSignature(obj.OwnerID[:], obj.Payload, obj.Signature)
			if valid {
				// Cache locally for future requests
				n.db.Write(CachePageID, n.db.BeginTxn(), objID[:], response, 72*time.Hour)
				return obj.Payload, nil
			}
		}
	}

	return nil, errors.New("swarm could not fulfill S2P request")
}

// RevokeObject (Tombstone) allows the hardware owner to cryptographically delete their data globally
func (n *Node) RevokeObject(ctx context.Context, objID NodeID) error {
	tombstone := append([]byte("TOMBSTONE:"), objID[:]...)
	signature := n.auth.SignPayload(tombstone)

	payload := append(tombstone, signature...)

	closestPeers, _ := n.FindClosestNodes(objID, 5)
	for _, peer := range closestPeers {
		go n.netGate.SendEncrypted(ctx, peer.Address, payload)
	}

	// Scrub from local DB using a null-write
	return n.db.Delete(CachePageID, n.db.BeginTxn(), objID[:])
}

// --- BOOTSTRAP AND ROUTING ---

// Bootstrap connects to a seed node and populates the local routing table
func (n *Node) Bootstrap(ctx context.Context, seedAddress string) error {
	// Request k-closest nodes to our own ID from the seed
	req := append([]byte("FIND_NODE:"), n.localID[:]...)
	resp, err := n.netGate.RequestEncrypted(ctx, seedAddress, req, "BOOTSTRAP")
	if err != nil {
		return fmt.Errorf("bootstrap failed: %v", err)
	}

	var peers []struct {
		ID        NodeID
		Address   string
		DBSCProof []byte
	}
	json.Unmarshal(resp, &peers)

	// Register discovered peers into our local ultimate_db system index
	for _, peer := range peers {
		n.UpdateRoutingTable(peer.ID, peer.Address, peer.DBSCProof)
	}

	return nil
}

// FindClosestNodes leverages ultimate_db's native indexing to calculate XOR distance
func (n *Node) FindClosestNodes(targetID NodeID, count int) ([]struct {
	ID      NodeID
	Address string
}, error) {
	txn := n.db.BeginTxn()
	prefix := []byte("dht_node:")
	records, err := n.db.PrefixScan(SystemPageID, txn, prefix)
	if err != nil {
		return nil, err
	}

	type routingEntry struct {
		ID      NodeID `json:"id"`
		Address string `json:"address"`
	}

	var closest []routingEntry
	for _, rec := range records {
		var entry routingEntry
		if err := json.Unmarshal(rec.Value, &entry); err == nil {
			closest = append(closest, entry)
		}
	}

	// XOR Sort Logic
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

func (n *Node) UpdateRoutingTable(remoteID NodeID, address string, dbscProof []byte) error {
	isValid, err := n.auth.VerifyAddressClaim(remoteID[:], address, dbscProof)
	if err != nil || !isValid {
		return errors.New("hardware verification failed")
	}

	entry := struct {
		ID        NodeID `json:"id"`
		Address   string `json:"address"`
		DBSCProof []byte `json:"dbsc_proof"`
	}{
		ID:        remoteID,
		Address:   address,
		DBSCProof: dbscProof,
	}

	valBytes, _ := json.Marshal(entry)
	key := append([]byte("dht_node:"), remoteID[:]...)
	return n.db.Write(SystemPageID, n.db.BeginTxn(), key, valBytes, 2*time.Hour)
}

func xorDistance(a, b NodeID) NodeID {
	var result NodeID
	for i := 0; i < len(a); i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}
