package secure_network

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
)

type AccessPolicy int

const (
	Deny AccessPolicy = iota
	ReadOnly
	See
	Write
	Admin
)

type NodeID [32]byte

type PeerIdentity struct {
	NodeID    NodeID
	PublicKey []byte
	Address   string
	LastSeen  time.Time
}

type PeerMessage struct {
	ID        string    `json:"id"`
	Route     string    `json:"route"`
	Payload   []byte    `json:"payload"`
	Origin    []byte    `json:"origin"`
	Timestamp time.Time `json:"timestamp"`
}

type PeerHandler func(ctx context.Context, msg *PeerMessage) error

type PeerRoute struct {
	meshNode       *MeshNode
	Logger         *logger.LogDispatcher
	mu             sync.RWMutex
	handlers       map[string]PeerHandler
	accessPolicies map[NodeID]AccessPolicy
	peers          map[string]*PeerIdentity
}

func NewPeerRoute(node *MeshNode, sysLog *logger.LogDispatcher) *PeerRoute {
	return &PeerRoute{
		meshNode:       node,
		Logger:         sysLog,
		handlers:       make(map[string]PeerHandler),
		accessPolicies: make(map[NodeID]AccessPolicy),
		peers:          make(map[string]*PeerIdentity),
	}
}

func (pr *PeerRoute) RegisterHandler(route string, handler PeerHandler) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.handlers[route] = handler
}

func (pr *PeerRoute) Dispatch(ctx context.Context, msg *PeerMessage) error {
	pr.mu.RLock()
	handler, ok := pr.handlers[msg.Route]
	pr.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no handler registered for route: %s", msg.Route)
	}
	return handler(ctx, msg)
}

func (pr *PeerRoute) MeshConnected() bool {
	return pr.meshNode != nil && pr.meshNode.Connected()
}

func (pr *PeerRoute) Broadcast(ctx context.Context, route string, payload []byte) error {
	if pr.meshNode == nil {
		return fmt.Errorf("mesh node context unavailable")
	}
	if !pr.meshNode.Connected() {
		return fmt.Errorf("mesh tunnel context unavailable")
	}

	hash := sha256.Sum256(append([]byte(route), payload...))
	msg := PeerMessage{
		ID:        hex.EncodeToString(hash[:]),
		Route:     route,
		Payload:   payload,
		Origin:    pr.meshNode.noisePub,
		Timestamp: time.Now(),
	}

	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return pr.meshNode.SendAction(APIPayload{Action: "rpc", Content: string(raw)})
}

func (pr *PeerRoute) SendToPeer(ctx context.Context, peerID []byte, route string, payload []byte) error {
	if pr.meshNode == nil {
		return fmt.Errorf("mesh node context unavailable")
	}

	hash := sha256.Sum256(append(peerID, payload...))
	msg := PeerMessage{
		ID:        hex.EncodeToString(hash[:]),
		Route:     route,
		Payload:   payload,
		Origin:    pr.meshNode.noisePub,
		Timestamp: time.Now(),
	}

	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return pr.meshNode.SendAction(APIPayload{Action: "rpc", Content: string(raw)})
}

func (pr *PeerRoute) HandleIngress(ctx context.Context, payload []byte) error {
	var msg PeerMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		return err
	}
	return pr.Dispatch(ctx, &msg)
}

func (pr *PeerRoute) AddPeer(peer *PeerIdentity) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.peers[hex.EncodeToString(peer.NodeID[:])] = peer
}

func (pr *PeerRoute) RemovePeer(nodeID NodeID) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	key := hex.EncodeToString(nodeID[:])
	delete(pr.peers, key)
	delete(pr.accessPolicies, nodeID)
}

// GetAccessPolicy returns the mesh ACL for a node (Deny if unset).
func (pr *PeerRoute) GetAccessPolicy(nodeID NodeID) AccessPolicy {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if p, ok := pr.accessPolicies[nodeID]; ok {
		return p
	}
	return Deny
}

// AccessPolicyName is a stable string for APIs and UIs.
func AccessPolicyName(p AccessPolicy) string {
	switch p {
	case ReadOnly:
		return "readonly"
	case See:
		return "see"
	case Write:
		return "write"
	case Admin:
		return "admin"
	case Deny:
		return "deny"
	default:
		return "deny"
	}
}

// ParseAccessPolicy maps API strings to AccessPolicy.
func ParseAccessPolicy(s string) (AccessPolicy, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "deny", "none", "block":
		return Deny, true
	case "readonly", "read", "ro":
		return ReadOnly, true
	case "see", "view":
		return See, true
	case "write", "rw":
		return Write, true
	case "admin", "owner":
		return Admin, true
	default:
		return Deny, false
	}
}

func (pr *PeerRoute) ListPeers() []*PeerIdentity {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	out := make([]*PeerIdentity, 0, len(pr.peers))
	for _, peer := range pr.peers {
		out = append(out, peer)
	}
	return out
}

func (pr *PeerRoute) SetAccessPolicy(nodeID NodeID, policy AccessPolicy) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.accessPolicies[nodeID] = policy
}

func (pr *PeerRoute) EvaluateSwarmHandshake(remotePub []byte, intent string) (bool, error) {
	if len(remotePub) < 32 {
		return false, fmt.Errorf("invalid identity attributes length")
	}

	var nodeID NodeID
	copy(nodeID[:], remotePub[:32])

	// Assert access policy checks using transient dataframe evaluations
	script := fmt.Sprintf(`network:swarm_ingress(intent("%s") node("%x"))`, intent, remotePub[:4])
	tx := secure_data_format.DataInvocation{
		TargetAddress: "swarm:ingress:policy",
		Caller:        hex.EncodeToString(remotePub),
		Nonce:         0,
		Method:        "EVALUATE_SWARM",
		Profile:       secure_data_format.ProfileGrant,
	}
	if _, err := pr.meshNode.SdfEngine.CompileSecureData(script, tx); err != nil {
		return false, fmt.Errorf("sdf dataframe policy blocked entry authorization parameters: %w", err)
	}

	pr.mu.RLock()
	policy, ok := pr.accessPolicies[nodeID]
	pr.mu.RUnlock()

	if !ok {
		return false, fmt.Errorf("no capability mapping defined for target context node")
	}

	switch policy {
	case Admin, See:
		return true, nil
	case Write:
		if intent == "WRITE_INTENT" || intent == "READ_INTENT" || intent == "S2P_PULL" {
			return true, nil
		}
	case ReadOnly:
		if intent == "READ_INTENT" || intent == "S2P_PULL" {
			return true, nil
		}
	case Deny:
		return false, fmt.Errorf("policy explicitly denied")
	}

	return false, fmt.Errorf("intent signature validation rejected")
}

func (pr *PeerRoute) HasPeer(nodeID NodeID) bool {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	_, ok := pr.peers[hex.EncodeToString(nodeID[:])]
	return ok
}

func (pr *PeerRoute) GetPeer(nodeID NodeID) (*PeerIdentity, bool) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	peer, ok := pr.peers[hex.EncodeToString(nodeID[:])]
	return peer, ok
}

func (pr *PeerRoute) TouchPeer(nodeID NodeID) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if peer, ok := pr.peers[hex.EncodeToString(nodeID[:])]; ok {
		peer.LastSeen = time.Now()
	}
}

func (pr *PeerRoute) PeerCount() int {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	return len(pr.peers)
}

func (pr *PeerRoute) SignMessage(serviceID string, payload []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) == 0 {
		return nil, fmt.Errorf("missing private signing key matrix")
	}
	hash := sha256.Sum256(append([]byte(serviceID), payload...))
	return ed25519.Sign(priv, hash[:]), nil
}
