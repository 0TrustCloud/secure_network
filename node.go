package secure_network

import (
	"context"
	"fmt"
	"time"

	"github.com/0TrustCloud/auth_provider"
	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/secure_policy"
)

// SecureNode acts as the main microkernel engine orchestrating the network plane.
type SecureNode struct {
	SdfEngine      *secure_data_format.SecureDataEngine
	PolicyEngine   *secure_policy.PolicyEngine
	SessionManager *secure_policy.SessionManager
	AuthProvider   *auth_provider.Provider
	Logger         *logger.LogDispatcher
	Mesh           *MeshNode
	PeerRoute      *PeerRoute
	Gossip         *GossipManager
	RPC            *RPCManager
	HostID         string
	Realm          string
}

func NewSecureNode(
	sdf *secure_data_format.SecureDataEngine,
	sm *secure_policy.SessionManager,
	gk *guikit.GUIKit, // Injected dependency to prevent nil dereference
	realm string,
	hostID string,
	issuerURL string,
	gatewayPub []byte,
) (*SecureNode, error) {
	if sdf == nil {
		return nil, fmt.Errorf("secure dataframe architecture context cannot be nil")
	}

	logDispatcher, err := logger.NewLogDispatcher(hostID, 1000, sdf)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize node logger matrix: %w", err)
	}

	// Corrected: Passed the full engine instance, not just the store
	policyEngine := secure_policy.NewPolicyEngine(sdf)

	// Corrected: Passed the actual GUIKit instance instead of nil
	authProvider, err := auth_provider.New(
		gk,
		sm,
		sdf,
		realm,
		hostID,
		issuerURL,
		"0trust.services",
	)
	if err != nil {
		return nil, fmt.Errorf("failed creating auth provider domain map: %w", err)
	}

	meshNode, err := NewMeshNode(sdf, gatewayPub, logDispatcher)
	if err != nil {
		return nil, fmt.Errorf("failed creating core mesh node context: %w", err)
	}

	peerRoute := NewPeerRoute(meshNode, logDispatcher)
	gossipManager := NewGossipManager(peerRoute, logDispatcher)
	rpcManager := NewRPCManager(peerRoute, logDispatcher)

	meshNode.SetRPCManager(rpcManager)

	node := &SecureNode{
		SdfEngine:      sdf,
		PolicyEngine:   policyEngine,
		SessionManager: sm,
		AuthProvider:   authProvider,
		Logger:         logDispatcher,
		Mesh:           meshNode,
		PeerRoute:      peerRoute,
		Gossip:         gossipManager,
		RPC:            rpcManager,
		HostID:         hostID,
		Realm:          realm,
	}

	gossipManager.StartJanitor()

	if node.Logger != nil {
		node.Logger.Info("Secure node initialized successfully via SDF data frame structures")
	}

	return node, nil
}

func (n *SecureNode) ConnectMesh(ctx context.Context, gatewayAddr string) error {
	if n.Mesh == nil {
		return fmt.Errorf("mesh transport layer unavailable")
	}
	return n.Mesh.Connect(ctx, gatewayAddr)
}

func (n *SecureNode) Shutdown() error {
	if n.Mesh != nil {
		return n.Mesh.Close()
	}
	return nil
}

func (n *SecureNode) RegisterRPC(method string, handler RPCHandler) {
	if n.RPC != nil {
		n.RPC.Register(method, handler)
	}
}

func (n *SecureNode) RegisterGossip(serviceID string, handler GossipHandler) {
	if n.Gossip != nil {
		n.Gossip.RegisterHandler(serviceID, handler)
	}
}

func (n *SecureNode) BroadcastRPC(ctx context.Context, method string, payload []byte) error {
	if n.RPC == nil {
		return fmt.Errorf("rpc subsystem offline")
	}
	return n.RPC.Broadcast(ctx, method, payload)
}

func (n *SecureNode) NotifyRPC(ctx context.Context, method string, payload []byte) error {
	if n.RPC == nil {
		return fmt.Errorf("rpc subsystem offline")
	}
	return n.RPC.Notify(ctx, method, payload)
}

func (n *SecureNode) CallPeer(ctx context.Context, target []byte, method string, payload []byte) ([]byte, error) {
	if n.RPC == nil {
		return nil, fmt.Errorf("rpc subsystem offline")
	}
	return n.RPC.Call(ctx, target, method, payload, DefaultRPCTimeout)
}

func (n *SecureNode) PublishGossip(ctx context.Context, serviceID string, payload []byte, signature []byte) error {
	if n.Gossip == nil {
		return fmt.Errorf("gossip service offline")
	}
	return n.Gossip.Publish(ctx, serviceID, payload, signature)
}

func (n *SecureNode) PeerCount() int {
	if n.PeerRoute == nil {
		return 0
	}
	return n.PeerRoute.PeerCount()
}

func (n *SecureNode) IsMeshConnected() bool {
	return n.Mesh != nil && n.Mesh.conn != nil
}

const DefaultRPCTimeout = 15 * time.Second
