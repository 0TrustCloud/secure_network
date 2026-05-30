package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/service_keys"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/0TrustCloud/webauthnext"
)

type SecureNode struct {
	DB *ultimate_db.DB

	Logger *logger.LogDispatcher

	PolicyEngine *secure_policy.PolicyEngine

	SessionManager *secure_policy.SessionManager

	ServiceKeys *service_keys.ServiceKeyManager

	WebAuthn *webauthnext.Provider

	Mesh *MeshNode

	PeerRoute *PeerRoute

	Gossip *GossipManager

	RPC *RPCManager
}

func NewSecureNode(
	db *ultimate_db.DB,
	sysLog *logger.LogDispatcher,
	rpID string,
	rpOrigin string,
	rpName string,
	gatewayPub []byte,
) (*SecureNode, error) {

	if db == nil {

		return nil,
			fmt.Errorf(
				"database is nil",
			)
	}

	var err error

	if sysLog == nil {

		sysLog, err = logger.NewLogDispatcher(
			"secure_node",
			db,
			ConfigPageID,
			1000,
		)

		if err != nil {

			return nil,
				fmt.Errorf(
					"failed to initialize logger: %w",
					err,
				)
		}
	}

	rsaPrivKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)

	if err != nil {

		return nil,
			fmt.Errorf(
				"failed generating RSA key: %w",
				err,
			)
	}

	policyEngine := secure_policy.NewPolicyEngine(
		db,
	)

	sessionManager := secure_policy.NewSessionManager(
		db,
		rsaPrivKey,
	)

	webAuthnProvider, err := webauthnext.New(
		nil,
		sessionManager,
		rpID,
		rpOrigin,
		rpName,
	)

	if err != nil {

		return nil,
			fmt.Errorf(
				"failed creating webauthn provider: %w",
				err,
			)
	}

	skm, err := service_keys.LoadOrCreateManager(
		db,
		sysLog,
	)

	if err != nil {

		return nil,
			fmt.Errorf(
				"failed loading service key manager: %w",
				err,
			)
	}

	skm.Provider = webAuthnProvider

	meshNode, err := NewMeshNode(
		db,
		gatewayPub,
		skm,
		sysLog,
	)

	if err != nil {

		return nil,
			fmt.Errorf(
				"failed creating mesh node: %w",
				err,
			)
	}

	peerRoute := NewPeerRoute(
		meshNode,
		skm,
		sysLog,
	)

	gossipManager := NewGossipManager(
		db,
		peerRoute,
		skm,
		sysLog,
	)

	rpcManager := NewRPCManager(
		peerRoute,
		sysLog,
	)

	meshNode.SetRPCManager(
		rpcManager,
	)

	node := &SecureNode{
		DB:             db,
		Logger:         sysLog,
		PolicyEngine:   policyEngine,
		SessionManager: sessionManager,
		ServiceKeys:    skm,
		WebAuthn:       webAuthnProvider,
		Mesh:           meshNode,
		PeerRoute:      peerRoute,
		Gossip:         gossipManager,
		RPC:            rpcManager,
	}

	gossipManager.StartJanitor()

	if node.Logger != nil {

		node.Logger.Info(
			"Secure node initialized",
		)
	}

	return node, nil
}

func (n *SecureNode) ConnectMesh(
	ctx context.Context,
	gatewayAddr string,
) error {

	if n.Mesh == nil {

		return fmt.Errorf(
			"mesh subsystem unavailable",
		)
	}

	return n.Mesh.Connect(
		ctx,
		gatewayAddr,
	)
}

func (n *SecureNode) Shutdown() error {

	if n.Mesh != nil {

		return n.Mesh.Close()
	}

	return nil
}

func (n *SecureNode) RegisterRPC(
	method string,
	handler RPCHandler,
) {

	if n.RPC == nil {
		return
	}

	n.RPC.Register(
		method,
		handler,
	)
}

func (n *SecureNode) RegisterGossip(
	serviceID string,
	handler GossipHandler,
) {

	if n.Gossip == nil {
		return
	}

	n.Gossip.RegisterHandler(
		serviceID,
		handler,
	)
}

func (n *SecureNode) BroadcastRPC(
	ctx context.Context,
	method string,
	payload []byte,
) error {

	if n.RPC == nil {

		return fmt.Errorf(
			"rpc unavailable",
		)
	}

	return n.RPC.Broadcast(
		ctx,
		method,
		payload,
	)
}

func (n *SecureNode) NotifyRPC(
	ctx context.Context,
	method string,
	payload []byte,
) error {

	if n.RPC == nil {

		return fmt.Errorf(
			"rpc unavailable",
		)
	}

	return n.RPC.Notify(
		ctx,
		method,
		payload,
	)
}

func (n *SecureNode) CallPeer(
	ctx context.Context,
	target []byte,
	method string,
	payload []byte,
) ([]byte, error) {

	if n.RPC == nil {

		return nil,
			fmt.Errorf(
				"rpc unavailable",
			)
	}

	return n.RPC.Call(
		ctx,
		target,
		method,
		payload,
		DefaultRPCTimeout,
	)
}

func (n *SecureNode) PublishGossip(
	ctx context.Context,
	serviceID string,
	payload []byte,
	signature []byte,
) error {

	if n.Gossip == nil {

		return fmt.Errorf(
			"gossip unavailable",
		)
	}

	return n.Gossip.Publish(
		ctx,
		serviceID,
		payload,
		signature,
	)
}

func (n *SecureNode) PeerCount() int {

	if n.PeerRoute == nil {
		return 0
	}

	return n.PeerRoute.PeerCount()
}

func (n *SecureNode) IsMeshConnected() bool {

	return n.Mesh != nil &&
		n.Mesh.conn != nil
}

const (
	DefaultRPCTimeout = 15 * time.Second
)
