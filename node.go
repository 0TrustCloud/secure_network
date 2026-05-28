package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
	"github.com/gddisney/secure_policy"
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

	if sysLog == nil {

		sysLog = logger.NewLogDispatcher()
	}

	bp := db.BufferPool()

	_, err := bp.NewPage()

	if err != nil {

		return nil,
			fmt.Errorf(
				"failed creating bootstrap page: %w",
				err,
			)
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

	webAuthnProvider := webauthnext.New(
		nil,
		sessionManager,
		rpID,
		rpOrigin,
		rpName,
	)

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

	if sysLog != nil {

		sysLog.Info(
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

func (n *SecureNode) Broadcast(
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

const (
	DefaultRPCTimeout = 15_000_000_000
)
