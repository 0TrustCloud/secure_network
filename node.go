package secure_network

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gddisney/guikit"
	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

type EdgeNode struct {
	DB *ultimate_db.DB

	Router   *Router
	PeerMesh *PeerRoute
	Gossip   *GossipManager
	Gateway  *Gateway
	MeshNode *MeshNode

	ServiceKeys *service_keys.ServiceKeyManager

	Logger *logger.LogDispatcher
}

func NewEdgeNode(
	ctx context.Context,
	dbPath string,
	staticGatewayPubKey []byte,
	auth *webauthnext.Provider,
	sysLogger *logger.LogDispatcher,
) (*EdgeNode, error) {

	// ==========================================
	// DATABASE BOOTSTRAP
	// ==========================================

	dm, err := ultimate_db.NewDiskManager(
		dbPath,
	)

	if err != nil {
		return nil,
			fmt.Errorf(
				"disk manager init failed: %w",
				err,
			)
	}

	bp := ultimate_db.NewBufferPool(
		dm,
		1024,
	)

	wal, err := ultimate_db.NewBatchingWAL(
		dbPath + ".wal",
	)

	if err != nil {
		return nil,
			fmt.Errorf(
				"WAL init failed: %w",
				err,
			)
	}

	db := ultimate_db.NewDB(
		bp,
		wal,
	)

	// ==========================================
	// SYSTEM PAGE INITIALIZATION
	// ==========================================

	for i := 1; i <= 5; i++ {

		pageID := ultimate_db.PageID(i)

		if _, err := bp.FetchPage(pageID); err != nil {

			_, _, err := bp.NewPage()

			if err != nil {
				return nil,
					fmt.Errorf(
						"page allocation failed: %w",
						err,
					)
			}

		} else {

			bp.UnpinPage(
				pageID,
				false,
			)
		}
	}

	// ==========================================
	// GUIKIT
	// ==========================================

	gk := &guikit.GUIKit{
		DB:  db,
		BP:  bp,
		Mux: http.NewServeMux(),
	}

	// ==========================================
	// POLICY ENGINE
	// ==========================================

	policyEngine := secure_policy.NewPolicyEngine()

	sessionManager := secure_policy.NewSessionManager(
		[]byte("secure-dbsc-secret"),
	)

	// ==========================================
	// ROUTER
	// ==========================================

	router, err := NewRouter(
		db,
		gk,
		"secure_session_token",
		policyEngine,
		sessionManager,
		sysLogger,
	)

	if err != nil {
		return nil,
			fmt.Errorf(
				"router init failed: %w",
				err,
			)
	}

	// ==========================================
	// SERVICE KEYS
	// ==========================================

	serviceKeyManager := service_keys.NewServiceKeyManager()

	// ==========================================
	// MESH NODE
	// ==========================================

	meshNode, err := NewMeshNode(
		db,
		staticGatewayPubKey,
		serviceKeyManager,
		sysLogger,
	)

	if err != nil {
		return nil,
			fmt.Errorf(
				"mesh node init failed: %w",
				err,
			)
	}

	// ==========================================
	// PEER ROUTE
	// ==========================================

	peerMesh := NewPeerRoute(
		meshNode,
		serviceKeyManager,
		sysLogger,
	)

	// ==========================================
	// GOSSIP
	// ==========================================

	gossip := NewGossipManager(
		db,
		peerMesh,
		serviceKeyManager,
		sysLogger,
	)

	// ==========================================
	// RPC ENGINE
	// ==========================================

	rpcManager := NewRPCManager(
		peerMesh,
		sysLogger,
	)

	meshNode.SetRPCManager(
		rpcManager,
	)

	// ==========================================
	// ROUTE REGISTRATION
	// ==========================================

	peerMesh.RegisterHandler(
		"gossip",
		func(
			ctx context.Context,
			msg *PeerMessage,
		) error {

			return gossip.HandleIngress(
				ctx,
				msg.Payload,
				nil,
			)
		},
	)

	peerMesh.RegisterHandler(
		"rpc",
		func(
			ctx context.Context,
			msg *PeerMessage,
		) error {

			rpcManager.handleIngress(
				ctx,
				msg.Payload,
			)

			return nil
		},
	)

	// ==========================================
	// GATEWAY
	// ==========================================

	gateway := NewGateway(
		router,
		peerMesh,
		meshNode.noisePriv,
		meshNode.noisePub,
		sysLogger,
	)

	// ==========================================
	// ROUTER MODULES
	// ==========================================

	router.Attach(
		gossip,
	)

	router.Attach(
		rpcManager,
	)

	tunnelManager := NewTunnelManager(
		"8080",
		sysLogger,
	)

	router.Attach(
		tunnelManager,
	)

	// ==========================================
	// NODE
	// ==========================================

	node := &EdgeNode{
		DB:           db,
		Router:       router,
		PeerMesh:     peerMesh,
		Gossip:       gossip,
		Gateway:      gateway,
		MeshNode:     meshNode,
		ServiceKeys:  serviceKeyManager,
		Logger:       sysLogger,
	}

	if sysLogger != nil {

		sysLogger.Info(
			fmt.Sprintf(
				"EdgeNode initialized. Mesh ID: %x",
				meshNode.noisePub[:8],
			),
		)
	}

	return node, nil
}

func (n *EdgeNode) StartGateway(
	port string,
) error {

	if n.Gateway == nil {
		return fmt.Errorf(
			"gateway not initialized",
		)
	}

	return n.Gateway.ListenAndServe(
		port,
		nil,
	)
}

func (n *EdgeNode) ConnectToGateway(
	ctx context.Context,
	addr string,
) error {

	if n.MeshNode == nil {
		return fmt.Errorf(
			"mesh node not initialized",
		)
	}

	return n.MeshNode.Connect(
		ctx,
		addr,
	)
}

func (n *EdgeNode) Shutdown() error {

	if n.Logger != nil {
		n.Logger.Info(
			"Shutting down EdgeNode...",
		)
	}

	if n.MeshNode != nil {
		_ = n.MeshNode.Close()
	}

	if n.DB != nil {
		n.DB.Close()
	}

	return nil
}
