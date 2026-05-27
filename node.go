package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"log"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

type EdgeNode struct {
	DB             *ultimate_db.DB
	Router         *Router
	PeerMesh       *PeerRoute
	Gossip         *GossipManager
	Gateway        *Gateway
	PolicyEngine   *secure_policy.PolicyEngine
	SessionManager *secure_policy.SessionManager
	Logger         *logger.LogDispatcher // Injected Logger
}

// NewEdgeNode initializes the secure mesh node and propagates the LogDispatcher
func NewEdgeNode(ctx context.Context, dbPath string, staticPrivKey []byte, auth *webauthnext.Provider, sysLogger *logger.LogDispatcher) (*EdgeNode, error) {
	dm, err := ultimate_db.NewDiskManager(dbPath)
	if err != nil {
		return nil, err
	}

	bp := ultimate_db.NewBufferPool(dm, 1024)
	wal, err := ultimate_db.NewBatchingWAL(dbPath + "_wal.log")
	if err != nil {
		return nil, err
	}

	db := ultimate_db.NewDB(bp, wal)
	ultimate_db.RecoverDB(dbPath+"_wal.log", db)

	peerMesh := NewPeerRoute(db, auth, staticPrivKey)
	
	// Inject logger into GossipManager
	gossip := NewGossipManager(db, peerMesh, sysLogger)
	peerMesh.SetIngressHandler(gossip.HandleIngress)

	// Generate RSA key for Session Manager signing
	sessionKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pe := secure_policy.NewPolicyEngine(db)
	sm := secure_policy.NewSessionManager(db, sessionKey)

	router, _ := NewRouter(db, nil, "secure_session_token", pe, sm)

	// Inject logger into key generation
	noisePriv, noisePub, _, err := loadOrGenerateKeys(db, sysLogger)
	if err != nil {
		return nil, err
	}

	// Inject logger into Gateway
	gateway := NewGateway(router, peerMesh, noisePriv, noisePub, sysLogger)
	peerMesh.SetGateway(gateway)

	// Inject logger into RPC Manager
	rpcEngine := NewRPCManager(peerMesh, sysLogger)
	router.Attach(rpcEngine)

	return &EdgeNode{
		DB:             db,
		Router:         router,
		PeerMesh:       peerMesh,
		Gossip:         gossip,
		Gateway:        gateway,
		PolicyEngine:   pe,
		SessionManager: sm,
		Logger:         sysLogger,
	}, nil
}

func (n *EdgeNode) Start(port string, tlsConfig *tls.Config) error {
	if n.Logger != nil {
		n.Logger.Info("Starting Zero-Trust Edge Node on port " + port)
	} else {
		log.Printf("Starting Zero-Trust Edge Node on port %s", port)
	}
	
	go n.PeerMesh.Listen(context.Background())
	return n.Gateway.ListenAndServe(port, tlsConfig)
}
