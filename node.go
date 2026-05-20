package secure_network

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/gddisney/ultimate_db"
)

// EdgeNode represents the fully integrated secure_network microkernel.
type EdgeNode struct {
	DB       *ultimate_db.Database
	Router   *Router
	PeerMesh *PeerRoute
	Gossip   *GossipManager
	Gateway  *Gateway
}

// NewEdgeNode wires the core networking and storage components together.
func NewEdgeNode(ctx context.Context, dbPath string, staticPrivKey []byte) (*EdgeNode, error) {
	// 1. Initialize the Embedded Storage Engine
	// ultimate_db isolates short-lived session garbage and ban states in PageID = 1.
	db, err := ultimate_db.NewDatabase(dbPath)
	if err != nil {
		return nil, err
	}

	// 2. Initialize the Noise IK Peer Routing Mesh
	// Handles decentralized node-to-node communication.
	peerMesh := NewPeerRoute(staticPrivKey)

	// 3. Initialize the Gossip Protocol
	// Wires the DHT state synchronization directly to the mesh and storage layers.
	gossip := NewGossipManager(db, peerMesh)

	// Bind the peer ingress to the gossip handler so incoming Noise frames are decrypted,
	// verified, and synced directly to PageID = 1.
	peerMesh.SetIngressHandler(gossip.HandleIngress)

	// 4. Initialize the Edge Router (DBSC Enforcer)
	// The router needs access to ultimate_db to enforce instant ban checks against 
	// hardware-bound session check-ins at the network edge.
	router := NewRouter(db)

	// 5. Initialize the Dual-Stack Gateway
	// Multiplexes HTTP/3 (UDP) and HTTPS (TCP) on a unified port.
	gateway := NewGateway(router, peerMesh)

	return &EdgeNode{
		DB:       db,
		Router:   router,
		PeerMesh: peerMesh,
		Gossip:   gossip,
		Gateway:  gateway,
	}, nil
}

// Start boots the unified edge node.
func (n *EdgeNode) Start(port string, tlsConfig *tls.Config) error {
	log.Printf("Starting Zero-Trust Edge Node on port %s", port)

	// Boot the Peer Mesh listeners asynchronously
	go n.PeerMesh.Listen(context.Background())

	// Boot the Gateway (Dual-Stack Listeners) blocking the main thread
	return n.Gateway.ListenAndServe(port, tlsConfig)
}
