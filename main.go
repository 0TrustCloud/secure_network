package main

import (
	"context"
	"crypto/tls"
	"log"
	"os"

	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/guikit"
	"github.com/gddisney/webauthnext"
	"github.com/gddisney/secure_network"
)

func main() {
	ctx := context.Background()
	log.Println("Booting Zero-Trust Microkernel Runtime...")

	// 1. Initialize the Foundational Storage Tier (ultimate_db)
	// Manages transactional constraints, raw byte layouts, and index balancing[cite: 130].
	db, err := ultimate_db.NewDatabase("./data/primary.db")
	if err != nil {
		log.Fatalf("Failed to initialize ultimate_db: %v", err)
	}
	defer db.Close()

	// 2. Initialize the Web & Reactive UI Pipeline (guikit)
	// Provides custom markup parsing, routing, and bidirectional WebSocket pipelines[cite: 132].
	// guikit integrates ultimate_db as its embedded database dependency[cite: 396].
	guiEngine := guikit.NewEngine(db)

	// 3. Initialize the Federated Authentication Topology (webauthnext)
	// Transforms the system into a passkey-first OIDC Identity Provider[cite: 158].
	// It hooks directly into guikit's multiplexer and wraps state queries within ultimate_db[cite: 134, 468].
	authProvider := webauthnext.NewProvider(guiEngine, db)
	authProvider.RegisterRoutes() // Exposes /auth/register, /auth/login, /.well-known/openid-configuration[cite: 469, 474].

	// 4. Initialize the Distributed Network Elements (secure_network internals)
	staticPrivKey := loadOrGenerateNoiseKey()
	
	peerMesh := secure_network.NewPeerRoute(staticPrivKey)
	gossip := secure_network.NewGossipManager(db, peerMesh)
	peerMesh.SetIngressHandler(gossip.HandleIngress)
	
	// The Router enforces the DBSC hardware interception middleware[cite: 428].
	edgeRouter := secure_network.NewRouter(db)

	// 5. The Master Link: Attach the App Engine to the Zero-Trust Gateway
	// The Gateway acts as the perimeter, hosting dual-stack HTTP/3 and HTTPS listeners[cite: 163].
	// Crucially, it must proxy all successfully authenticated external traffic down to the guiEngine.
	gateway := secure_network.NewGateway(edgeRouter, peerMesh)
	
	// Bind the guikit multiplexer as the fallback handler for valid, hardware-attested sessions.
	gateway.SetApplicationHandler(guiEngine.ServeHTTP)

	// Boot the Peer Mesh listeners asynchronously
	go peerMesh.Listen(ctx)

	// 6. Boot the Gateway blocking the main thread
	tlsConfig := loadTLSConfig()
	port := ":443"
	
	log.Printf("Microkernel listening on dual-stack port %s", port)
	if err := gateway.ListenAndServe(port, tlsConfig); err != nil {
		log.Fatalf("Gateway fatal error: %v", err)
	}
}

// Dummy helper functions for cryptographic material
func loadOrGenerateNoiseKey() []byte { return []byte("32-byte-static-private-key-here") }
func loadTLSConfig() *tls.Config { return &tls.Config{} }
