package main

import (
	"context"
	"crypto/tls"
	"log"

	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/guikit"
	"github.com/gddisney/webauthnext"
	"github.com/gddisney/secure_network"
)

func main() {
	ctx := context.Background()
	log.Println("Booting Zero-Trust Microkernel Runtime...")

	dm, err := ultimate_db.NewDiskManager("./data/primary.db")
	if err != nil {
		log.Fatalf("Failed to initialize ultimate_db disk manager: %v", err)
	}
	bp := ultimate_db.NewBufferPool(dm, 1024)
	wal, err := ultimate_db.NewBatchingWAL("./data/wal.log")
	if err != nil {
		log.Fatalf("Failed to initialize WAL: %v", err)
	}
	db := ultimate_db.NewDB(bp, wal)
	ultimate_db.RecoverDB("./data/wal.log", db)

	guiEngine, err := guikit.New("./data/primary.db", "./data/wal.log")
	if err != nil {
		log.Fatalf("Failed to initialize guikit: %v", err)
	}
	guiEngine.DB = db

	authProvider := webauthnext.NewProvider(guiEngine, db)
	authProvider.RegisterRoutes() 

	staticPrivKey := loadOrGenerateNoiseKey()
	
	peerMesh := secure_network.NewPeerRoute(db, authProvider, staticPrivKey)
	gossip := secure_network.NewGossipManager(db, peerMesh)
	peerMesh.SetIngressHandler(gossip.HandleIngress)
	
	edgeRouter, _ := secure_network.NewRouter(db, guiEngine, "secure_session_token")
	
	gateway := secure_network.NewGateway(edgeRouter, peerMesh)
	peerMesh.SetGateway(gateway)
	
	gateway.SetApplicationHandler(guiEngine.Mux.ServeHTTP)

	go peerMesh.Listen(ctx)

	tlsConfig := loadTLSConfig()
	port := "443"
	
	log.Printf("Microkernel listening on dual-stack port %s", port)
	if err := gateway.ListenAndServe(port, tlsConfig); err != nil {
		log.Fatalf("Gateway fatal error: %v", err)
	}
}

func loadOrGenerateNoiseKey() []byte { return []byte("32-byte-static-private-key-here") }
func loadTLSConfig() *tls.Config { return &tls.Config{} }
