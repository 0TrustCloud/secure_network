package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/webauthnext"
)

func TestPolicyEngineInitialization(
	t *testing.T,
) {

	engine := secure_policy.NewPolicyEngine(
		nil,
	)

	if engine == nil {

		t.Fatal(
			"policy engine is nil",
		)
	}
}

func TestSessionManagerInitialization(
	t *testing.T,
) {

	rsaPriv, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)

	if err != nil {

		t.Fatalf(
			"rsa generation failed: %v",
			err,
		)
	}

	manager := secure_policy.NewSessionManager(
		nil,
		rsaPriv,
	)

	if manager == nil {

		t.Fatal(
			"session manager is nil",
		)
	}
}

func TestServiceKeyManagerInitialization(
	t *testing.T,
) {

	manager := service_keys.NewServiceKeyManager(
		nil,
		nil,
		nil,
	)

	if manager == nil {

		t.Fatal(
			"service key manager is nil",
		)
	}
}

func TestGossipIngress(
	t *testing.T,
) {

	peerRoute := NewPeerRoute(
		nil,
		nil,
		nil,
	)

	gossip := NewGossipManager(
		nil,
		peerRoute,
		nil,
		nil,
	)

	payload := []byte(`{
		"id":"test-msg",
		"service_id":"test",
		"payload":"aGVsbG8=",
		"signature":"dGVzdA==",
		"lamport":1
	}`)

	err := gossip.HandleIngress(
		context.Background(),
		payload,
	)

	if err != nil {

		t.Fatalf(
			"gossip ingress failed: %v",
			err,
		)
	}
}


func TestRPCManagerInitialization(
	t *testing.T,
) {

	peerRoute := NewPeerRoute(
		nil,
		nil,
		nil,
	)

	rpc := NewRPCManager(
		peerRoute,
		nil,
	)

	if rpc == nil {

		t.Fatal(
			"rpc manager is nil",
		)
	}
}

func TestRPCRegistration(
	t *testing.T,
) {

	peerRoute := NewPeerRoute(
		nil,
		nil,
		nil,
	)

	rpc := NewRPCManager(
		peerRoute,
		nil,
	)

	called := false

	rpc.Register(
		"ping",
		func(
			ctx context.Context,
			payload []byte,
		) ([]byte, error) {

			called = true

			return []byte("pong"), nil
		},
	)

	handler, ok := rpc.handlers["ping"]

	if !ok {

		t.Fatal(
			"rpc handler not registered",
		)
	}

	resp, err := handler(
		context.Background(),
		[]byte("hello"),
	)

	if err != nil {

		t.Fatalf(
			"handler execution failed: %v",
			err,
		)
	}

	if string(resp) != "pong" {

		t.Fatal(
			"unexpected response",
		)
	}

	if !called {

		t.Fatal(
			"handler was not executed",
		)
	}
}

func TestGossipRegistration(
	t *testing.T,
) {

	peerRoute := NewPeerRoute(
		nil,
		nil,
		nil,
	)

	gossip := NewGossipManager(
		nil,
		peerRoute,
		nil,
		nil,
	)

	called := false

	gossip.RegisterHandler(
		"test-service",
		func(
			ctx context.Context,
			env *GossipEnvelope,
		) error {

			called = true

			return nil
		},
	)

	handler, ok := gossip.handlers["test-service"]

	if !ok {

		t.Fatal(
			"gossip handler missing",
		)
	}

	err := handler(
		context.Background(),
		&GossipEnvelope{},
	)

	if err != nil {

		t.Fatalf(
			"handler execution failed: %v",
			err,
		)
	}

	if !called {

		t.Fatal(
			"handler not called",
		)
	}
}

func TestPeerRouteLifecycle(
	t *testing.T,
) {

	peerRoute := NewPeerRoute(
		nil,
		nil,
		nil,
	)

	var nodeID NodeID

	copy(
		nodeID[:],
		[]byte("peer-1"),
	)

	peer := &PeerIdentity{
		NodeID:    nodeID,
		PublicKey: []byte("pub"),
		Address:   "127.0.0.1",
		LastSeen:  time.Now(),
	}

	peerRoute.AddPeer(
		peer,
	)

	if peerRoute.PeerCount() != 1 {

		t.Fatal(
			"peer count mismatch",
		)
	}

	peerRoute.RemovePeer(
		nodeID,
	)

	if peerRoute.PeerCount() != 0 {

		t.Fatal(
			"peer removal failed",
		)
	}
}

func TestTunnelManagerInitialization(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	if tm == nil {

		t.Fatal(
			"tunnel manager is nil",
		)
	}

	if tm.Name() != "mesh_tunnel" {

		t.Fatal(
			"unexpected module name",
		)
	}
}

func TestTunnelManagerRegisterTunnelNilPolicy(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	auth := TunnelAuthPayload{
		Subdomain:    "demo",
		IdentityType: "human",
		Credential:   "token",
	}

	authBytes, err := json.Marshal(
		auth,
	)

	if err != nil {

		t.Fatalf(
			"marshal failed: %v",
			err,
		)
	}

	err = tm.RegisterTunnel(
		nil,
		authBytes,
	)

	if err == nil {

		t.Fatal(
			"expected error with nil dependencies",
		)
	}
}

func TestTunnelManagerBadPayload(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	err := tm.RegisterTunnel(
		nil,
		[]byte("invalid-json"),
	)

	if err == nil {

		t.Fatal(
			"expected malformed payload error",
		)
	}
}

func TestTunnelManagerUnknownIdentity(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	_, err := tm.authenticate(
		TunnelAuthPayload{
			IdentityType: "alien",
		},
	)

	if err == nil {

		t.Fatal(
			"expected unknown identity error",
		)
	}
}

func TestTunnelManagerExpiredMachineProof(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	oldNonce := fmt.Sprintf(
		"%d",
		time.Now().Unix()-120,
	)

	_, err := tm.authenticate(
		TunnelAuthPayload{
			IdentityType: "machine",
			Identifier:   "agent-1",
			Credential:   "bad",
			Nonce:        oldNonce,
			Subdomain:    "demo",
		},
	)

	if err == nil {

		t.Fatal(
			"expected expired DBSC proof",
		)
	}
}

func TestTunnelManagerHumanWithoutSessionManager(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	_, err := tm.authenticate(
		TunnelAuthPayload{
			IdentityType: "human",
			Credential:   "fake-token",
		},
	)

	if err == nil {

		t.Fatal(
			"expected validation failure",
		)
	}
}

func TestTunnelMapLifecycle(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	if tm.tunnels == nil {

		t.Fatal(
			"tunnel map not initialized",
		)
	}

	if len(tm.tunnels) != 0 {

		t.Fatal(
			"unexpected initial tunnel count",
		)
	}

	tm.mu.Lock()

	tm.tunnels["alpha"] = nil

	tm.mu.Unlock()

	tm.mu.RLock()

	_, ok := tm.tunnels["alpha"]

	tm.mu.RUnlock()

	if !ok {

		t.Fatal(
			"tunnel insert failed",
		)
	}

	tm.mu.Lock()

	delete(
		tm.tunnels,
		"alpha",
	)

	tm.mu.Unlock()

	tm.mu.RLock()

	_, ok = tm.tunnels["alpha"]

	tm.mu.RUnlock()

	if ok {

		t.Fatal(
			"tunnel delete failed",
		)
	}
}

func TestTunnelAuthPayloadJSON(
	t *testing.T,
) {

	msg := TunnelAuthPayload{
		Subdomain:    "app",
		IdentityType: "human",
		Identifier:   "alice",
		Credential:   "token",
		Nonce:        "123",
	}

	raw, err := json.Marshal(
		msg,
	)

	if err != nil {

		t.Fatalf(
			"marshal failed: %v",
			err,
		)
	}

	var decoded TunnelAuthPayload

	err = json.Unmarshal(
		raw,
		&decoded,
	)

	if err != nil {

		t.Fatalf(
			"unmarshal failed: %v",
			err,
		)
	}

	if decoded.Subdomain != "app" {

		t.Fatal(
			"subdomain mismatch",
		)
	}

	if decoded.Identifier != "alice" {

		t.Fatal(
			"identifier mismatch",
		)
	}
}

func TestTunnelManagerInit(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	router := &Router{
		DB:             &ultimate_db.DB{},
		PolicyEngine:   nil,
		SessionManager: nil,
	}

	err := tm.Init(
		router,
	)

	if err != nil {

		t.Fatalf(
			"init failed: %v",
			err,
		)
	}

	if tm.router == nil {

		t.Fatal(
			"router not assigned",
		)
	}
}

func TestTunnelAgentConfig(
	t *testing.T,
) {

	cfg := TunnelAgentConfig{
		GatewayAddr:  "localhost:9443",
		LocalAddr:    "127.0.0.1:3000",
		Subdomain:    "dashboard",
		IdentityType: "human",
		Identifier:   "alice",
		SessionToken: "abc123",
	}

	if cfg.Subdomain != "dashboard" {

		t.Fatal(
			"subdomain mismatch",
		)
	}

	if cfg.IdentityType != "human" {

		t.Fatal(
			"identity type mismatch",
		)
	}
}
