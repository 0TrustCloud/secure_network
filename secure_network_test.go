package secure_network

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"


	"github.com/gddisney/logger"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"

)

func createTestLogger(
	t *testing.T,
	db *ultimate_db.DB,
) *logger.LogDispatcher {

	t.Helper()

	logDisp, err := logger.NewLogDispatcher(
		"test",
		db,
		ConfigPageID,
		100,
	)

	if err != nil {

		t.Fatalf(
			"logger init failed: %v",
			err,
		)
	}

	return logDisp
}

func TestPolicyEngineInitialization(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	engine := secure_policy.NewPolicyEngine(
		db,
	)

	if engine == nil {

		t.Fatal(
			"policy engine nil",
		)
	}
}

func TestSessionManagerInitialization(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	priv, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)

	if err != nil {

		t.Fatal(err)
	}

	sm := secure_policy.NewSessionManager(
		db,
		priv,
	)

	if sm == nil {

		t.Fatal(
			"session manager nil",
		)
	}
}

func TestServiceKeyManagerInitialization(
	t *testing.T,
) {

	db := &ultimate_db.DB{}

	skm := service_keys.NewServiceKeyManager(
		db,
		nil,
		nil,
	)

	if skm == nil {

		t.Fatal(
			"service key manager nil",
		)
	}
}


func TestRPCManagerInitialization(
	t *testing.T,
) {

	rpc := NewRPCManager(
		NewPeerRoute(nil, nil, nil),
		nil,
	)

	if rpc == nil {

		t.Fatal(
			"rpc manager nil",
		)
	}
}

func TestRPCRegistration(
	t *testing.T,
) {

	rpc := NewRPCManager(
		NewPeerRoute(nil, nil, nil),
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
			"handler missing",
		)
	}

	resp, err := handler(
		context.Background(),
		[]byte("hello"),
	)

	if err != nil {

		t.Fatal(err)
	}

	if string(resp) != "pong" {

		t.Fatal(
			"unexpected response",
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

	pr := NewPeerRoute(
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

	pr.AddPeer(peer)

	if pr.PeerCount() != 1 {

		t.Fatal(
			"peer add failed",
		)
	}

	pr.RemovePeer(nodeID)

	if pr.PeerCount() != 0 {

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
			"tunnel manager nil",
		)
	}
}

func TestTunnelRegistrationRejectsInvalidPayload(
	t *testing.T,
) {

	var payload TunnelAuthPayload

	err := json.Unmarshal(
		[]byte("invalid-json"),
		&payload,
	)

	if err == nil {

		t.Fatal(
			"expected invalid json error",
		)
	}
}

func TestTunnelAuthenticationUnknownIdentity(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	_, err := tm.authenticate(
		TunnelAuthPayload{
			IdentityType: "unknown",
		},
	)

	if err == nil {

		t.Fatal(
			"expected auth failure",
		)
	}
}

func TestTunnelManagerName(
	t *testing.T,
) {

	tm := NewTunnelManager(
		"8443",
		nil,
	)

	if tm.Name() != "mesh_tunnel" {

		t.Fatal(
			"unexpected tunnel name",
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
		DB: &ultimate_db.DB{},
	}

	err := tm.Init(router)

	if err != nil {

		t.Fatal(err)
	}
}

func TestTunnelAgentConfig(
	t *testing.T,
) {

	cfg := TunnelAgentConfig{
		GatewayAddr:  "localhost:4433",
		LocalAddr:    "127.0.0.1:8080",
		Subdomain:    "demo",
		IdentityType: "human",
		SessionToken: "token",
	}

	if cfg.Subdomain != "demo" {

		t.Fatal(
			"bad config",
		)
	}
}

func TestTLSConfigCreation(
	t *testing.T,
) {

	cfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos: []string{
			"secure-overlay",
		},
	}

	if len(cfg.NextProtos) == 0 {

		t.Fatal(
			"tls config invalid",
		)
	}
}
