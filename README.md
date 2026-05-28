# secure_network

`secure_network` is a zero-trust QUIC mesh and encrypted edge networking framework written in Go. It combines authenticated overlay routing, hardware-backed identity verification, RPC/gossip synchronization, and secure ingress tunneling into a unified distributed networking layer.

The system is designed for:

* secure edge gateways
* distributed service meshes
* authenticated overlay routing
* encrypted peer-to-peer backplanes
* hardware-bound machine identity
* QUIC-native reverse tunnels
* RPC and gossip propagation
* zero-trust infrastructure

---

# Features

## QUIC Mesh Networking

* Encrypted QUIC overlay transport using `quic-go`
* Persistent peer connections
* Stream multiplexing
* Automatic reconnect handling
* Bidirectional secure overlay communication

## Secure RPC Layer

* Distributed RPC manager
* Request/response correlation
* Broadcast notifications
* Peer-targeted calls
* Timeout handling
* Concurrent-safe pending request tracking

## Gossip Synchronization

* Distributed gossip propagation
* Lamport logical clocks
* Signature verification
* Service-scoped handlers
* Replay protection
* Mesh-wide broadcast support

## Zero-Trust Tunnel Gateway

* Reverse HTTP tunnel ingress
* QUIC-backed stream forwarding
* Subdomain tunnel registration
* Machine identity authentication
* Human session authentication
* Secure overlay proxy transport

## Hardware-Backed Identity

* TPM-backed service identity support
* DBSC-compatible verification flows
* RSA signature validation
* Passkey/WebAuthn integration
* Secure session enforcement

## Secure Overlay Routing

* Peer discovery and management
* Concurrent-safe routing tables
* Dynamic peer registration
* Broadcast routing
* Direct peer messaging

## Production Safety

* Concurrent-safe internal structures
* Race-condition tested
* Graceful shutdown handling
* Context-aware cancellation
* Modular router architecture

---

# Architecture

```text
                ┌────────────────────┐
                │   Public Clients   │
                └─────────┬──────────┘
                          │
                   HTTPS / HTTP3
                          │
                ┌─────────▼──────────┐
                │   Tunnel Gateway   │
                └─────────┬──────────┘
                          │
                 QUIC Overlay Mesh
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
 ┌────────────┐   ┌────────────┐   ┌────────────┐
 │ RPC Layer  │   │ Gossip Bus │   │ PeerRoute  │
 └────────────┘   └────────────┘   └────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          ▼
                  Secure Mesh Nodes
```

---

# Core Components

## MeshNode

Manages encrypted QUIC connectivity between nodes.

Responsibilities:

* peer connection lifecycle
* stream management
* ingress processing
* mesh synchronization
* tunnel coordination

## PeerRoute

Concurrent-safe peer registry and routing fabric.

Supports:

* direct peer delivery
* mesh broadcast
* peer registration/removal
* ingress handlers

## RPCManager

Distributed RPC execution framework.

Supports:

* request/response messaging
* targeted RPC calls
* broadcast notifications
* timeout enforcement
* async handlers

## GossipManager

Distributed state propagation layer.

Supports:

* signed gossip envelopes
* Lamport timestamps
* replay protection
* service-scoped handlers

## TunnelManager

Secure reverse ingress gateway.

Supports:

* HTTP reverse tunneling
* QUIC stream forwarding
* authenticated tunnel binding
* secure overlay ingress

---

# Dependencies

## Core Infrastructure

* `github.com/gddisney/ultimate_db`

  * transactional embedded database
  * WAL-backed persistence
  * buffer pool management

* `github.com/gddisney/logger`

  * distributed audit logging
  * structured event persistence

* `github.com/gddisney/secure_policy`

  * policy enforcement
  * session validation
  * authorization controls

* `github.com/gddisney/service_keys`

  * TPM-backed service identity
  * hardware signature validation

* `github.com/gddisney/webauthnext`

  * passkey/WebAuthn integration
  * session authentication

* `github.com/quic-go/quic-go`

  * QUIC transport layer
  * multiplexed encrypted streams

---

# Installation

```bash
go get github.com/gddisney/secure_network
```

---

# Quick Start

## Initialize a Secure Node

```go
package main

import (
	"log"

	"github.com/gddisney/logger"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
)

func main() {

	db := &ultimate_db.DB{}

	logDispatcher, err := logger.NewLogDispatcher(
		"secure_node",
		db,
		99,
		100,
	)

	if err != nil {
		log.Fatal(err)
	}

	node, err := secure_network.NewSecureNode(
		db,
		logDispatcher,
		"localhost",
		"localhost",
		"Secure Mesh",
		nil,
	)

	if err != nil {
		log.Fatal(err)
	}

	log.Println(node != nil)
}
```

---

# RPC Example

## Register RPC Handler

```go
rpc.Register(
	"ping",
	func(
		ctx context.Context,
		payload []byte,
	) ([]byte, error) {

		return []byte("pong"), nil
	},
)
```

## Execute RPC Call

```go
resp, err := rpc.Call(
	ctx,
	targetNode,
	"ping",
	[]byte("hello"),
	5*time.Second,
)
```

---

# Gossip Example

## Register Gossip Handler

```go
gossip.RegisterHandler(
	"cluster_event",
	func(
		ctx context.Context,
		env *secure_network.GossipEnvelope,
	) error {

		return nil
	},
)
```

---

# Tunnel Example

## Start Tunnel Manager

```go
tm := secure_network.NewTunnelManager(
	"443",
	logger,
)

err := tm.Start()
```

## Tunnel Agent

```go
cfg := secure_network.TunnelAgentConfig{
	GatewayAddr:  "gateway.example.com:443",
	LocalAddr:    "127.0.0.1:8080",
	Subdomain:    "app",
	IdentityType: "human",
	SessionToken: "session-token",
}
```

---

# Security Model

`secure_network` follows a zero-trust design:

* all peers are authenticated
* all mesh traffic is encrypted
* hardware-backed identity is supported
* sessions can be cryptographically bound
* replay attacks are mitigated
* RPC and gossip traffic can be signed
* tunnels require authenticated registration

---

# Testing

Run standard tests:

```bash
go test -v
```

Run race detection:

```bash
go test -race .
```

Run all packages:

```bash
go test ./...
```

---

# Current Status

Validated:

* QUIC mesh transport
* concurrent routing
* RPC subsystem
* gossip propagation
* tunnel registration
* race-condition safety
* secure session integration
* TPM-backed identity verification

---

# License

MIT
