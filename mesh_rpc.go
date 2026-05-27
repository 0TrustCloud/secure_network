package secure_network

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/gddisney/logger"
)

// RPCPayload defines the envelope for our Mesh RPC traffic.
type RPCPayload struct {
	RequestID string          `json:"request_id"`
	Method    string          `json:"method,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	IsReply   bool            `json:"is_reply"`
	Signer    []byte          `json:"signer"` // Injected securely by the Gateway
}

// RPCContext carries the caller's cryptographic identity for authorization.
type RPCContext struct {
	CallerID []byte
}

// RPCManager implements the Module interface and manages mesh function calls.
type RPCManager struct {
	router    *Router
	peerRoute *PeerRoute
	Logger    *logger.LogDispatcher // Injected Logger

	methods map[string]func(ctx RPCContext, args []byte) (interface{}, error)
	pending map[string]chan *RPCPayload
	mu      sync.RWMutex
}

// NewRPCManager creates a new instance of the RPC engine.
func NewRPCManager(pr *PeerRoute, sysLog *logger.LogDispatcher) *RPCManager {
	return &RPCManager{
		peerRoute: pr,
		Logger:    sysLog,
		methods:   make(map[string]func(RPCContext, []byte) (interface{}, error)),
		pending:   make(map[string]chan *RPCPayload),
	}
}

// Name satisfies the Module interface.
func (m *RPCManager) Name() string { return "mesh_rpc" }

// Init satisfies the Module interface.
func (m *RPCManager) Init(r *Router) error {
	m.router = r
	return nil
}

// Start satisfies the Module interface.
func (m *RPCManager) Start() error {
	if m.Logger != nil {
		m.Logger.Info("Mesh RPC Engine online and listening to LocalBus")
	}

	// Listen for RPC events published by the Gateway
	for event := range m.router.LocalBus {
		if event.Topic == "rpc_ingress" {
			go m.handleIngress(event.Payload)
		}
	}
	return nil
}

// Register adds a local function to the RPC registry.
func (m *RPCManager) Register(method string, handler func(RPCContext, []byte) (interface{}, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.methods[method] = handler
}

// Call executes a remote RPC method across the mesh and waits for a reply.
func (m *RPCManager) Call(ctx context.Context, method string, args interface{}) (*RPCPayload, error) {
	// Generate a unique Request ID
	reqIDBytes := make([]byte, 8)
	rand.Read(reqIDBytes)
	reqID := hex.EncodeToString(reqIDBytes)

	argsBytes, err := json.Marshal(args)
	if err != nil {
		if m.Logger != nil {
			m.Logger.Error(fmt.Sprintf("Failed to marshal RPC args for method '%s': %v", method, err))
		}
		return nil, fmt.Errorf("failed to marshal args: %w", err)
	}

	req := RPCPayload{
		RequestID: reqID,
		Method:    method,
		Args:      argsBytes,
		IsReply:   false,
	}

	replyCh := make(chan *RPCPayload, 1)

	m.mu.Lock()
	m.pending[reqID] = replyCh
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.pending, reqID)
		m.mu.Unlock()
	}()

	payloadBytes, _ := json.Marshal(req)

	// Wrap in the APIPayload envelope expected by your Gossip/Gateway mesh
	apiReq := APIPayload{
		Action:  "rpc",
		Content: string(payloadBytes),
	}
	apiReqBytes, _ := json.Marshal(apiReq)

	// Broadcast out to the mesh
	m.peerRoute.Broadcast(ctx, apiReqBytes)

	// Wait for the response or context timeout
	select {
	case reply := <-replyCh:
		if reply.Error != "" {
			return nil, fmt.Errorf("remote error: %s", reply.Error)
		}
		return reply, nil
	case <-ctx.Done():
		if m.Logger != nil {
			m.Logger.Error(fmt.Sprintf("RPC Call timeout for method '%s'", method))
		}
		return nil, ctx.Err()
	}
}

// handleIngress processes incoming packets off the LocalBus.
func (m *RPCManager) handleIngress(payload []byte) {
	var req RPCPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		if m.Logger != nil {
			m.Logger.Error(fmt.Sprintf("Malformed RPC payload dropped: %v", err))
		}
		return
	}

	// 1. Handle incoming replies to our outgoing requests
	if req.IsReply {
		m.mu.RLock()
		ch, exists := m.pending[req.RequestID]
		m.mu.RUnlock()
		if exists {
			ch <- &req
		}
		return
	}

	// 2. Handle incoming requests from remote nodes
	m.mu.RLock()
	handler, exists := m.methods[req.Method]
	m.mu.RUnlock()

	reply := RPCPayload{
		RequestID: req.RequestID,
		IsReply:   true,
	}

	if !exists {
		reply.Error = fmt.Sprintf("method '%s' not found", req.Method)
		if m.Logger != nil {
			m.Logger.Error(fmt.Sprintf("RPC method '%s' requested by %x not found", req.Method, req.Signer[:8]))
		}
	} else {
		// Inject the cryptographic identity established by the Noise tunnel
		ctx := RPCContext{CallerID: req.Signer}
		res, err := handler(ctx, req.Args)
		if err != nil {
			reply.Error = err.Error()
			if m.Logger != nil {
				m.Logger.Error(fmt.Sprintf("RPC method '%s' failed for %x: %v", req.Method, req.Signer[:8], err))
			}
		} else {
			resBytes, _ := json.Marshal(res)
			reply.Result = resBytes
			
			// Optional: Audit successful RPC execution if tracing is highly desired
			// if m.Logger != nil {
			// 	m.Logger.Info(fmt.Sprintf("Successfully executed RPC method '%s' for %x", req.Method, req.Signer[:8]))
			// }
		}
	}

	replyBytes, _ := json.Marshal(reply)

	apiReply := APIPayload{
		Action:  "rpc",
		Content: string(replyBytes),
	}
	apiReplyBytes, _ := json.Marshal(apiReply)

	// Route the reply back to the mesh
	m.peerRoute.Broadcast(context.Background(), apiReplyBytes)
}
