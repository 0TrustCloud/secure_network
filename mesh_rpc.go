package secure_network

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/logger"
)

const (
	DefaultRPCTimeout = 10 * time.Second
	MaxRPCPayloadSize = 4 * 1024 * 1024
)

// RPCPayload defines the envelope for mesh RPC traffic.
type RPCPayload struct {
	RequestID string          `json:"request_id"`
	Method    string          `json:"method,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	IsReply   bool            `json:"is_reply"`

	// Injected by gateway from Noise-authenticated tunnel.
	Signer []byte `json:"signer,omitempty"`

	// Optional routing metadata.
	TargetPeer string `json:"target_peer,omitempty"`
	OriginPeer string `json:"origin_peer,omitempty"`

	CreatedAt int64 `json:"created_at"`
}

// RPCContext carries authenticated caller identity.
type RPCContext struct {
	CallerID []byte
	PeerID   string
	Context  context.Context
}

// RPCHandler represents a registered RPC method.
type RPCHandler func(
	ctx RPCContext,
	args []byte,
) (interface{}, error)

// RPCManager manages distributed mesh RPC execution.
type RPCManager struct {
	router    *Router
	peerRoute *PeerRoute
	Logger    *logger.LogDispatcher

	methods map[string]RPCHandler
	pending map[string]chan *RPCPayload

	mu sync.RWMutex
}

// NewRPCManager creates a new RPC subsystem.
func NewRPCManager(
	pr *PeerRoute,
	sysLog *logger.LogDispatcher,
) *RPCManager {

	return &RPCManager{
		peerRoute: pr,
		Logger:    sysLog,
		methods:   make(map[string]RPCHandler),
		pending:   make(map[string]chan *RPCPayload),
	}
}

// Name satisfies Module interface.
func (m *RPCManager) Name() string {
	return "mesh_rpc"
}

// Init satisfies Module interface.
func (m *RPCManager) Init(r *Router) error {
	m.router = r
	return nil
}

// Start begins consuming RPC ingress events.
func (m *RPCManager) Start() error {

	if m.router == nil {
		return fmt.Errorf("router not initialized")
	}

	if m.Logger != nil {
		m.Logger.Info(
			"Mesh RPC Engine online",
		)
	}

	go m.consumeIngress()

	go m.cleanupStaleRequests()

	return nil
}

func (m *RPCManager) consumeIngress() {

	for event := range m.router.LocalBus {

		if event.Topic != "rpc_ingress" {
			continue
		}

		go m.handleIngress(
			context.Background(),
			event.Payload,
		)
	}
}

// Register adds a callable RPC method.
func (m *RPCManager) Register(
	method string,
	handler RPCHandler,
) {

	if method == "" || handler == nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.methods[method] = handler

	if m.Logger != nil {
		m.Logger.Info(
			fmt.Sprintf(
				"RPC method registered: %s",
				method,
			),
		)
	}
}

// Call broadcasts RPC request to mesh.
func (m *RPCManager) Call(
	ctx context.Context,
	method string,
	args interface{},
) (*RPCPayload, error) {

	return m.CallPeer(
		ctx,
		"",
		method,
		args,
	)
}

// CallPeer routes RPC to a specific peer.
func (m *RPCManager) CallPeer(
	ctx context.Context,
	targetPeer string,
	method string,
	args interface{},
) (*RPCPayload, error) {

	if method == "" {
		return nil, fmt.Errorf("method required")
	}

	reqID, err := generateRPCRequestID()
	if err != nil {
		return nil, err
	}

	argsBytes, err := json.Marshal(args)
	if err != nil {

		if m.Logger != nil {
			m.Logger.Error(
				fmt.Sprintf(
					"RPC marshal failed for %s: %v",
					method,
					err,
				),
			)
		}

		return nil, err
	}

	if len(argsBytes) > MaxRPCPayloadSize {
		return nil, fmt.Errorf(
			"rpc payload exceeds limit",
		)
	}

	req := RPCPayload{
		RequestID: reqID,
		Method:    method,
		Args:      argsBytes,
		IsReply:   false,
		TargetPeer: targetPeer,
		CreatedAt: time.Now().Unix(),
	}

	replyCh := make(chan *RPCPayload, 1)

	m.mu.Lock()
	m.pending[reqID] = replyCh
	m.mu.Unlock()

	defer func() {

		m.mu.Lock()
		delete(m.pending, reqID)
		close(replyCh)
		m.mu.Unlock()
	}()

	payloadBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	apiReq := APIPayload{
		Action:  "rpc",
		Content: string(payloadBytes),
	}

	apiReqBytes, err := json.Marshal(apiReq)
	if err != nil {
		return nil, err
	}

	if targetPeer != "" {

		err = m.peerRoute.SendToPeer(
			ctx,
			targetPeer,
			apiReqBytes,
		)

	} else {

		err = m.peerRoute.Broadcast(
			ctx,
			apiReqBytes,
		)
	}

	if err != nil {

		if m.Logger != nil {
			m.Logger.Error(
				fmt.Sprintf(
					"RPC dispatch failed: %v",
					err,
				),
			)
		}

		return nil, err
	}

	timeout := time.NewTimer(
		DefaultRPCTimeout,
	)

	defer timeout.Stop()

	select {

	case reply := <-replyCh:

		if reply == nil {
			return nil, fmt.Errorf(
				"rpc reply channel closed",
			)
		}

		if reply.Error != "" {

			if m.Logger != nil {
				m.Logger.Error(
					fmt.Sprintf(
						"RPC remote error (%s): %s",
						method,
						reply.Error,
					),
				)
			}

			return nil, fmt.Errorf(reply.Error)
		}

		return reply, nil

	case <-ctx.Done():

		return nil, ctx.Err()

	case <-timeout.C:

		return nil, fmt.Errorf(
			"rpc timeout for method %s",
			method,
		)
	}
}

// Notify sends fire-and-forget RPC event.
func (m *RPCManager) Notify(
	ctx context.Context,
	method string,
	args interface{},
) error {

	argsBytes, err := json.Marshal(args)
	if err != nil {
		return err
	}

	req := RPCPayload{
		RequestID: "",
		Method:    method,
		Args:      argsBytes,
		IsReply:   false,
		CreatedAt: time.Now().Unix(),
	}

	payloadBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}

	apiReq := APIPayload{
		Action:  "rpc",
		Content: string(payloadBytes),
	}

	apiReqBytes, err := json.Marshal(apiReq)
	if err != nil {
		return err
	}

	return m.peerRoute.Broadcast(
		ctx,
		apiReqBytes,
	)
}

// handleIngress processes incoming RPC packets.
func (m *RPCManager) handleIngress(
	ctx context.Context,
	payload []byte,
) {

	if len(payload) == 0 {
		return
	}

	var req RPCPayload

	if err := json.Unmarshal(payload, &req); err != nil {

		if m.Logger != nil {
			m.Logger.Error(
				fmt.Sprintf(
					"Malformed RPC payload: %v",
					err,
				),
			)
		}

		return
	}

	// Handle replies.
	if req.IsReply {

		m.mu.RLock()
		ch, exists := m.pending[req.RequestID]
		m.mu.RUnlock()

		if exists {

			select {

			case ch <- &req:

			default:

				if m.Logger != nil {
					m.Logger.Error(
						fmt.Sprintf(
							"Dropped RPC reply %s",
							req.RequestID,
						),
					)
				}
			}
		}

		return
	}

	// Execute request.
	m.mu.RLock()
	handler, exists := m.methods[req.Method]
	m.mu.RUnlock()

	reply := RPCPayload{
		RequestID: req.RequestID,
		IsReply:   true,
		CreatedAt: time.Now().Unix(),
	}

	if !exists {

		reply.Error = fmt.Sprintf(
			"rpc method not found: %s",
			req.Method,
		)

		if m.Logger != nil {

			m.Logger.Error(
				fmt.Sprintf(
					"RPC method missing: %s",
					req.Method,
				),
			)
		}

		m.sendReply(ctx, &reply)

		return
	}

	rpcCtx := RPCContext{
		CallerID: req.Signer,
		PeerID:   req.OriginPeer,
		Context:  ctx,
	}

	result, err := handler(
		rpcCtx,
		req.Args,
	)

	if err != nil {

		reply.Error = err.Error()

		if m.Logger != nil {

			m.Logger.Error(
				fmt.Sprintf(
					"RPC execution failed (%s): %v",
					req.Method,
					err,
				),
			)
		}

	} else {

		resBytes, err := json.Marshal(result)
		if err != nil {

			reply.Error = err.Error()

		} else {

			reply.Result = resBytes
		}
	}

	m.sendReply(ctx, &reply)
}

func (m *RPCManager) sendReply(
	ctx context.Context,
	reply *RPCPayload,
) {

	replyBytes, err := json.Marshal(reply)
	if err != nil {
		return
	}

	apiReply := APIPayload{
		Action:  "rpc",
		Content: string(replyBytes),
	}

	apiReplyBytes, err := json.Marshal(apiReply)
	if err != nil {
		return
	}

	err = m.peerRoute.Broadcast(
		ctx,
		apiReplyBytes,
	)

	if err != nil && m.Logger != nil {

		m.Logger.Error(
			fmt.Sprintf(
				"RPC reply dispatch failed: %v",
				err,
			),
		)
	}
}

func (m *RPCManager) cleanupStaleRequests() {

	ticker := time.NewTicker(
		1 * time.Minute,
	)

	defer ticker.Stop()

	for range ticker.C {

		m.mu.Lock()

		for reqID, ch := range m.pending {

			select {

			case <-ch:

			default:
			}

			_ = reqID
		}

		m.mu.Unlock()
	}
}

func generateRPCRequestID() (string, error) {

	buf := make([]byte, 16)

	_, err := rand.Read(buf)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(buf), nil
}
