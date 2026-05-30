package secure_network

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/0TrustCloud/logger"
)

type RPCPacket struct {
	ID        string `json:"id"`
	Method    string `json:"method"`
	Payload   []byte `json:"payload"`
	Source    []byte `json:"source,omitempty"`
	Target    []byte `json:"target,omitempty"`
	Timestamp int64  `json:"timestamp"`
	Response  bool   `json:"response"`
	Error     string `json:"error,omitempty"`
}

type RPCHandler func(
	ctx context.Context,
	payload []byte,
) ([]byte, error)

type pendingRPC struct {
	ch chan *RPCPacket
}

type RPCManager struct {
	peerRoute *PeerRoute

	Logger *logger.LogDispatcher

	mu sync.RWMutex

	handlers map[string]RPCHandler

	pending map[string]*pendingRPC
}

func NewRPCManager(
	peerRoute *PeerRoute,
	sysLog *logger.LogDispatcher,
) *RPCManager {

	return &RPCManager{
		peerRoute: peerRoute,
		Logger:    sysLog,
		handlers:  make(map[string]RPCHandler),
		pending:   make(map[string]*pendingRPC),
	}
}

func (m *RPCManager) Init() error {
	return nil
}

func (m *RPCManager) Name() string {
	return "rpc_manager"
}

func (m *RPCManager) Register(
	method string,
	handler RPCHandler,
) {

	m.mu.Lock()
	defer m.mu.Unlock()

	m.handlers[method] = handler

	if m.Logger != nil {

		m.Logger.Info(
			fmt.Sprintf(
				"RPC method registered: %s",
				method,
			),
		)
	}
}

func (m *RPCManager) Call(
	ctx context.Context,
	target []byte,
	method string,
	payload []byte,
	timeout time.Duration,
) ([]byte, error) {

	reqIDBytes := make([]byte, 16)

	if _, err := rand.Read(
		reqIDBytes,
	); err != nil {

		return nil, err
	}

	reqID := hex.EncodeToString(
		reqIDBytes,
	)

	packet := RPCPacket{
		ID:        reqID,
		Method:    method,
		Payload:   payload,
		Target:    target,
		Timestamp: time.Now().Unix(),
		Response:  false,
	}

	raw, err := json.Marshal(
		packet,
	)

	if err != nil {
		return nil, err
	}

	waiter := &pendingRPC{
		ch: make(chan *RPCPacket, 1),
	}

	m.mu.Lock()
	m.pending[reqID] = waiter
	m.mu.Unlock()

	defer func() {

		m.mu.Lock()

		delete(
			m.pending,
			reqID,
		)

		m.mu.Unlock()
	}()

	err = m.peerRoute.SendToPeer(
		ctx,
		target,
		"rpc",
		raw,
	)

	if err != nil {
		return nil, err
	}

	select {

	case resp := <-waiter.ch:

		if resp.Error != "" {

			return nil,
				fmt.Errorf(
					"%s",
					resp.Error,
				)
		}

		return resp.Payload, nil

	case <-ctx.Done():

		return nil,
			ctx.Err()

	case <-time.After(timeout):

		return nil,
			fmt.Errorf(
				"rpc timeout",
			)
	}
}

func (m *RPCManager) Broadcast(
	ctx context.Context,
	method string,
	payload []byte,
) error {

	packet := RPCPacket{
		Method:    method,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
		Response:  false,
	}

	raw, err := json.Marshal(
		packet,
	)

	if err != nil {
		return err
	}

	return m.peerRoute.Broadcast(
		ctx,
		"rpc",
		raw,
	)
}

func (m *RPCManager) Notify(
	ctx context.Context,
	method string,
	payload []byte,
) error {

	packet := RPCPacket{
		Method:    method,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
		Response:  false,
	}

	raw, err := json.Marshal(
		packet,
	)

	if err != nil {
		return err
	}

	return m.peerRoute.Broadcast(
		ctx,
		"rpc",
		raw,
	)
}

func (m *RPCManager) NotifyPeer(
	ctx context.Context,
	target []byte,
	method string,
	payload []byte,
) error {

	packet := RPCPacket{
		Method:    method,
		Payload:   payload,
		Target:    target,
		Timestamp: time.Now().Unix(),
		Response:  false,
	}

	raw, err := json.Marshal(
		packet,
	)

	if err != nil {
		return err
	}

	return m.peerRoute.SendToPeer(
		ctx,
		target,
		"rpc",
		raw,
	)
}

func (m *RPCManager) handleIngress(
	ctx context.Context,
	payload []byte,
) {

	var packet RPCPacket

	if err := json.Unmarshal(
		payload,
		&packet,
	); err != nil {

		if m.Logger != nil {

			m.Logger.Error(
				fmt.Sprintf(
					"RPC decode failed: %v",
					err,
				),
			)
		}

		return
	}

	if packet.Response {

		m.mu.RLock()

		waiter, ok := m.pending[packet.ID]

		m.mu.RUnlock()

		if ok {

			select {

			case waiter.ch <- &packet:

			default:
			}
		}

		return
	}

	m.mu.RLock()

	handler, ok := m.handlers[packet.Method]

	m.mu.RUnlock()

	if !ok {

		if m.Logger != nil {

			m.Logger.Error(
				fmt.Sprintf(
					"Unknown RPC method: %s",
					packet.Method,
				),
			)
		}

		return
	}

	respPayload, err := handler(
		ctx,
		packet.Payload,
	)

	resp := RPCPacket{
		ID:        packet.ID,
		Method:    packet.Method,
		Payload:   respPayload,
		Target:    packet.Source,
		Response:  true,
		Timestamp: time.Now().Unix(),
	}

	if err != nil {

		resp.Error = err.Error()
	}

	raw, marshalErr := json.Marshal(
		resp,
	)

	if marshalErr != nil {

		if m.Logger != nil {

			m.Logger.Error(
				fmt.Sprintf(
					"RPC marshal failed: %v",
					marshalErr,
				),
			)
		}

		return
	}

	if len(packet.Source) > 0 {

		_ = m.peerRoute.SendToPeer(
			ctx,
			packet.Source,
			"rpc",
			raw,
		)

	} else {

		_ = m.peerRoute.Broadcast(
			ctx,
			"rpc",
			raw,
		)
	}
}

// RPCContext is the struct requested by identity_provider
type RPCContext struct {
	Ctx context.Context
}

// Init now satisfies the secure_network.Module interface
func (m *RPCManager) Init(router *Router) error {
	return nil
}
