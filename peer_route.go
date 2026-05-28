package secure_network

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
)

const (
	DefaultPeerWriteTimeout = 10 * time.Second
	DefaultPeerReadTimeout  = 30 * time.Second
	DefaultPeerQueueSize    = 1024
)

type PeerMessage struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	From      string `json:"from"`
	Target    string `json:"target,omitempty"`
	Timestamp int64  `json:"timestamp"`

	Payload []byte `json:"payload"`

	ServiceName string `json:"service_name,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	Proof       string `json:"proof,omitempty"`

	Signature string `json:"signature,omitempty"`
}

type PeerSession struct {
	ID string

	Node *MeshNode

	LastSeen int64

	SendQueue chan []byte
}

type PeerRoute struct {
	node *MeshNode

	serviceKeys *service_keys.ServiceKeyManager

	Logger *logger.LogDispatcher

	mu sync.RWMutex

	peers map[string]*PeerSession

	handlers map[string]func(
		context.Context,
		*PeerMessage,
	) error

	startOnce sync.Once
	stopOnce  sync.Once

	ctx    context.Context
	cancel context.CancelFunc

	wg sync.WaitGroup
}

func NewPeerRoute(
	node *MeshNode,
	skm *service_keys.ServiceKeyManager,
	sysLog *logger.LogDispatcher,
) *PeerRoute {

	ctx, cancel := context.WithCancel(
		context.Background(),
	)

	return &PeerRoute{
		node:        node,
		serviceKeys: skm,
		Logger:      sysLog,
		peers:       make(map[string]*PeerSession),
		handlers: make(
			map[string]func(
				context.Context,
				*PeerMessage,
			) error,
		),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (p *PeerRoute) Start() {

	p.startOnce.Do(func() {

		if p.Logger != nil {
			p.Logger.Info(
				"PeerRoute overlay online",
			)
		}

		p.wg.Add(1)

		go p.reaperLoop()
	})
}

func (p *PeerRoute) Stop() {

	p.stopOnce.Do(func() {

		p.cancel()

		p.mu.Lock()

		for _, peer := range p.peers {
			close(peer.SendQueue)
		}

		p.peers = map[string]*PeerSession{}

		p.mu.Unlock()

		p.wg.Wait()
	})
}

func (p *PeerRoute) RegisterHandler(
	messageType string,
	handler func(
		context.Context,
		*PeerMessage,
	) error,
) {

	p.mu.Lock()
	defer p.mu.Unlock()

	p.handlers[messageType] = handler
}

func (p *PeerRoute) AddPeer(
	peerID string,
	node *MeshNode,
) {

	p.mu.Lock()
	defer p.mu.Unlock()

	if existing, ok := p.peers[peerID]; ok {

		existing.LastSeen = time.Now().Unix()

		return
	}

	session := &PeerSession{
		ID:        peerID,
		Node:      node,
		LastSeen:  time.Now().Unix(),
		SendQueue: make(chan []byte, DefaultPeerQueueSize),
	}

	p.peers[peerID] = session

	p.wg.Add(1)

	go p.peerWriteLoop(session)

	if p.Logger != nil {

		p.Logger.Info(
			fmt.Sprintf(
				"Peer connected: %s",
				peerID,
			),
		)
	}
}

func (p *PeerRoute) RemovePeer(
	peerID string,
) {

	p.mu.Lock()
	defer p.mu.Unlock()

	peer, ok := p.peers[peerID]
	if !ok {
		return
	}

	close(peer.SendQueue)

	delete(p.peers, peerID)

	if p.Logger != nil {

		p.Logger.Info(
			fmt.Sprintf(
				"Peer removed: %s",
				peerID,
			),
		)
	}
}

func (p *PeerRoute) Broadcast(
	ctx context.Context,
	payload []byte,
) error {

	msg := &PeerMessage{
		ID:        generatePeerMessageID(),
		Type:      "broadcast",
		From:      base64.StdEncoding.EncodeToString(p.node.noisePub),
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}

	return p.broadcastMessage(
		ctx,
		msg,
	)
}

func (p *PeerRoute) SendToPeer(
	ctx context.Context,
	peerID string,
	payload []byte,
) error {

	msg := &PeerMessage{
		ID:        generatePeerMessageID(),
		Type:      "direct",
		From:      base64.StdEncoding.EncodeToString(p.node.noisePub),
		Target:    peerID,
		Timestamp: time.Now().UnixNano(),
		Payload:   payload,
	}

	return p.sendMessageToPeer(
		ctx,
		peerID,
		msg,
	)
}

func (p *PeerRoute) BroadcastSigned(
	ctx context.Context,
	serviceName string,
	payload []byte,
) error {

	nonce := fmt.Sprintf(
		"%d",
		time.Now().UnixNano(),
	)

	signature := ed25519.Sign(
		p.node.dbscPriv,
		[]byte(nonce),
	)

	msg := &PeerMessage{
		ID:          generatePeerMessageID(),
		Type:        "signed_broadcast",
		From:        base64.StdEncoding.EncodeToString(p.node.noisePub),
		Timestamp:   time.Now().UnixNano(),
		Payload:     payload,
		ServiceName: serviceName,
		Nonce:       nonce,
		Proof: base64.StdEncoding.EncodeToString(
			signature,
		),
	}

	return p.broadcastMessage(
		ctx,
		msg,
	)
}

func (p *PeerRoute) HandleIngress(
	ctx context.Context,
	raw []byte,
) error {

	var msg PeerMessage

	if err := json.Unmarshal(
		raw,
		&msg,
	); err != nil {

		return fmt.Errorf(
			"peer message decode failed: %w",
			err,
		)
	}

	if err := p.validateMessage(
		&msg,
	); err != nil {

		if p.Logger != nil {

			p.Logger.Audit(
				"peer_route",
				"PEER_REJECTED",
				err.Error(),
			)
		}

		return err
	}

	p.mu.RLock()

	handler, ok := p.handlers[msg.Type]

	p.mu.RUnlock()

	if ok {

		return handler(
			ctx,
			&msg,
		)
	}

	if p.Logger != nil {

		p.Logger.Info(
			fmt.Sprintf(
				"No handler for peer message type: %s",
				msg.Type,
			),
		)
	}

	return nil
}

func (p *PeerRoute) validateMessage(
	msg *PeerMessage,
) error {

	if msg.ID == "" {
		return fmt.Errorf(
			"missing message id",
		)
	}

	if msg.Timestamp == 0 {
		return fmt.Errorf(
			"missing timestamp",
		)
	}

	if len(msg.Payload) == 0 {
		return fmt.Errorf(
			"empty payload",
		)
	}

	if time.Since(
		time.Unix(0, msg.Timestamp),
	) > 5*time.Minute {

		return fmt.Errorf(
			"stale peer message",
		)
	}

	if msg.ServiceName != "" {

		if p.serviceKeys == nil {

			return fmt.Errorf(
				"service key layer unavailable",
			)
		}

		if msg.Nonce == "" ||
			msg.Proof == "" {

			return fmt.Errorf(
				"missing service proof",
			)
		}

		err := p.node.VerifyMachineIdentity(
			msg.ServiceName,
			msg.Nonce,
			msg.Proof,
			"/mesh/peer",
		)

		if err != nil {

			return fmt.Errorf(
				"service verification failed: %w",
				err,
			)
		}
	}

	return nil
}

func (p *PeerRoute) sendMessageToPeer(
	ctx context.Context,
	peerID string,
	msg *PeerMessage,
) error {

	p.mu.RLock()

	peer, ok := p.peers[peerID]

	p.mu.RUnlock()

	if !ok {

		return fmt.Errorf(
			"peer not found: %s",
			peerID,
		)
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	select {

	case peer.SendQueue <- data:
		return nil

	case <-ctx.Done():
		return ctx.Err()

	default:

		return fmt.Errorf(
			"peer send queue full",
		)
	}
}

func (p *PeerRoute) broadcastMessage(
	ctx context.Context,
	msg *PeerMessage,
) error {

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	p.mu.RLock()

	peers := make(
		[]*PeerSession,
		0,
		len(p.peers),
	)

	for _, peer := range p.peers {
		peers = append(peers, peer)
	}

	p.mu.RUnlock()

	for _, peer := range peers {

		select {

		case peer.SendQueue <- data:

		case <-ctx.Done():
			return ctx.Err()

		default:

			if p.Logger != nil {

				p.Logger.Error(
					fmt.Sprintf(
						"Peer queue full: %s",
						peer.ID,
					),
				)
			}
		}
	}

	return nil
}

func (p *PeerRoute) peerWriteLoop(
	peer *PeerSession,
) {

	defer p.wg.Done()

	for {

		select {

		case <-p.ctx.Done():
			return

		case payload, ok := <-peer.SendQueue:

			if !ok {
				return
			}

			writeCtx, cancel := context.WithTimeout(
				p.ctx,
				DefaultPeerWriteTimeout,
			)

			err := peer.Node.SendAction(
				APIPayload{
					Action:  "peer_message",
					Content: string(payload),
				},
			)

			cancel()

			if err != nil {

				if p.Logger != nil {

					p.Logger.Error(
						fmt.Sprintf(
							"Peer write failed [%s]: %v",
							peer.ID,
							err,
						),
					)
				}

				p.RemovePeer(peer.ID)

				return
			}

			peer.LastSeen = time.Now().Unix()

			select {

			case <-writeCtx.Done():

			default:
			}
		}
	}
}

func (p *PeerRoute) reaperLoop() {

	defer p.wg.Done()

	ticker := time.NewTicker(
		2 * time.Minute,
	)

	defer ticker.Stop()

	for {

		select {

		case <-p.ctx.Done():
			return

		case <-ticker.C:

			now := time.Now().Unix()

			var expired []string

			p.mu.RLock()

			for id, peer := range p.peers {

				if now-peer.LastSeen > 300 {
					expired = append(expired, id)
				}
			}

			p.mu.RUnlock()

			for _, id := range expired {

				if p.Logger != nil {

					p.Logger.Info(
						fmt.Sprintf(
							"Reaping stale peer: %s",
							id,
						),
					)
				}

				p.RemovePeer(id)
			}
		}
	}
}

func (p *PeerRoute) PeerCount() int {

	p.mu.RLock()
	defer p.mu.RUnlock()

	return len(p.peers)
}

func (p *PeerRoute) ListPeers() []string {

	p.mu.RLock()
	defer p.mu.RUnlock()

	out := make([]string, 0, len(p.peers))

	for id := range p.peers {
		out = append(out, id)
	}

	return out
}

func generatePeerMessageID() string {

	b := make([]byte, 16)

	_, _ = rand.Read(b)

	return base64.RawURLEncoding.EncodeToString(b)
}
