package secure_network

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
)

type GossipEnvelope struct {
	ID         string    `json:"id"`
	ServiceID  string    `json:"service_id"`
	Payload    []byte    `json:"payload"`
	Signature  []byte    `json:"signature"`
	Lamport    uint64    `json:"lamport"`
	Origin     []byte    `json:"origin"`
	ReceivedAt time.Time `json:"received_at"`
}

type GossipHandler func(
	ctx context.Context,
	env *GossipEnvelope,
) error

type GossipManager struct {
	db *ultimate_db.DB

	peerRoute *PeerRoute

	serviceKeys *service_keys.ServiceKeyManager

	Logger *logger.LogDispatcher

	mu sync.RWMutex

	handlers map[string]GossipHandler

	seen map[string]time.Time

	lamport uint64
}

func NewGossipManager(
	db *ultimate_db.DB,
	peerRoute *PeerRoute,
	skm *service_keys.ServiceKeyManager,
	sysLog *logger.LogDispatcher,
) *GossipManager {

	return &GossipManager{
		db:          db,
		peerRoute:   peerRoute,
		serviceKeys: skm,
		Logger:      sysLog,
		handlers:    make(map[string]GossipHandler),
		seen:        make(map[string]time.Time),
	}
}

func (gm *GossipManager) RegisterHandler(
	serviceID string,
	handler GossipHandler,
) {

	gm.mu.Lock()
	defer gm.mu.Unlock()

	gm.handlers[serviceID] = handler

	if gm.Logger != nil {

		gm.Logger.Info(
			fmt.Sprintf(
				"Gossip handler registered: %s",
				serviceID,
			),
		)
	}
}

func (gm *GossipManager) Publish(
	ctx context.Context,
	serviceID string,
	payload []byte,
	signature []byte,
) error {

	gm.mu.Lock()

	gm.lamport++

	lamport := gm.lamport

	gm.mu.Unlock()

	env := GossipEnvelope{
		ID: fmt.Sprintf(
			"%s-%d",
			serviceID,
			time.Now().UnixNano(),
		),
		ServiceID:  serviceID,
		Payload:    payload,
		Signature:  signature,
		Lamport:    lamport,
		ReceivedAt: time.Now(),
	}

	raw, err := json.Marshal(
		env,
	)

	if err != nil {
		return err
	}

	return gm.peerRoute.Broadcast(
		ctx,
		"gossip",
		raw,
	)
}

func (gm *GossipManager) HandleIngress(
	ctx context.Context,
	payload []byte,
) error {

	var env GossipEnvelope

	if err := json.Unmarshal(
		payload,
		&env,
	); err != nil {

		return err
	}

	gm.mu.Lock()

	if ts, exists := gm.seen[env.ID]; exists {

		if time.Since(ts) < time.Hour {

			gm.mu.Unlock()
			return nil
		}
	}

	gm.seen[env.ID] = time.Now()

	if env.Lamport > gm.lamport {

		gm.lamport = env.Lamport
	}

	gm.lamport++

	gm.mu.Unlock()

	if gm.serviceKeys != nil {

		valid := gm.serviceKeys.VerifySignature(
			env.ServiceID,
			env.Payload,
			env.Signature,
		)

		if !valid {

			if gm.Logger != nil {

				gm.Logger.Error(
					fmt.Sprintf(
						"Invalid gossip signature for %s",
						env.ServiceID,
					),
				)
			}

			return fmt.Errorf(
				"invalid gossip signature",
			)
		}
	}

	gm.mu.RLock()

	handler, ok := gm.handlers[env.ServiceID]

	gm.mu.RUnlock()

	if !ok {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"No gossip handler for %s",
					env.ServiceID,
				),
			)
		}

		return nil
	}

	return handler(
		ctx,
		&env,
	)
}

func (gm *GossipManager) CleanupSeenCache() {

	gm.mu.Lock()
	defer gm.mu.Unlock()

	cutoff := time.Now().Add(
		-1 * time.Hour,
	)

	for id, ts := range gm.seen {

		if ts.Before(cutoff) {

			delete(
				gm.seen,
				id,
			)
		}
	}
}

func (gm *GossipManager) StartJanitor() {

	ticker := time.NewTicker(
		15 * time.Minute,
	)

	go func() {

		defer ticker.Stop()

		for range ticker.C {

			gm.CleanupSeenCache()
		}
	}()
}

func (gm *GossipManager) GetLamport() uint64 {

	gm.mu.RLock()
	defer gm.mu.RUnlock()

	return gm.lamport
}

func (gm *GossipManager) SeenCount() int {

	gm.mu.RLock()
	defer gm.mu.RUnlock()

	return len(
		gm.seen,
	)
}
