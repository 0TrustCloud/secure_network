package secure_network

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
	"github.com/gddisney/logger"
	"github.com/gddisney/service_keys"
	"github.com/gddisney/ultimate_db"
)

const (
	AuthPageID ultimate_db.PageID = 1

	DefaultGossipTTL       = 5 * time.Minute
	MaxGossipPayloadSize   = 2 * 1024 * 1024
	GossipReplayWindowSize = 4096
)

// GossipFrame is replicated across the secure mesh.
type GossipFrame struct {
	Key         string `json:"k"`
	Value       []byte `json:"v"`
	LamportTime uint64 `json:"lt"`

	// Service identity.
	ServiceID string `json:"sid"`

	// Signed timestamp nonce.
	Nonce int64 `json:"nonce"`

	// DBSC / TPM-backed signature.
	Signature string `json:"sig"`

	// Optional metadata.
	ContentType string `json:"ct,omitempty"`
	ShardID     uint64 `json:"shard_id,omitempty"`
}

// GossipManager handles distributed replicated state.
type GossipManager struct {
	db     *ultimate_db.DB
	router *PeerRoute

	serviceKeys *service_keys.ServiceKeyManager

	Logger *logger.LogDispatcher

	clock uint64

	framePool *sync.Pool

	replayMu sync.Mutex
	replays  map[string]int64
}

// NewGossipManager initializes the gossip subsystem.
func NewGossipManager(
	db *ultimate_db.DB,
	router *PeerRoute,
	serviceKeyManager *service_keys.ServiceKeyManager,
	sysLog *logger.LogDispatcher,
) *GossipManager {

	gm := &GossipManager{
		db:          db,
		router:      router,
		serviceKeys: serviceKeyManager,
		Logger:      sysLog,
		replays:     make(map[string]int64),
		framePool: &sync.Pool{
			New: func() interface{} {
				return &GossipFrame{}
			},
		},
	}

	go gm.cleanupReplayCache()

	return gm
}

// Tick advances Lamport clock.
func (gm *GossipManager) Tick() uint64 {
	return atomic.AddUint64(
		&gm.clock,
		1,
	)
}

// updateClock synchronizes Lamport time.
func (gm *GossipManager) updateClock(
	incoming uint64,
) {

	for {

		current := atomic.LoadUint64(
			&gm.clock,
		)

		if current >= incoming {
			break
		}

		if atomic.CompareAndSwapUint64(
			&gm.clock,
			current,
			incoming,
		) {
			break
		}
	}

	atomic.AddUint64(
		&gm.clock,
		1,
	)
}

// BroadcastStateChange sends signed state update.
func (gm *GossipManager) BroadcastStateChange(
	ctx context.Context,
	key string,
	value []byte,
	serviceID string,
	signer func(string) (string, error),
) error {

	if key == "" {
		return errors.New(
			"gossip key required",
		)
	}

	if len(value) > MaxGossipPayloadSize {
		return fmt.Errorf(
			"gossip payload exceeds limit",
		)
	}

	if signer == nil {
		return errors.New(
			"service signer required",
		)
	}

	frame := gm.framePool.Get().
		(*GossipFrame)

	defer gm.framePool.Put(frame)

	now := time.Now().Unix()

	frame.Key = key
	frame.Value = value
	frame.LamportTime = gm.Tick()
	frame.ServiceID = serviceID
	frame.Nonce = now
	frame.ContentType = "application/octet-stream"

	signingPayload := gm.buildSigningPayload(
		frame,
	)

	sig, err := signer(
		signingPayload,
	)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Gossip signing failed: %v",
					err,
				),
			)
		}

		return err
	}

	frame.Signature = sig

	payload, err := json.Marshal(frame)
	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Failed to marshal gossip frame: %v",
					err,
				),
			)
		}

		return err
	}

	err = gm.router.Broadcast(
		ctx,
		payload,
	)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Gossip broadcast failed: %v",
					err,
				),
			)
		}

		return err
	}

	if gm.Logger != nil {

		gm.Logger.Info(
			fmt.Sprintf(
				"Gossip broadcast committed [%s]",
				key,
			),
		)
	}

	return nil
}

// HandleIngress processes encrypted gossip frames.
func (gm *GossipManager) HandleIngress(
	ctx context.Context,
	encryptedPayload []byte,
	peerNoiseState *noise.CipherState,
) error {

	if peerNoiseState == nil {
		return errors.New(
			"missing noise cipher state",
		)
	}

	payload, err := peerNoiseState.Decrypt(
		nil,
		nil,
		encryptedPayload,
	)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				"Gossip decrypt failed",
			)
		}

		return errors.New(
			"noise decryption failed",
		)
	}

	if len(payload) > MaxGossipPayloadSize {

		if gm.Logger != nil {

			gm.Logger.Error(
				"Gossip payload exceeds limit",
			)
		}

		return errors.New(
			"payload exceeds limit",
		)
	}

	frame := gm.framePool.Get().
		(*GossipFrame)

	defer func() {

		*frame = GossipFrame{}

		gm.framePool.Put(frame)
	}()

	if err := json.Unmarshal(
		payload,
		frame,
	); err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Gossip unmarshal failed: %v",
					err,
				),
			)
		}

		return err
	}

	if frame.Key == "" {
		return errors.New(
			"missing gossip key",
		)
	}

	// Replay protection.
	if gm.isReplay(frame) {

		if gm.Logger != nil {

			gm.Logger.Audit(
				frame.ServiceID,
				"GOSSIP_REPLAY_BLOCKED",
				frame.Key,
			)
		}

		return errors.New(
			"replay detected",
		)
	}

	// Expiration protection.
	if time.Now().Unix()-frame.Nonce > int64(DefaultGossipTTL.Seconds()) {

		if gm.Logger != nil {

			gm.Logger.Audit(
				frame.ServiceID,
				"GOSSIP_EXPIRED",
				frame.Key,
			)
		}

		return errors.New(
			"gossip frame expired",
		)
	}

	// Verify TPM-backed service identity.
	if err := gm.verifyServiceFrame(
		frame,
	); err != nil {

		if gm.Logger != nil {

			gm.Logger.Audit(
				frame.ServiceID,
				"GOSSIP_AUTH_FAILED",
				err.Error(),
			)
		}

		return err
	}

	gm.updateClock(
		frame.LamportTime,
	)

	writeTxn := gm.db.BeginTxn()

	err = gm.db.Write(
		AuthPageID,
		writeTxn,
		[]byte(frame.Key),
		frame.Value,
		0,
	)

	gm.db.CommitTxn(writeTxn)

	if err != nil {

		if gm.Logger != nil {

			gm.Logger.Error(
				fmt.Sprintf(
					"Gossip DB write failed: %v",
					err,
				),
			)
		}

		return err
	}

	if gm.Logger != nil {

		gm.Logger.Info(
			fmt.Sprintf(
				"Gossip synchronized [%s] from %s",
				frame.Key,
				frame.ServiceID,
			),
		)
	}

	return nil
}

// verifyServiceFrame validates DBSC-backed frame signature.
func (gm *GossipManager) verifyServiceFrame(
	frame *GossipFrame,
) error {

	if gm.serviceKeys == nil {
		return errors.New(
			"service key manager unavailable",
		)
	}

	if frame.ServiceID == "" {
		return errors.New(
			"missing service identity",
		)
	}

	if frame.Signature == "" {
		return errors.New(
			"missing gossip signature",
		)
	}

	// Reuse your ServiceKeyManager verifier.
	payload := gm.buildSigningPayload(
		frame,
	)

	err := gm.serviceKeys.VerifyDetachedSignature(
		frame.ServiceID,
		payload,
		frame.Signature,
	)

	if err != nil {

		return fmt.Errorf(
			"service signature invalid: %w",
			err,
		)
	}

	return nil
}

// buildSigningPayload creates canonical payload.
func (gm *GossipManager) buildSigningPayload(
	frame *GossipFrame,
) string {

	return fmt.Sprintf(
		"%s|%d|%d|%d",
		frame.Key,
		len(frame.Value),
		frame.LamportTime,
		frame.Nonce,
	)
}

// Replay prevention.
func (gm *GossipManager) isReplay(
	frame *GossipFrame,
) bool {

	replayKey := fmt.Sprintf(
		"%s:%d:%d",
		frame.ServiceID,
		frame.LamportTime,
		frame.Nonce,
	)

	gm.replayMu.Lock()
	defer gm.replayMu.Unlock()

	if _, exists := gm.replays[replayKey]; exists {
		return true
	}

	gm.replays[replayKey] = time.Now().Unix()

	if len(gm.replays) > GossipReplayWindowSize {

		for k := range gm.replays {
			delete(gm.replays, k)
			break
		}
	}

	return false
}

// cleanupReplayCache prevents unbounded growth.
func (gm *GossipManager) cleanupReplayCache() {

	ticker := time.NewTicker(
		5 * time.Minute,
	)

	defer ticker.Stop()

	for range ticker.C {

		cutoff := time.Now().
			Add(-DefaultGossipTTL).
			Unix()

		gm.replayMu.Lock()

		for k, ts := range gm.replays {

			if ts < cutoff {
				delete(gm.replays, k)
			}
		}

		gm.replayMu.Unlock()
	}
}
