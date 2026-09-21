package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/nshekhawat/portcullis/internal/clock"
)

// Defaults for the Redis-backed tier store.
const (
	DefaultTierKey      = "pc:tiers"
	DefaultTierChannel  = "pc:tiers:events"
	DefaultResyncPeriod = 10 * time.Second
)

// RedisOptions configures a RedisStore.
type RedisOptions struct {
	// Key is the hash holding identity -> entry JSON.
	Key string
	// Channel is the pub/sub channel carrying change events.
	Channel string
	// ResyncInterval is the safety-net full refresh period.
	ResyncInterval time.Duration
	Clock          clock.Clock
	Logger         *zap.Logger
}

// tierEvent is the pub/sub payload.
type tierEvent struct {
	Op       string    `json:"op"`
	Identity string    `json:"identity"`
	Entry    TierEntry `json:"entry"`
}

// RedisStore keeps tiers in Redis and serves lookups from a local mirror.
//
// The mirror is kept current by pub/sub for immediate propagation and by a
// periodic full resync as a safety net, so a dropped message costs latency, not
// correctness.
type RedisStore struct {
	client *redis.Client
	mirror *MemoryStore
	opts   RedisOptions

	pubsub *redis.PubSub
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewRedisStore connects the store, loads the initial mirror and starts the
// subscription and resync loops.
func NewRedisStore(ctx context.Context, client *redis.Client, opts RedisOptions) (*RedisStore, error) {
	if opts.Key == "" {
		opts.Key = DefaultTierKey
	}
	if opts.Channel == "" {
		opts.Channel = DefaultTierChannel
	}
	if opts.ResyncInterval <= 0 {
		opts.ResyncInterval = DefaultResyncPeriod
	}
	if opts.Clock == nil {
		opts.Clock = clock.System()
	}
	if opts.Logger == nil {
		opts.Logger = zap.NewNop()
	}

	s := &RedisStore{
		client: client,
		mirror: NewMemoryStore(opts.Clock),
		opts:   opts,
	}

	if err := s.Resync(ctx); err != nil {
		return nil, err
	}

	s.pubsub = client.Subscribe(ctx, opts.Channel)
	// Wait for the subscription to be registered before returning, so a caller
	// that writes immediately is not racing the subscriber.
	if _, err := s.pubsub.Receive(ctx); err != nil {
		_ = s.pubsub.Close()
		return nil, fmt.Errorf("failed to subscribe to %s: %w", opts.Channel, err)
	}

	loopCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.wg.Add(2)
	go s.listen(loopCtx)
	go s.resyncLoop(loopCtx)

	return s, nil
}

// Lookup reads the local mirror: no I/O, no allocation.
func (s *RedisStore) Lookup(identity string, now time.Time) (TierEntry, bool) {
	return s.mirror.Lookup(identity, now)
}

// Set writes the entry to Redis, publishes the change and updates the mirror.
func (s *RedisStore) Set(ctx context.Context, identity string, e TierEntry) error {
	payload, marshalErr := json.Marshal(e)
	if marshalErr != nil {
		return fmt.Errorf("failed to marshal tier entry: %w", marshalErr)
	}
	if err := s.client.HSet(ctx, s.opts.Key, identity, payload).Err(); err != nil {
		return fmt.Errorf("failed to store tier entry: %w", err)
	}
	// The in-memory mirror never fails; Redis is the source of truth and the
	// resync repairs it regardless.
	_ = s.mirror.Set(ctx, identity, e)

	// Publish after the write so a subscriber that reacts by reading Redis sees
	// the new value.
	event, err := json.Marshal(tierEvent{Op: "set", Identity: identity, Entry: e})
	if err != nil {
		return fmt.Errorf("failed to marshal tier event: %w", err)
	}
	if err := s.client.Publish(ctx, s.opts.Channel, event).Err(); err != nil {
		// The local mirror is already correct and the resync will catch peers.
		s.opts.Logger.Warn("failed to publish tier event", zap.Error(err))
	}
	return nil
}

// Delete removes the entry from Redis, publishes the change and updates the mirror.
func (s *RedisStore) Delete(ctx context.Context, identity string) error {
	if err := s.client.HDel(ctx, s.opts.Key, identity).Err(); err != nil {
		return fmt.Errorf("failed to delete tier entry: %w", err)
	}
	_ = s.mirror.Delete(ctx, identity)

	event, err := json.Marshal(tierEvent{Op: "del", Identity: identity})
	if err != nil {
		return fmt.Errorf("failed to marshal tier event: %w", err)
	}
	if err := s.client.Publish(ctx, s.opts.Channel, event).Err(); err != nil {
		s.opts.Logger.Warn("failed to publish tier event", zap.Error(err))
	}
	return nil
}

// List reads every entry from Redis, not from the mirror.
func (s *RedisStore) List(ctx context.Context) (map[string]TierEntry, error) {
	return s.readAll(ctx)
}

// Resync replaces the mirror with the authoritative contents of Redis.
func (s *RedisStore) Resync(ctx context.Context) error {
	entries, err := s.readAll(ctx)
	if err != nil {
		return err
	}
	s.mirror.replaceAll(entries)
	return nil
}

// readAll loads the hash from Redis, filtering to entries that are still
// active and reaping (HDel) the ones that have expired.
//
// Without this, an expired entry stays in the hash forever: it is only ever
// removed by an explicit Delete, so an attacker rotating through identities
// (exactly the traffic this store exists to escalate against) grows the hash
// without bound, and every replica's periodic Resync copies the whole,
// ever-growing thing (H2). Reaping here, rather than in a separate sweep,
// costs nothing extra: readAll already walks every field on every List call
// and on every resync tick.
func (s *RedisStore) readAll(ctx context.Context) (map[string]TierEntry, error) {
	fields, err := s.client.HGetAll(ctx, s.opts.Key).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to read tier hash: %w", err)
	}

	now := s.opts.Clock.Now()
	entries := make(map[string]TierEntry, len(fields))
	var expired map[string]string
	for identity, raw := range fields {
		var entry TierEntry
		if err := json.Unmarshal([]byte(raw), &entry); err != nil {
			s.opts.Logger.Warn("skipping unreadable tier entry",
				zap.String("reason", err.Error()),
			)
			continue
		}
		if !entry.Active(now) {
			// Keep the exact bytes read: the reap deletes the field only while
			// it still holds them.
			if expired == nil {
				expired = make(map[string]string)
			}
			expired[identity] = raw
			continue
		}
		entries[identity] = entry
	}

	s.reapExpired(ctx, expired)

	return entries, nil
}

// reapExpiredScript deletes hash fields, but only while each still holds the
// exact value the caller read. It is the Redis equivalent of
// sync.Map.CompareAndDelete, and it exists for the same reason the memory
// backend needed that call (B6).
var reapExpiredScript = redis.NewScript(`
local deleted = 0
for i = 1, #ARGV, 2 do
  if redis.call('HGET', KEYS[1], ARGV[i]) == ARGV[i+1] then
    redis.call('HDEL', KEYS[1], ARGV[i])
    deleted = deleted + 1
  end
end
return deleted
`)

// reapBatchSize bounds how many fields one reap script touches. Redis runs
// scripts on its single thread, so a sweep after a long outage — when tens of
// thousands of entries can expire together — is split rather than parked on
// the server in one call.
const reapBatchSize = 512

// reapExpired removes expired fields from the tier hash.
//
// stale maps each identity to the exact value readAll saw. A field is deleted
// only while it still holds that value: between the HGETALL that found it
// expired and this delete, another replica may have re-escalated the same
// identity, and dropping that fresh entry would hand an active abuser its
// full quota back. Failures are not fatal — the entries are already excluded
// from what readAll returns, and the next sweep tries again.
func (s *RedisStore) reapExpired(ctx context.Context, stale map[string]string) {
	if len(stale) == 0 {
		return
	}

	argv := make([]any, 0, min(len(stale), reapBatchSize)*2)
	flush := func() {
		if len(argv) == 0 {
			return
		}
		err := reapExpiredScript.Run(ctx, s.client, []string{s.opts.Key}, argv...).Err()
		if err != nil && !errors.Is(err, redis.Nil) {
			s.opts.Logger.Warn("failed to reap expired tier entries", zap.Error(err))
		}
		argv = argv[:0]
	}

	for identity, raw := range stale {
		argv = append(argv, identity, raw)
		if len(argv) >= reapBatchSize*2 {
			flush()
		}
	}
	flush()
}

// listen applies pub/sub events to the mirror.
func (s *RedisStore) listen(ctx context.Context) {
	defer s.wg.Done()

	channel := s.pubsub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-channel:
			if !ok {
				return
			}
			var event tierEvent
			if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
				s.opts.Logger.Warn("ignoring malformed tier event", zap.Error(err))
				continue
			}
			if event.Identity == "" {
				continue
			}
			switch event.Op {
			case "set":
				_ = s.mirror.Set(ctx, event.Identity, event.Entry)
			case "del":
				_ = s.mirror.Delete(ctx, event.Identity)
			default:
				s.opts.Logger.Warn("ignoring unknown tier event", zap.String("op", event.Op))
			}
		}
	}
}

// resyncLoop refreshes the mirror periodically.
func (s *RedisStore) resyncLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(s.opts.ResyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Resync(ctx); err != nil && !errors.Is(err, context.Canceled) {
				s.opts.Logger.Warn("tier store resync failed", zap.Error(err))
			}
		}
	}
}

// Close stops the background loops and releases the subscription.
func (s *RedisStore) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	err := s.pubsub.Close()
	s.wg.Wait()
	return err
}
