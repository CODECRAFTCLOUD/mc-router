package nethernet

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Session is what the relay needs to forward one join: where BDS listens and
// the ICE password that signs the client's connectivity checks. Stored as the
// spec 6.5 JSON {serverId, target, icePwd}, plus signalIp.
type Session struct {
	ServerID string         `json:"serverId"`
	Target   netip.AddrPort `json:"target"`
	IcePwd   string         `json:"icePwd"`
	SignalIP netip.Addr     `json:"signalIp"` // the player IP that POSTed the offer
	// SignalIPTrusted is true when SignalIP is the player's own address (PROXY v2
	// on the main listener). On the legacy listener every player arrives from the
	// relay's address, so it is false there and no per-IP cap applies.
	SignalIPTrusted bool `json:"signalIpTrusted"`
}

// Registry maps an ICE ufrag pair ("serverUfrag:clientUfrag") to its Session
// and a client UDP address to its pair.
type Registry interface {
	PutSession(ctx context.Context, pair string, s Session, ttl time.Duration) error
	GetSession(ctx context.Context, pair string) (Session, bool, error)
	BindClient(ctx context.Context, client netip.AddrPort, pair string, ttl time.Duration) error
	LookupClient(ctx context.Context, client netip.AddrPort) (string, bool, error)
	DeleteClient(ctx context.Context, client netip.AddrPort) error
}

type memEntry[T any] struct {
	v       T
	expires time.Time
}

type memoryRegistry struct {
	now      func() time.Time
	mu       sync.Mutex
	sessions map[string]memEntry[Session]
	clients  map[netip.AddrPort]memEntry[string]
}

func NewMemoryRegistry() Registry { return newMemoryRegistry(time.Now) }

func newMemoryRegistry(now func() time.Time) *memoryRegistry {
	return &memoryRegistry{now: now, sessions: map[string]memEntry[Session]{}, clients: map[netip.AddrPort]memEntry[string]{}}
}

// sweep drops expired entries so pairs that never bind do not pile up. Callers hold mu.
func (m *memoryRegistry) sweep(now time.Time) {
	for k, e := range m.sessions {
		if !now.Before(e.expires) {
			delete(m.sessions, k)
		}
	}
	for k, e := range m.clients {
		if !now.Before(e.expires) {
			delete(m.clients, k)
		}
	}
}

func (m *memoryRegistry) PutSession(_ context.Context, pair string, s Session, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.sweep(now)
	m.sessions[pair] = memEntry[Session]{s, now.Add(ttl)}
	return nil
}

func (m *memoryRegistry) GetSession(_ context.Context, pair string) (Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sessions[pair]
	if !ok || !m.now().Before(e.expires) {
		return Session{}, false, nil
	}
	return e.v, true, nil
}

func (m *memoryRegistry) BindClient(_ context.Context, client netip.AddrPort, pair string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.sweep(now)
	m.clients[client] = memEntry[string]{pair, now.Add(ttl)}
	return nil
}

func (m *memoryRegistry) LookupClient(_ context.Context, client netip.AddrPort) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.clients[client]
	if !ok || !m.now().Before(e.expires) {
		return "", false, nil
	}
	return e.v, true, nil
}

func (m *memoryRegistry) DeleteClient(_ context.Context, client netip.AddrPort) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, client)
	return nil
}

type redisRegistry struct{ c *redis.Client }

// NewRedisRegistry shares sessions across router replicas: keys nn:sess:<pair>
// (JSON Session) and nn:client:<ip:port> (pair), both with a TTL. The client
// must set ContextTimeoutEnabled: without it go-redis ignores context deadlines
// and a hung server holds every call for ReadTimeout (5 s by default).
func NewRedisRegistry(c *redis.Client) (Registry, error) {
	if !c.Options().ContextTimeoutEnabled {
		return nil, errors.New("nethernet: the redis client must set ContextTimeoutEnabled")
	}
	return &redisRegistry{c}, nil
}

func (r *redisRegistry) PutSession(ctx context.Context, pair string, s Session, ttl time.Duration) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return r.c.Set(ctx, "nn:sess:"+pair, b, ttl).Err()
}

func (r *redisRegistry) GetSession(ctx context.Context, pair string) (Session, bool, error) {
	b, err := r.c.Get(ctx, "nn:sess:"+pair).Bytes()
	if errors.Is(err, redis.Nil) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return Session{}, false, err
	}
	return s, true, nil
}

func (r *redisRegistry) BindClient(ctx context.Context, client netip.AddrPort, pair string, ttl time.Duration) error {
	return r.c.Set(ctx, "nn:client:"+client.String(), pair, ttl).Err()
}

func (r *redisRegistry) LookupClient(ctx context.Context, client netip.AddrPort) (string, bool, error) {
	pair, err := r.c.Get(ctx, "nn:client:"+client.String()).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return pair, true, nil
}

func (r *redisRegistry) DeleteClient(ctx context.Context, client netip.AddrPort) error {
	return r.c.Del(ctx, "nn:client:"+client.String()).Err()
}
