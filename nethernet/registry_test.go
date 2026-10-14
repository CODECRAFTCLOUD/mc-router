package nethernet

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type registryCase struct {
	name    string
	reg     Registry
	advance func(time.Duration)
}

func registryCases(t *testing.T) []registryCase {
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mr := miniredis.RunT(t)
	return []registryCase{
		{"memory", newMemoryRegistry(clock.now), clock.advance},
		{"redis", newTestRedisRegistry(t, mr.Addr()), mr.FastForward},
	}
}

// newTestRedisRegistry builds the registry the way B4 must: with context timeouts on.
func newTestRedisRegistry(t *testing.T, addr string) Registry {
	rc := redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = rc.Close() })
	reg, err := NewRedisRegistry(rc)
	require.NoError(t, err)
	return reg
}

var testSession = Session{ServerID: "srv-1", Target: netip.MustParseAddrPort("10.0.0.3:19140"), IcePwd: testPwd,
	SignalIP: netip.MustParseAddr("198.51.100.7"), SignalIPTrusted: true}

func TestRegistryRoundTrip(t *testing.T) {
	for _, tc := range registryCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			require.NoError(t, tc.reg.PutSession(ctx, "2c69:QXyz", testSession, time.Minute))
			got, ok, err := tc.reg.GetSession(ctx, "2c69:QXyz")
			require.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, testSession, got)

			_, ok, err = tc.reg.GetSession(ctx, "2c69:other")
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestRegistryExpires(t *testing.T) {
	for _, tc := range registryCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			client := netip.MustParseAddrPort("203.0.113.7:50000")
			require.NoError(t, tc.reg.PutSession(ctx, "2c69:QXyz", testSession, 10*time.Second))
			require.NoError(t, tc.reg.BindClient(ctx, client, "2c69:QXyz", 10*time.Second))
			tc.advance(11 * time.Second)

			_, ok, err := tc.reg.GetSession(ctx, "2c69:QXyz")
			require.NoError(t, err)
			assert.False(t, ok)
			_, ok, err = tc.reg.LookupClient(ctx, client)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestRegistryBindAndLookupClient(t *testing.T) {
	for _, tc := range registryCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			client := netip.MustParseAddrPort("203.0.113.7:50000")
			require.NoError(t, tc.reg.BindClient(ctx, client, "2c69:QXyz", time.Minute))
			pair, ok, err := tc.reg.LookupClient(ctx, client)
			require.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, "2c69:QXyz", pair)

			_, ok, err = tc.reg.LookupClient(ctx, netip.MustParseAddrPort("203.0.113.7:50001"))
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestRegistryDeleteClient(t *testing.T) {
	for _, tc := range registryCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			client := netip.MustParseAddrPort("203.0.113.7:50000")
			require.NoError(t, tc.reg.BindClient(ctx, client, "2c69:QXyz", time.Minute))
			require.NoError(t, tc.reg.DeleteClient(ctx, client))
			_, ok, err := tc.reg.LookupClient(ctx, client)
			require.NoError(t, err)
			assert.False(t, ok)
			require.NoError(t, tc.reg.DeleteClient(ctx, client), "deleting a missing key is not an error")
		})
	}
}

func TestNewRedisRegistryRefusesAClientWithoutContextTimeouts(t *testing.T) {
	rc := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer rc.Close()
	_, err := NewRedisRegistry(rc)
	assert.Error(t, err)
}

func TestRedisRegistryKeys(t *testing.T) {
	mr := miniredis.RunT(t)
	reg := newTestRedisRegistry(t, mr.Addr())
	require.NoError(t, reg.PutSession(t.Context(), "2c69:QXyz", testSession, time.Minute))
	require.NoError(t, reg.BindClient(t.Context(), netip.MustParseAddrPort("203.0.113.7:50000"), "2c69:QXyz", time.Minute))
	assert.True(t, mr.Exists("nn:sess:2c69:QXyz"))
	assert.Equal(t, time.Minute, mr.TTL("nn:sess:2c69:QXyz"))
	sess, err := mr.Get("nn:sess:2c69:QXyz")
	require.NoError(t, err)
	assert.JSONEq(t, `{"serverId":"srv-1","target":"10.0.0.3:19140","icePwd":"`+testPwd+`","signalIp":"198.51.100.7","signalIpTrusted":true}`, sess)
	got, err := mr.Get("nn:client:203.0.113.7:50000")
	require.NoError(t, err)
	assert.Equal(t, "2c69:QXyz", got)
}
