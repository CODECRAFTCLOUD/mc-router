package server

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnRateLimiterPerIPDoesNotStarveOtherClients(t *testing.T) {
	l := newConnRateLimiter(1000, 5)
	now := time.Now()

	flood := netip.MustParseAddr("203.0.113.7")
	victim := netip.MustParseAddr("198.51.100.9")

	// Burst is 4x the rate, so the 21st connection in the same instant is over.
	for i := 0; i < 20; i++ {
		ok, _, _ := l.allow(flood, now)
		require.Truef(t, ok, "connection %d from the flooding IP should be within its burst", i)
	}

	ok, scope, logIt := l.allow(flood, now)
	assert.False(t, ok)
	assert.Equal(t, "per_ip", scope)
	assert.True(t, logIt, "the first rejection for a source should be logged")

	_, _, logIt = l.allow(flood, now)
	assert.False(t, logIt, "further rejections within the sample window stay quiet")

	// The whole point: the flood spends its own budget, not everyone's.
	ok, _, _ = l.allow(victim, now)
	assert.True(t, ok)
}

func TestConnRateLimiterExemptsPrivateSources(t *testing.T) {
	l := newConnRateLimiter(0, 1)
	now := time.Now()

	// The status prober opens one connection per hosted server in a burst.
	prober := netip.MustParseAddr("10.244.155.135")
	for i := 0; i < 50; i++ {
		ok, _, _ := l.allow(prober, now)
		require.Truef(t, ok, "in-cluster connection %d must not be throttled", i)
	}
}

func TestConnRateLimiterGlobalTier(t *testing.T) {
	l := newConnRateLimiter(10, 0)
	now := time.Now()

	client := netip.MustParseAddr("203.0.113.7")
	for i := 0; i < 20; i++ {
		ok, _, _ := l.allow(client, now)
		require.Truef(t, ok, "connection %d should be within the global burst", i)
	}

	ok, scope, _ := l.allow(client, now)
	assert.False(t, ok)
	assert.Equal(t, "global", scope)

	// Tokens refill with time rather than staying wedged.
	ok, _, _ = l.allow(client, now.Add(time.Second))
	assert.True(t, ok)
}

func TestConnRateLimiterEvictsIdleSources(t *testing.T) {
	l := newConnRateLimiter(0, 5)
	now := time.Now()

	ok, _, _ := l.allow(netip.MustParseAddr("203.0.113.7"), now)
	require.True(t, ok)
	assert.Equal(t, 1, l.tracked())

	ok, _, _ = l.allow(netip.MustParseAddr("203.0.113.8"), now.Add(ipIdleTTL+ipSweepEvery))
	require.True(t, ok)
	assert.Equal(t, 1, l.tracked(), "the idle source should have been swept")
}
