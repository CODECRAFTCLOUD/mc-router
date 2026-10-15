package nethernet

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Review M-1: a flood past the global tier writes at most one log line per
// second, and that line counts the rejections it stands for.
func TestConnRateLimiterSamplesTheGlobalTierLog(t *testing.T) {
	l := newConnRateLimiter(1, 0) // burst 2
	at := time.Now()
	for range 2 {
		ok, _, _, _ := l.allow(netip.Addr{}, at)
		assert.True(t, ok)
	}
	ok, scope, logIt, suppressed := l.allow(netip.Addr{}, at)
	assert.False(t, ok)
	assert.Equal(t, "global", scope)
	assert.True(t, logIt, "the first rejection is logged")
	assert.Zero(t, suppressed)
	for range 5 {
		_, _, logIt, _ = l.allow(netip.Addr{}, at.Add(500*time.Millisecond))
		assert.False(t, logIt, "within the second: not logged")
	}

	at = at.Add(1500 * time.Millisecond) // one token back
	ok, _, _, _ = l.allow(netip.Addr{}, at)
	assert.True(t, ok)
	ok, _, logIt, suppressed = l.allow(netip.Addr{}, at)
	assert.False(t, ok)
	assert.True(t, logIt, "the next second logs again")
	assert.Equal(t, 5, suppressed, "with the lines it held back")
}
