package nethernet

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// connRateLimiter bounds how fast NEW signaling connections are taken on, both
// globally and per source IP. Copied from server/conn_rate_limiter.go; the
// per-IP tier applies to the player's own address only (Ruling R36), which the
// caller passes, so the private-address exemption is gone.
//
// It is deliberately applied AFTER Accept() instead of around it. Gating the
// accept loop lets a flood fill the kernel's accept queue, and every legitimate
// join then waits behind the flood's connections: with the upstream default of
// one accept per second, a ~145k pkt/s flood on 2026-08-22 left uniz.host
// players unable to join for a further 13 minutes after the flood had stopped,
// and only a pod restart (a fresh listener with an empty queue) cleared it.
// Accepting immediately and dropping over-limit connections keeps the queue
// short, so a flood costs one accept+close per connection instead of blocking
// everyone behind it.
type connRateLimiter struct {
	global *rate.Limiter

	perIPRate  rate.Limit
	perIPBurst int

	mu        sync.Mutex
	perIP     map[netip.Addr]*ipLimiter
	lastSweep time.Time
	// The global tier's rejection line: at most one per globalLogEvery, which
	// carries how many it held back (review M-1).
	globalLastLog    time.Time
	globalSuppressed int
}

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
	lastLog  time.Time
}

const (
	// maxTrackedIPs bounds the per-IP table so a botnet flood cannot grow it
	// without limit inside the router's memory budget. Past the cap only the
	// global limiter applies.
	maxTrackedIPs = 50_000
	ipSweepEvery  = time.Minute
	ipIdleTTL     = 5 * time.Minute
	// logEvery samples the "throttled" log line per source IP so a flood
	// cannot turn the log itself into the bottleneck.
	logEvery       = 10 * time.Second
	globalLogEvery = time.Second
)

// newConnRateLimiter builds a limiter from per-second rates. A rate <= 0
// disables that tier.
func newConnRateLimiter(globalPerSec, perIPPerSec int) *connRateLimiter {
	l := &connRateLimiter{perIP: make(map[netip.Addr]*ipLimiter)}

	if globalPerSec > 0 {
		l.global = rate.NewLimiter(rate.Limit(globalPerSec), globalPerSec*2)
	}
	if perIPPerSec > 0 {
		l.perIPRate = rate.Limit(perIPPerSec)
		l.perIPBurst = perIPPerSec * 4
	}

	return l
}

// allow reports whether a connection from addr may proceed. An invalid addr
// (a legacy-port join, or a trusted proxy without a PROXY header: the source is
// the relay, shared by every player behind it) skips the per-IP tier; an IPv6
// address counts per /64. scope names the tier that rejected it, and logIt is
// true at most once per logEvery per source, and once per globalLogEvery for
// the global tier, so the caller can log a rejection without amplifying a
// flood; suppressed counts the global rejections not logged since the last line.
func (l *connRateLimiter) allow(addr netip.Addr, now time.Time) (ok bool, scope string, logIt bool, suppressed int) {
	if l.perIPRate > 0 && addr.IsValid() {
		if allowed, shouldLog := l.allowIP(ipKey(addr), now); !allowed {
			return false, "per_ip", shouldLog, 0
		}
	}

	if l.global != nil && !l.global.AllowN(now, 1) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if now.Sub(l.globalLastLog) < globalLogEvery {
			l.globalSuppressed++
			return false, "global", false, 0
		}
		suppressed, l.globalSuppressed, l.globalLastLog = l.globalSuppressed, 0, now
		return false, "global", true, suppressed
	}

	return true, "", false, 0
}

func (l *connRateLimiter) allowIP(addr netip.Addr, now time.Time) (allowed, shouldLog bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(now)

	entry, ok := l.perIP[addr]
	if !ok {
		if len(l.perIP) >= maxTrackedIPs {
			// Table is full: fall back to the global tier rather than evicting
			// a legitimate client's budget to track an attacker's.
			return true, false
		}
		entry = &ipLimiter{limiter: rate.NewLimiter(l.perIPRate, l.perIPBurst)}
		l.perIP[addr] = entry
	}
	entry.lastSeen = now

	if entry.limiter.AllowN(now, 1) {
		return true, false
	}

	if now.Sub(entry.lastLog) >= logEvery {
		entry.lastLog = now
		return false, true
	}

	return false, false
}

func (l *connRateLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < ipSweepEvery {
		return
	}
	l.lastSweep = now

	for addr, entry := range l.perIP {
		if now.Sub(entry.lastSeen) > ipIdleTTL {
			delete(l.perIP, addr)
		}
	}
}
