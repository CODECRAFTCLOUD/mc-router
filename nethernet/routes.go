package nethernet

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// Backend is one published Bedrock-side server: where its NetherNet signaling
// port is (the mc-<id> Service's ClusterIP and `nethernet` port), the IPv4
// addresses of its ready pods (the only valid relay targets; empty while it is
// asleep or not ready) and what the router needs to wake it. PodIPs is shared
// and read-only: discovery replaces it, never mutates it.
type Backend struct {
	ServerID   string
	Addr       netip.AddrPort
	PodIPs     []netip.Addr
	LegacyPort int
	AsleepMOTD string
}

type routeEntry struct {
	hosts   []string
	backend Backend
}

// RouteTable maps hostnames and legacy pool ports to backends. Entries are
// keyed by the Service ("namespace/name") that published them, so an update
// replaces all of that Service's hosts at once. When two Services claim one
// host or port (a leaked Service), the highest svcKey wins on every replica,
// whatever the event order: Services are mc-<ObjectId> and an ObjectId starts
// with its creation time, so the newest server beats a leaked older one. The
// next claimant takes over when the winner goes.
type RouteTable struct {
	mu      sync.RWMutex
	entries map[string]routeEntry
	hosts   map[string][]string // normalized host -> sorted claimant svcKeys
	legacy  map[int][]string    // legacy port -> sorted claimant svcKeys
}

func NewRouteTable() *RouteTable {
	return &RouteTable{entries: map[string]routeEntry{}, hosts: map[string][]string{}, legacy: map[int][]string{}}
}

// normalizeHost lowercases, strips a ":port" and a trailing ".".
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// Upsert changes only the claims that differ from svcKey's last Upsert, so a
// slice event re-running it never logs a conflict again.
func (t *RouteTable) Upsert(svcKey string, hosts []string, b Backend) {
	t.mu.Lock()
	defer t.mu.Unlock()
	old := t.entries[svcKey]
	e := routeEntry{backend: b}
	for _, h := range hosts {
		if h = normalizeHost(h); h != "" {
			e.hosts = append(e.hosts, h)
		}
	}
	for _, h := range old.hosts {
		if !slices.Contains(e.hosts, h) {
			dropClaim(t.hosts, "host", h, svcKey)
		}
	}
	if p := old.backend.LegacyPort; p > 0 && p != b.LegacyPort {
		dropClaim(t.legacy, "legacyPort", p, svcKey)
	}
	for _, h := range e.hosts {
		addClaim(t.hosts, "host", h, svcKey)
	}
	if b.LegacyPort > 0 {
		addClaim(t.legacy, "legacyPort", b.LegacyPort, svcKey)
	}
	t.entries[svcKey] = e
}

func (t *RouteTable) Remove(svcKey string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[svcKey]
	if !ok {
		return
	}
	for _, h := range e.hosts {
		dropClaim(t.hosts, "host", h, svcKey)
	}
	if p := e.backend.LegacyPort; p > 0 {
		dropClaim(t.legacy, "legacyPort", p, svcKey)
	}
	delete(t.entries, svcKey)
}

func addClaim[K comparable](m map[K][]string, kind string, k K, svcKey string) {
	i, found := slices.BinarySearch(m[k], svcKey)
	if found {
		return
	}
	m[k] = slices.Insert(m[k], i, svcKey)
	if len(m[k]) > 1 {
		warnClaim(kind, k, m[k], svcKey, m[k][len(m[k])-1], "nethernet: Services claim the same route; the newest (highest name) wins")
	}
}

func dropClaim[K comparable](m map[K][]string, kind string, k K, svcKey string) {
	i, found := slices.BinarySearch(m[k], svcKey)
	if !found {
		return
	}
	if len(m[k]) > 1 {
		rest := slices.Delete(slices.Clone(m[k]), i, i+1)
		warnClaim(kind, k, m[k], svcKey, rest[len(rest)-1], "nethernet: a Service gave up a contested route; the highest remaining name wins")
	}
	if c := slices.Delete(m[k], i, i+1); len(c) > 0 {
		m[k] = c
	} else {
		delete(m, k)
	}
}

// warnClaim makes a leaked Service visible: it names every claimant involved
// (sorted), the Service that joined or left, and the one that serves now.
func warnClaim[K comparable](kind string, k K, claimants []string, service, winner, msg string) {
	logrus.WithFields(logrus.Fields{
		"route": fmt.Sprintf("%s %v", kind, k), "claimants": slices.Clone(claimants),
		"service": service, "winner": winner,
	}).Warn(msg)
}

func (t *RouteTable) ByHost(host string) (Backend, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lookupLocked(t.hosts[normalizeHost(host)])
}

func (t *RouteTable) ByLegacyPort(port int) (Backend, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.lookupLocked(t.legacy[port])
}

func (t *RouteTable) lookupLocked(claims []string) (Backend, bool) {
	if len(claims) == 0 {
		return Backend{}, false
	}
	e, ok := t.entries[claims[len(claims)-1]]
	return e.backend, ok
}
