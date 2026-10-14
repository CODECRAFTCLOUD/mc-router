package nethernet

import (
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
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
// host or port (a leaked Service), the lowest svcKey wins on every replica,
// whatever the event order, and the next claimant takes over when it goes.
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

func (t *RouteTable) Upsert(svcKey string, hosts []string, b Backend) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeLocked(svcKey)
	e := routeEntry{backend: b}
	for _, h := range hosts {
		if h = normalizeHost(h); h != "" {
			e.hosts = append(e.hosts, h)
			addClaim(t.hosts, h, svcKey)
		}
	}
	if b.LegacyPort > 0 {
		addClaim(t.legacy, b.LegacyPort, svcKey)
	}
	t.entries[svcKey] = e
}

func (t *RouteTable) Remove(svcKey string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeLocked(svcKey)
}

func (t *RouteTable) removeLocked(svcKey string) {
	e, ok := t.entries[svcKey]
	if !ok {
		return
	}
	for _, h := range e.hosts {
		dropClaim(t.hosts, h, svcKey)
	}
	if p := e.backend.LegacyPort; p > 0 {
		dropClaim(t.legacy, p, svcKey)
	}
	delete(t.entries, svcKey)
}

func addClaim[K comparable](m map[K][]string, k K, svcKey string) {
	if i, found := slices.BinarySearch(m[k], svcKey); !found {
		m[k] = slices.Insert(m[k], i, svcKey)
	}
}

func dropClaim[K comparable](m map[K][]string, k K, svcKey string) {
	i, found := slices.BinarySearch(m[k], svcKey)
	if !found {
		return
	}
	if c := slices.Delete(m[k], i, i+1); len(c) > 0 {
		m[k] = c
	} else {
		delete(m, k)
	}
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
	e, ok := t.entries[claims[0]]
	return e.backend, ok
}
