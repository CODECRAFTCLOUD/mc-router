package nethernet

import (
	"net"
	"net/netip"
	"strings"
	"sync"
)

// Backend is one published Bedrock-side server: where its NetherNet signaling
// port is (the mc-<id> Service's ClusterIP and `nethernet` port) and what the
// router needs to wake it.
type Backend struct {
	ServerID   string
	Addr       netip.AddrPort
	LegacyPort int
	AsleepMOTD string
}

type routeEntry struct {
	hosts   []string
	backend Backend
}

// RouteTable maps hostnames and legacy pool ports to backends. Entries are
// keyed by the Service ("namespace/name") that published them, so an update
// replaces all of that Service's hosts at once.
type RouteTable struct {
	mu      sync.RWMutex
	entries map[string]routeEntry
	hosts   map[string]string // normalized host -> svcKey
	legacy  map[int]string    // legacy port -> svcKey
}

func NewRouteTable() *RouteTable {
	return &RouteTable{entries: map[string]routeEntry{}, hosts: map[string]string{}, legacy: map[int]string{}}
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
			t.hosts[h] = svcKey
		}
	}
	if b.LegacyPort > 0 {
		t.legacy[b.LegacyPort] = svcKey
	}
	t.entries[svcKey] = e
}

func (t *RouteTable) Remove(svcKey string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.removeLocked(svcKey)
}

// removeLocked drops svcKey's entry and only those host/port claims it still
// owns: a Service that took a host over later keeps it.
func (t *RouteTable) removeLocked(svcKey string) {
	e, ok := t.entries[svcKey]
	if !ok {
		return
	}
	for _, h := range e.hosts {
		if t.hosts[h] == svcKey {
			delete(t.hosts, h)
		}
	}
	if p := e.backend.LegacyPort; p > 0 && t.legacy[p] == svcKey {
		delete(t.legacy, p)
	}
	delete(t.entries, svcKey)
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

func (t *RouteTable) lookupLocked(svcKey string) (Backend, bool) {
	if svcKey == "" {
		return Backend{}, false
	}
	e, ok := t.entries[svcKey]
	return e.backend, ok
}
