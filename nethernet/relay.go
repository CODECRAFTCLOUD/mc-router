package nethernet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// registryTimeout bounds every shared-registry call.
	registryTimeout = 250 * time.Millisecond
	// Shared-registry work runs on a few workers behind a bounded queue, never on
	// the read loop: a full queue drops the job; lookups retry on the client's
	// retransmit, publishes on the next datagram after sharedRetry. Session
	// lookups (by STUN username) have workers and a queue of these sizes of their
	// own, apart from client lookups and publishes (review I-2).
	sharedWorkers = 4
	sharedQueue   = 256
	sharedRetry   = time.Second
	// A key is looked up at most once per 1-2 s (de-dup while in flight plus a
	// negative cache), and at most maxLookupKeys distinct keys per window, for
	// each kind of lookup.
	lookupWindow  = time.Second
	maxLookupKeys = 4096
	// A STUN USERNAME of maxUsername bytes or more is dropped: RFC 5389 section
	// 15.3 allows fewer than 513 bytes.
	maxUsername = 513
)

// ErrSessionCap is Register's answer when the replica or the server holds its
// maximum of sessions; the signal server answers 503.
var ErrSessionCap = errors.New("nethernet relay: session cap reached")

// ErrInvalidSignalIP is Register's answer to a session marked SignalIPTrusted
// without a valid SignalIP: a forgotten field must fail loudly, not share one
// per-IP bucket with every other such session.
var ErrInvalidSignalIP = errors.New("nethernet relay: a trusted Session.SignalIP must be a valid address")

// RelayOptions bound every session: UnboundTTL for a signaled session that never
// binds, IdleTimeout without client traffic, HardReap for any session (0 = off).
// MaxSessions (per replica), MaxSessionsPerServer and MaxPerIPPerServer count
// signaled and bound sessions alike; MaxPerIPPerServer counts only sessions
// with a trusted SignalIP, per (IPv4 address or IPv6 /64, server).
type RelayOptions struct {
	UnboundTTL, IdleTimeout, HardReap                    time.Duration
	MaxSessions, MaxSessionsPerServer, MaxPerIPPerServer int
	Metrics                                              *Metrics
}

// ipServer is the per-IP cap's key.
type ipServer struct {
	ip     netip.Addr // IPv4, or IPv6 masked to /64
	server string
}

// relaySession is a signaled session until a client binds it; then it has one
// upstream socket to BDS and the client address it currently answers to.
type relaySession struct {
	pair        string
	s           Session        // s.CreatedAt (wall, UTC) carries the age to other replicas
	created     time.Time      // monotonic anchor of s.CreatedAt on this replica
	upstream    *net.UDPConn   // nil while signaled; set once under Relay.mu
	ipKey       ipServer       // guarded by Relay.mu, with countsForIP
	countsForIP bool           // counted in Relay.perIP
	client      netip.AddrPort // guarded by Relay.mu
	lastSeen    atomic.Int64   // Relay.since() of the last client datagram
	lastShared  atomic.Int64   // Relay.since() of the last shared-registry refresh; 0 = never

	publishing, republish bool           // guarded by Relay.mu
	published             netip.AddrPort // the address in nn:client; owned by the one publish in flight
}

// Relay forwards one public UDP port to many BDS pods. A client address binds
// to a session only through a STUN check signed with that session's ICE
// password, or through a binding another replica already verified.
type Relay struct {
	conn          *net.UDPConn
	local, shared Registry
	opt           RelayOptions
	// epoch anchors lastSeen and lastShared: offsets on the monotonic clock, so
	// a wall-clock step never idle-reaps or keeps a session.
	epoch time.Time

	mu        sync.Mutex
	byClient  map[netip.AddrPort]*relaySession
	byPair    map[string]*relaySession // signaled and bound
	perServer map[string]int
	// Sessions with a trusted signaling IP, per (IP key, server); counted only
	// on the replica that handled the POST, for as long as the session lives here.
	perIP map[ipServer]int

	jobs         chan func(context.Context)                 // client lookups and publishes
	dialUpstream func(netip.AddrPort) (*net.UDPConn, error) // tests make it fail

	// A flood of client lookups (any DTLS-shaped junk from many source ports)
	// must not delay a join's first check, which needs a session lookup.
	clientLookups, sessionLookups lookupBudget
}

// lookupBudget bounds one kind of shared-registry lookup. Read loop only.
type lookupBudget struct {
	kind string // the metric label: "s" (session by STUN username) or "c" (client by address)
	jobs chan func(context.Context)
	// Keys looked up in this window and the previous one.
	looked, lookedPrev map[string]struct{}
	lookedUntil        time.Time
}

// NewRelay builds a relay on conn. shared may be nil (single replica). A zero
// timeout or cap is refused: it would make every join fail or never reap.
func NewRelay(conn *net.UDPConn, local Registry, shared Registry, opt RelayOptions) (*Relay, error) {
	if opt.UnboundTTL <= 0 || opt.IdleTimeout <= 0 || opt.HardReap < 0 || opt.MaxSessions <= 0 || opt.MaxSessionsPerServer <= 0 || opt.MaxPerIPPerServer <= 0 {
		return nil, errors.New("nethernet relay: UnboundTTL, IdleTimeout, MaxSessions, MaxSessionsPerServer and MaxPerIPPerServer must be > 0, HardReap >= 0")
	}
	r := &Relay{conn: conn, local: local, shared: shared, opt: opt, epoch: time.Now(),
		byClient: map[netip.AddrPort]*relaySession{}, byPair: map[string]*relaySession{}, perServer: map[string]int{},
		perIP: map[ipServer]int{},
		jobs:  make(chan func(context.Context), sharedQueue)}
	r.dialUpstream = func(to netip.AddrPort) (*net.UDPConn, error) {
		return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(to))
	}
	r.clientLookups = lookupBudget{kind: "c", jobs: r.jobs}
	r.sessionLookups = lookupBudget{kind: "s", jobs: make(chan func(context.Context), sharedQueue)}
	return r, nil
}

// Register records a signaled session here, locally and in the shared registry.
// It returns ErrSessionCap when the replica or s.ServerID is at its cap, or, for
// a trusted s.SignalIP, when that IP already holds MaxPerIPPerServer sessions of
// s.ServerID here; ErrInvalidSignalIP when s.SignalIPTrusted has no valid
// SignalIP. A shared-registry error is logged and counted, never returned.
func (r *Relay) Register(ctx context.Context, pair string, s Session) error {
	if s.SignalIPTrusted && !s.SignalIP.IsValid() {
		return ErrInvalidSignalIP
	}
	var added *relaySession
	r.mu.Lock()
	if rs := r.byPair[pair]; rs != nil {
		s.CreatedAt = rs.s.CreatedAt
	} else {
		s.CreatedAt = time.Now().UTC()
		key := ipServer{ipKey(s.SignalIP), s.ServerID}
		if !r.roomLocked(s.ServerID) || s.SignalIPTrusted && r.perIP[key] >= r.opt.MaxPerIPPerServer {
			r.mu.Unlock()
			return ErrSessionCap
		}
		added = r.addLocked(pair, s)
		if s.SignalIPTrusted {
			added.ipKey, added.countsForIP = key, true
			r.perIP[key]++
		}
	}
	r.mu.Unlock()
	if err := r.local.PutSession(ctx, pair, s, r.opt.UnboundTTL); err != nil {
		r.mu.Lock()
		if added != nil && r.byPair[pair] == added { // release every slot counted above
			r.dropLocked(pair, added)
		}
		r.mu.Unlock()
		return err
	}
	if r.shared != nil {
		sctx, cancel := context.WithTimeout(ctx, registryTimeout)
		defer cancel()
		if err := r.shared.PutSession(sctx, pair, s, r.opt.UnboundTTL); err != nil {
			r.sharedError("put session", err, logrus.WarnLevel)
		}
	}
	return nil
}

// Serve reads the relay socket until ctx is done, then closes every upstream
// socket. Its workers and reaper end with it, whatever the reason it returns.
func (r *Relay) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = r.conn.SetReadDeadline(time.Now()) })
	defer stop()
	defer r.closeAll()
	go r.reapLoop(ctx)
	for range sharedWorkers {
		go r.work(ctx, r.jobs)
		go r.work(ctx, r.sessionLookups.jobs)
	}
	buf := make([]byte, 64*1024)
	for {
		n, from, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if isClosed(err) {
				return err
			}
			// e.g. WSAECONNRESET on Windows after an ICMP port-unreachable: not fatal.
			logrus.WithError(err).Debug("nethernet relay: read error")
			continue
		}
		r.handle(ctx, netip.AddrPortFrom(from.Addr().Unmap(), from.Port()), buf[:n])
	}
}

func (r *Relay) handle(ctx context.Context, from netip.AddrPort, pkt []byte) {
	r.mu.Lock()
	rs := r.byClient[from]
	r.mu.Unlock()
	if rs != nil { // DTLS records, alerts included, are never inspected
		if IsSTUN(pkt) {
			// Never move a bound address to another pair: a spoofed source with
			// credentials for the attacker's own pair would cut the victim's session.
			if pair, ok := STUNUsername(pkt); ok && pair != rs.pair {
				r.opt.Metrics.dropped("pair_mismatch")
				return
			}
		}
		r.forward(rs, pkt)
		return
	}
	if IsSTUN(pkt) {
		r.bindFromSTUN(ctx, from, pkt)
		return
	}
	r.bindFromKnownClient(ctx, from, pkt)
}

func (r *Relay) bindFromSTUN(ctx context.Context, from netip.AddrPort, pkt []byte) {
	pair, ok := STUNUsername(pkt)
	if !ok {
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	if len(pair) >= maxUsername { // never a lookup key: it would bloat the de-dup sets
		r.opt.Metrics.dropped("bad_username")
		return
	}
	s, ok := r.knownSession(ctx, pair)
	if !ok {
		r.queueLookup(&r.sessionLookups, pair, func(ctx context.Context) { r.fetchSession(ctx, pair) })
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	if !VerifyIntegrity(pkt, s.IcePwd) {
		r.opt.Metrics.dropped("bad_integrity")
		return
	}
	r.bindAndForward(from, pair, s, true, pkt)
}

// bindFromKnownClient covers a failover mid-session: the client was verified on
// another replica and its next datagram (not STUN) lands here. Only DTLS-shaped
// datagrams (first byte 20-63, RFC 7983) are worth a shared lookup.
func (r *Relay) bindFromKnownClient(ctx context.Context, from netip.AddrPort, pkt []byte) {
	if pair, ok, _ := r.local.LookupClient(ctx, from); ok {
		if s, ok := r.knownSession(ctx, pair); ok {
			// rebind=false: a session live on this replica moves only on a verified STUN check.
			r.bindAndForward(from, pair, s, false, pkt)
			return
		}
	}
	if len(pkt) > 0 && pkt[0] >= 20 && pkt[0] <= 63 {
		r.queueLookup(&r.clientLookups, from.String(), func(ctx context.Context) { r.fetchClient(ctx, from) })
	}
	r.opt.Metrics.dropped("unknown_peer")
}

// knownSession finds a pair without leaving the process: live here, then local.
func (r *Relay) knownSession(ctx context.Context, pair string) (Session, bool) {
	r.mu.Lock()
	rs := r.byPair[pair]
	r.mu.Unlock()
	if rs != nil {
		return rs.s, true
	}
	s, ok, err := r.local.GetSession(ctx, pair)
	return s, err == nil && ok
}

// queueLookup hands a shared-registry lookup to b's workers unless key was
// queued in this window or the last. A lookup dropped because b's budget or
// queue is full is counted by kind; the retransmit retries. Read loop only;
// never blocks.
func (r *Relay) queueLookup(b *lookupBudget, key string, job func(context.Context)) {
	if r.shared == nil {
		return
	}
	if now := time.Now(); now.After(b.lookedUntil) {
		b.lookedPrev, b.looked, b.lookedUntil = b.looked, map[string]struct{}{}, now.Add(lookupWindow)
	}
	if _, ok := b.looked[key]; ok {
		return
	}
	if _, ok := b.lookedPrev[key]; ok {
		return
	}
	if len(b.looked) >= maxLookupKeys {
		r.opt.Metrics.lookupDropped(b.kind)
		return
	}
	select {
	case b.jobs <- job:
		b.looked[key] = struct{}{}
	default:
		r.opt.Metrics.lookupDropped(b.kind)
	}
}

func (r *Relay) work(ctx context.Context, jobs <-chan func(context.Context)) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-jobs:
			job(ctx)
		}
	}
}

// fetchSession copies a pair signaled on another replica into the local
// registry, where the client's next check finds it. Worker only.
func (r *Relay) fetchSession(ctx context.Context, pair string) (Session, bool) {
	sctx, cancel := context.WithTimeout(ctx, registryTimeout)
	defer cancel()
	s, ok, err := r.shared.GetSession(sctx, pair)
	if err != nil {
		r.sharedError("get session", err, logrus.DebugLevel)
		return Session{}, false
	}
	if ok {
		_ = r.local.PutSession(ctx, pair, s, r.opt.UnboundTTL)
	}
	return s, ok
}

// fetchClient copies a client binding made on another replica, and its
// session, into the local registry. Worker only.
func (r *Relay) fetchClient(ctx context.Context, client netip.AddrPort) {
	sctx, cancel := context.WithTimeout(ctx, registryTimeout)
	pair, ok, err := r.shared.LookupClient(sctx, client)
	cancel()
	if err != nil {
		r.sharedError("lookup client", err, logrus.DebugLevel)
	}
	if !ok {
		return
	}
	if _, ok := r.knownSession(ctx, pair); !ok {
		if _, ok := r.fetchSession(ctx, pair); !ok {
			return
		}
	}
	_ = r.local.BindClient(ctx, client, pair, r.opt.UnboundTTL)
}

func (r *Relay) bindAndForward(from netip.AddrPort, pair string, s Session, rebind bool, pkt []byte) {
	rs, reason := r.bind(from, pair, s, rebind)
	if rs == nil {
		r.opt.Metrics.dropped(reason)
		return
	}
	r.queuePublish(rs)
	r.forward(rs, pkt)
}

func (r *Relay) bind(client netip.AddrPort, pair string, s Session, rebind bool) (*relaySession, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rs := r.byPair[pair]
	if rs != nil && rs.upstream != nil {
		if !rebind {
			return nil, "unknown_peer"
		}
		delete(r.byClient, rs.client)
		rs.client = client
		r.byClient[client] = rs
		return rs, ""
	}
	adopted := rs == nil
	if adopted { // signaled on another replica: it counts here once it binds
		if r.opt.HardReap > 0 && time.Since(s.CreatedAt) > r.opt.HardReap {
			return nil, "hard_reaped" // never adopted again with a fresh age
		}
		if !r.roomLocked(s.ServerID) {
			return nil, "session_cap"
		}
		rs = r.addLocked(pair, s)
	}
	up, err := r.dialUpstream(s.Target)
	if err != nil {
		logrus.WithError(err).WithField("serverId", s.ServerID).Warn("nethernet relay: cannot dial BDS")
		if adopted { // its slots go back now, not at the next reap tick (review M-3)
			r.dropLocked(pair, rs)
		}
		return nil, "dial_failed"
	}
	rs.upstream = up
	rs.lastSeen.Store(r.since())
	rs.client = client
	r.byClient[client] = rs
	r.opt.Metrics.session(s.ServerID, "signaled", -1)
	r.opt.Metrics.session(s.ServerID, "bound", 1)
	go r.pipeUpstream(rs)
	return rs, ""
}

// roomLocked reports whether one more session fits the replica and server caps. Callers hold mu.
func (r *Relay) roomLocked(server string) bool {
	return len(r.byPair) < r.opt.MaxSessions && r.perServer[server] < r.opt.MaxSessionsPerServer
}

// addLocked records a signaled session. Callers hold mu.
func (r *Relay) addLocked(pair string, s Session) *relaySession {
	now := time.Now()
	// The wall-clock age is read once, here (and in bind's adoption check); after
	// that, with lastSeen and lastShared on r.epoch, a wall-clock step on this
	// replica never reaps or keeps a session.
	rs := &relaySession{pair: pair, s: s, created: now.Add(-now.Sub(s.CreatedAt))}
	r.byPair[pair] = rs
	r.perServer[s.ServerID]++
	r.opt.Metrics.session(s.ServerID, "signaled", 1)
	return rs
}

// queuePublish writes rs's binding to the shared registry on a worker. Writes
// are coalesced: at most one in flight per session, and it carries the latest
// address. Never blocks.
func (r *Relay) queuePublish(rs *relaySession) {
	if r.shared == nil {
		return
	}
	rs.lastShared.Store(r.since())
	r.mu.Lock()
	defer r.mu.Unlock()
	if rs.publishing {
		rs.republish = true
		return
	}
	select {
	case r.jobs <- func(ctx context.Context) { r.publish(ctx, rs) }:
		rs.publishing = true
	default: // queue full: back-date lastShared so forward retries after sharedRetry (RN-4)
		rs.lastShared.Store(r.since() + int64(sharedRetry-r.opt.IdleTimeout/2))
		r.opt.Metrics.queueFull()
	}
}

// publish writes client->pair and refreshes the session to the active TTL,
// deleting the key of the address the session left. Worker only.
func (r *Relay) publish(ctx context.Context, rs *relaySession) {
	ttl := r.opt.IdleTimeout
	for {
		r.mu.Lock()
		client, live := rs.client, r.byPair[rs.pair] == rs
		r.mu.Unlock()
		if live && client.IsValid() {
			if rs.published.IsValid() && rs.published != client {
				r.sharedCall(ctx, "delete client", func(ctx context.Context) error { return r.shared.DeleteClient(ctx, rs.published) })
			}
			r.sharedCall(ctx, "bind client", func(ctx context.Context) error { return r.shared.BindClient(ctx, client, rs.pair, ttl) })
			r.sharedCall(ctx, "refresh session", func(ctx context.Context) error { return r.shared.PutSession(ctx, rs.pair, rs.s, ttl) })
			rs.published = client
		}
		r.mu.Lock()
		again := rs.republish
		rs.republish, rs.publishing = false, again
		r.mu.Unlock()
		if !again {
			return
		}
	}
}

func (r *Relay) sharedCall(ctx context.Context, op string, call func(context.Context) error) {
	sctx, cancel := context.WithTimeout(ctx, registryTimeout)
	defer cancel()
	if err := call(sctx); err != nil {
		r.sharedError(op, err, logrus.WarnLevel)
	}
}

func (r *Relay) forward(rs *relaySession, pkt []byte) {
	now := r.since()
	rs.lastSeen.Store(now)
	if last := rs.lastShared.Load(); last == 0 || now-last >= int64(r.opt.IdleTimeout/2) {
		r.queuePublish(rs)
	}
	if _, err := rs.upstream.Write(pkt); err != nil {
		logrus.WithError(err).Debug("nethernet relay: upstream write failed")
	}
}

// pipeUpstream sends BDS replies to whichever client address the session is bound to now.
func (r *Relay) pipeUpstream(rs *relaySession) {
	buf := make([]byte, 8*1024) // WebRTC datagrams stay near 1.2 KB
	for {
		n, err := rs.upstream.Read(buf)
		if err != nil {
			if isClosed(err) {
				return
			}
			continue
		}
		r.mu.Lock()
		client := rs.client
		r.mu.Unlock()
		if _, err := r.conn.WriteToUDPAddrPort(buf[:n], client); err != nil {
			logrus.WithError(err).Debug("nethernet relay: client write failed")
		}
	}
}

// reapLoop drops sessions that never bound within UnboundTTL, bound sessions
// with no client datagram for IdleTimeout, and any session older than
// HardReap. Only client traffic counts: a live client sends ICE consent checks
// on its own.
func (r *Relay) reapLoop(ctx context.Context) {
	tick := min(r.opt.IdleTimeout, r.opt.UnboundTTL)
	if r.opt.HardReap > 0 {
		tick = min(tick, r.opt.HardReap)
	}
	t := time.NewTicker(max(tick/2, time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			r.reap(now)
		}
	}
}

func (r *Relay) reap(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for pair, rs := range r.byPair {
		age := now.Sub(rs.created)
		switch {
		case r.opt.HardReap > 0 && age > r.opt.HardReap,
			rs.upstream == nil && age > r.opt.UnboundTTL,
			rs.upstream != nil && int64(now.Sub(r.epoch))-rs.lastSeen.Load() > int64(r.opt.IdleTimeout):
			r.dropLocked(pair, rs)
		}
	}
}

func (r *Relay) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for pair, rs := range r.byPair {
		r.dropLocked(pair, rs)
	}
}

// ipKey is the per-IP cap's address: IPv4 (mapped or not), or the IPv6 /64.
func ipKey(ip netip.Addr) netip.Addr {
	if ip = ip.Unmap(); ip.Is6() {
		return netip.PrefixFrom(ip, 64).Masked().Addr()
	}
	return ip
}

// releaseIPLocked stops counting rs against its signaling IP. Callers hold mu.
func (r *Relay) releaseIPLocked(rs *relaySession) {
	if !rs.countsForIP {
		return
	}
	rs.countsForIP = false
	if r.perIP[rs.ipKey]--; r.perIP[rs.ipKey] <= 0 {
		delete(r.perIP, rs.ipKey)
	}
}

func (r *Relay) dropLocked(pair string, rs *relaySession) {
	delete(r.byPair, pair)
	r.releaseIPLocked(rs)
	if r.byClient[rs.client] == rs {
		delete(r.byClient, rs.client)
	}
	if r.perServer[rs.s.ServerID]--; r.perServer[rs.s.ServerID] <= 0 {
		delete(r.perServer, rs.s.ServerID)
	}
	if rs.upstream == nil {
		r.opt.Metrics.session(rs.s.ServerID, "signaled", -1)
		return
	}
	_ = rs.upstream.Close()
	r.opt.Metrics.session(rs.s.ServerID, "bound", -1)
}

func (r *Relay) sharedError(op string, err error, level logrus.Level) {
	r.opt.Metrics.registryError()
	logrus.WithError(err).WithField("op", op).Log(level, "nethernet relay: shared registry error")
}

// boundPair and activeSession expose state to tests.
func (r *Relay) boundPair(client netip.AddrPort) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rs := r.byClient[client]; rs != nil {
		return rs.pair, true
	}
	return "", false
}

func (r *Relay) activeSession(pair string) *relaySession {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byPair[pair]
}

// since is the monotonic offset of now on r.epoch, in nanoseconds, never 0
// (0 marks "never"; Windows' monotonic clock can read the epoch itself).
func (r *Relay) since() int64 { return max(int64(time.Since(r.epoch)), 1) }

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }
