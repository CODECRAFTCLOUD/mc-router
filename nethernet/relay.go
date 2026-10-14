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
	// the read loop: a full queue drops the job and the client's retransmit retries.
	sharedWorkers = 4
	sharedQueue   = 256
	// A key is looked up at most once per 1-2 s (de-dup while in flight plus a
	// negative cache), and at most maxLookupKeys distinct keys per window.
	lookupWindow  = time.Second
	maxLookupKeys = 4096
)

// RelayOptions bound every session: UnboundTTL for a signaled session that never
// binds, IdleTimeout without client traffic, HardReap for any session (0 = off).
type RelayOptions struct {
	UnboundTTL, IdleTimeout, HardReap time.Duration
	MaxSessions, MaxSessionsPerServer int
	Metrics                           *Metrics
}

// relaySession is a bound session: one upstream socket to BDS and the client
// address it currently answers to.
type relaySession struct {
	pair       string
	s          Session
	upstream   *net.UDPConn
	client     netip.AddrPort // guarded by Relay.mu
	lastSeen   atomic.Int64   // unix nanos of the last client datagram
	lastShared atomic.Int64   // unix nanos of the last shared-registry refresh
}

// Relay forwards one public UDP port to many BDS pods. A client address binds
// to a session only through a STUN check signed with that session's ICE
// password, or through a binding another replica already verified.
type Relay struct {
	conn          *net.UDPConn
	local, shared Registry
	opt           RelayOptions

	mu       sync.Mutex
	byClient map[netip.AddrPort]*relaySession
	byPair   map[string]*relaySession

	jobs chan func(context.Context)
	// Keys looked up in this window and the previous one. Read loop only.
	looked, lookedPrev map[string]struct{}
	lookedUntil        time.Time
}

// NewRelay builds a relay on conn. shared may be nil (single replica). A zero
// timeout or cap is refused: it would make every join fail or never reap.
func NewRelay(conn *net.UDPConn, local Registry, shared Registry, opt RelayOptions) (*Relay, error) {
	if opt.UnboundTTL <= 0 || opt.IdleTimeout <= 0 || opt.HardReap < 0 || opt.MaxSessions <= 0 || opt.MaxSessionsPerServer <= 0 {
		return nil, errors.New("nethernet relay: UnboundTTL, IdleTimeout, MaxSessions and MaxSessionsPerServer must be > 0, HardReap >= 0")
	}
	return &Relay{conn: conn, local: local, shared: shared, opt: opt,
		byClient: map[netip.AddrPort]*relaySession{}, byPair: map[string]*relaySession{},
		jobs: make(chan func(context.Context), sharedQueue)}, nil
}

// Register records a signaled session locally and in the shared registry. A
// shared-registry error is logged and counted, never returned.
func (r *Relay) Register(ctx context.Context, pair string, s Session) error {
	if err := r.local.PutSession(ctx, pair, s, r.opt.UnboundTTL); err != nil {
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

// Serve reads the relay socket until ctx is done, then closes every upstream socket.
func (r *Relay) Serve(ctx context.Context) error {
	stop := context.AfterFunc(ctx, func() { _ = r.conn.SetReadDeadline(time.Now()) })
	defer stop()
	defer r.closeAll()
	go r.reapLoop(ctx)
	for range sharedWorkers {
		go r.work(ctx)
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
		r.forward(ctx, from, rs, pkt)
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
	s, ok := r.knownSession(ctx, pair)
	if !ok {
		r.queueLookup("s:"+pair, func(ctx context.Context) { r.fetchSession(ctx, pair) })
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	if !VerifyIntegrity(pkt, s.IcePwd) {
		r.opt.Metrics.dropped("bad_integrity")
		return
	}
	r.bindAndForward(ctx, from, pair, s, true, pkt)
}

// bindFromKnownClient covers a failover mid-session: the client was verified on
// another replica and its next datagram (not STUN) lands here. Only DTLS-shaped
// datagrams (first byte 20-63, RFC 7983) are worth a shared lookup.
func (r *Relay) bindFromKnownClient(ctx context.Context, from netip.AddrPort, pkt []byte) {
	if pair, ok, _ := r.local.LookupClient(ctx, from); ok {
		if s, ok := r.knownSession(ctx, pair); ok {
			// rebind=false: a session live on this replica moves only on a verified STUN check.
			r.bindAndForward(ctx, from, pair, s, false, pkt)
			return
		}
	}
	if len(pkt) > 0 && pkt[0] >= 20 && pkt[0] <= 63 {
		r.queueLookup("c:"+from.String(), func(ctx context.Context) { r.fetchClient(ctx, from) })
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

// queueLookup hands a shared-registry lookup to the workers unless key was
// queued in this window or the last. Read loop only; never blocks.
func (r *Relay) queueLookup(key string, job func(context.Context)) {
	if r.shared == nil {
		return
	}
	if now := time.Now(); now.After(r.lookedUntil) {
		r.lookedPrev, r.looked, r.lookedUntil = r.looked, map[string]struct{}{}, now.Add(lookupWindow)
	}
	if _, ok := r.looked[key]; ok {
		return
	}
	if _, ok := r.lookedPrev[key]; ok || len(r.looked) >= maxLookupKeys {
		return
	}
	select {
	case r.jobs <- job:
		r.looked[key] = struct{}{}
	default: // queue full: the retransmit retries
	}
}

func (r *Relay) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.jobs:
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

func (r *Relay) bindAndForward(ctx context.Context, from netip.AddrPort, pair string, s Session, rebind bool, pkt []byte) {
	rs, reason := r.bind(from, pair, s, rebind)
	if rs == nil {
		r.opt.Metrics.dropped(reason)
		return
	}
	r.publishBinding(ctx, from, rs)
	r.forward(ctx, from, rs, pkt)
}

func (r *Relay) bind(client netip.AddrPort, pair string, s Session, rebind bool) (*relaySession, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rs := r.byPair[pair]; rs != nil {
		if !rebind {
			return nil, "unknown_peer"
		}
		delete(r.byClient, rs.client)
		rs.client = client
		r.byClient[client] = rs
		return rs, ""
	}
	if len(r.byPair) >= r.opt.MaxSessions {
		return nil, "session_cap"
	}
	up, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(s.Target))
	if err != nil {
		logrus.WithError(err).WithField("serverId", s.ServerID).Warn("nethernet relay: cannot dial BDS")
		return nil, "dial_failed"
	}
	rs := &relaySession{pair: pair, s: s, upstream: up, client: client}
	rs.lastSeen.Store(time.Now().UnixNano())
	r.byPair[pair] = rs
	r.byClient[client] = rs
	r.opt.Metrics.activeSessions(len(r.byPair))
	go r.pipeUpstream(rs)
	return rs, ""
}

// publishBinding writes client→pair locally and, best-effort and off the packet
// path, to the shared registry with the session refreshed alongside.
func (r *Relay) publishBinding(ctx context.Context, client netip.AddrPort, rs *relaySession) {
	rs.lastShared.Store(time.Now().UnixNano())
	ttl := r.opt.IdleTimeout
	if err := r.local.BindClient(ctx, client, rs.pair, ttl); err != nil {
		logrus.WithError(err).Debug("nethernet relay: local bind failed")
	}
	if r.shared == nil {
		return
	}
	go func() {
		sctx, cancel := context.WithTimeout(context.Background(), registryTimeout)
		defer cancel()
		if err := r.shared.BindClient(sctx, client, rs.pair, ttl); err != nil {
			r.sharedError("bind client", err, logrus.WarnLevel)
			return
		}
		if err := r.shared.PutSession(sctx, rs.pair, rs.s, ttl); err != nil {
			r.sharedError("refresh session", err, logrus.WarnLevel)
		}
	}()
}

func (r *Relay) forward(ctx context.Context, from netip.AddrPort, rs *relaySession, pkt []byte) {
	now := time.Now().UnixNano()
	rs.lastSeen.Store(now)
	if now-rs.lastShared.Load() >= int64(r.opt.IdleTimeout/2) {
		r.publishBinding(ctx, from, rs)
	}
	if _, err := rs.upstream.Write(pkt); err != nil {
		logrus.WithError(err).Debug("nethernet relay: upstream write failed")
	}
}

// pipeUpstream sends BDS replies to whichever client address the session is bound to now.
func (r *Relay) pipeUpstream(rs *relaySession) {
	buf := make([]byte, 64*1024)
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

// reapLoop drops sessions with no client datagram for IdleTimeout. Only client
// traffic counts: a live client sends ICE consent checks on its own.
func (r *Relay) reapLoop(ctx context.Context) {
	t := time.NewTicker(max(r.opt.IdleTimeout/2, time.Millisecond))
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
		if now.UnixNano()-rs.lastSeen.Load() > int64(r.opt.IdleTimeout) {
			r.dropLocked(pair, rs)
		}
	}
	r.opt.Metrics.activeSessions(len(r.byPair))
}

func (r *Relay) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for pair, rs := range r.byPair {
		r.dropLocked(pair, rs)
	}
	r.opt.Metrics.activeSessions(0)
}

func (r *Relay) dropLocked(pair string, rs *relaySession) {
	delete(r.byPair, pair)
	delete(r.byClient, rs.client)
	_ = rs.upstream.Close()
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

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }
