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

// registryTimeout bounds every shared-registry call so a slow Dragonfly never stalls the packet path.
const registryTimeout = 250 * time.Millisecond

type RelayOptions struct {
	UnboundTTL, IdleTimeout time.Duration
	MaxSessions             int
	Metrics                 *Metrics
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
}

// NewRelay builds a relay on conn. shared may be nil (single replica).
func NewRelay(conn *net.UDPConn, local Registry, shared Registry, opt RelayOptions) *Relay {
	return &Relay{conn: conn, local: local, shared: shared, opt: opt,
		byClient: map[netip.AddrPort]*relaySession{}, byPair: map[string]*relaySession{}}
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
	if r.opt.IdleTimeout > 0 {
		go r.reapLoop(ctx)
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
	r.bindFromShared(ctx, from, pkt)
}

func (r *Relay) bindFromSTUN(ctx context.Context, from netip.AddrPort, pkt []byte) {
	pair, ok := STUNUsername(pkt)
	if !ok {
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	s, ok := r.lookupSession(ctx, pair)
	if !ok {
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	if !VerifyIntegrity(pkt, s.IcePwd) {
		r.opt.Metrics.dropped("bad_integrity")
		return
	}
	r.bindAndForward(ctx, from, pair, s, true, pkt)
}

// bindFromShared covers a failover mid-session: the client was verified on
// another replica and its next datagram (not STUN) lands here.
func (r *Relay) bindFromShared(ctx context.Context, from netip.AddrPort, pkt []byte) {
	if r.shared == nil {
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	sctx, cancel := context.WithTimeout(ctx, registryTimeout)
	pair, ok, err := r.shared.LookupClient(sctx, from)
	cancel()
	if err != nil {
		r.sharedError("lookup client", err, logrus.DebugLevel)
	}
	if !ok {
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	s, ok := r.lookupSession(ctx, pair)
	if !ok {
		r.opt.Metrics.dropped("unknown_peer")
		return
	}
	// rebind=false: a session live on this replica moves only on a verified STUN check.
	r.bindAndForward(ctx, from, pair, s, false, pkt)
}

// lookupSession finds a pair: live on this replica, then local, then shared.
func (r *Relay) lookupSession(ctx context.Context, pair string) (Session, bool) {
	r.mu.Lock()
	rs := r.byPair[pair]
	r.mu.Unlock()
	if rs != nil {
		return rs.s, true
	}
	if s, ok, err := r.local.GetSession(ctx, pair); err == nil && ok {
		return s, true
	}
	if r.shared == nil {
		return Session{}, false
	}
	sctx, cancel := context.WithTimeout(ctx, registryTimeout)
	defer cancel()
	s, ok, err := r.shared.GetSession(sctx, pair)
	if err != nil {
		r.sharedError("get session", err, logrus.DebugLevel)
		return Session{}, false
	}
	return s, ok
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
	if r.opt.MaxSessions > 0 && len(r.byPair) >= r.opt.MaxSessions {
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
	if r.opt.IdleTimeout > 0 && now-rs.lastShared.Load() >= int64(r.opt.IdleTimeout/2) {
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
	t := time.NewTicker(r.opt.IdleTimeout / 2)
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
