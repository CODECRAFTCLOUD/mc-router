package nethernet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/sirupsen/logrus"
)

const (
	// forwardTimeout bounds the backend's answer; the client waits 30 s in all,
	// of which the wake hold takes 25.
	forwardTimeout = 5 * time.Second
	writeTimeout   = 5 * time.Second
	pollEvery      = 500 * time.Millisecond
	maxHeaderBytes = 64 << 10
	maxTLSRecord   = 16 << 10 // a ClientHello is read as one TLS record
)

// tlsHandshakeFailure is the fatal handshake_failure alert BDS sends to a TLS
// ClientHello, the one refusal clients were measured to fall back from.
var tlsHandshakeFailure = []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}

var joinPostPath = regexp.MustCompile(`^/v1/join/[0-9]+$`)

// SignalOptions configure the NetherNet signaling server (spec §6.3-§6.7).
type SignalOptions struct {
	Routes     *RouteTable
	Relay      *Relay
	Waker      Waker
	PublicAddr netip.AddrPort // the one candidate every answer advertises
	TLSCert    *tls.Certificate
	// GetCertificate, when set, is used instead of TLSCert, so the binary can
	// serve a renewed certificate without a restart (Ruling R29).
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	TLSDomains     []string // TLS is served for an SNI under one of these that the certificate covers
	// SignalPort is the main listener's port. Only there is a PROXY v2 header
	// read, and only from a TrustedProxies peer; every other port is a legacy
	// listener, whose source is the relay (spec §6.1).
	SignalPort     int
	TrustedProxies []netip.Prefix
	WakeHold       time.Duration // from the accept, Verify included
	ProbeTimeout   time.Duration // the readiness dial
	MaxBody        int64
	RequestTimeout time.Duration // PROXY header, TLS handshake and the whole request, from the accept
	// PerIPRate (bursts to 4x) applies to a player's own address only; GlobalRate
	// (bursts to 2x) to every connection. Per second; 0 disables a tier.
	PerIPRate, GlobalRate int
	// Ruling R34: one verified player causes at most WakesPerPlayer actual
	// wakes per rolling WakeWindow on this replica; a lifted identity
	// assertion can wake, never join.
	WakesPerPlayer int
	WakeWindow     time.Duration
	// Ruling M-5: how long the API's booting or refused answer for a legacy
	// port is reused instead of calling the API again, which bounds the calls
	// one lifted assertion can cause.
	WakeBackoff time.Duration
	Identity    *IdentityVerifier
	Metrics     *Metrics
}

// SignalServer answers NetherNet signaling: the server-list card (GET) and the
// join offer (POST), waking an asleep server for a verified player only.
type SignalServer struct {
	o       SignalOptions
	getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error) // nil: TLS is never served
	limiter *connRateLimiter
	wakes   *wakeLimiter
	backoff wakeBackoffCache
	hc      *http.Client
	now     func() time.Time // for the rate limits; tests freeze it
}

func NewSignalServer(o SignalOptions) *SignalServer {
	s := &SignalServer{o: o, limiter: newConnRateLimiter(o.GlobalRate, o.PerIPRate),
		wakes: newWakeLimiter(o.WakesPerPlayer, o.WakeWindow), backoff: wakeBackoffCache{ttl: o.WakeBackoff, byPort: map[int]cachedWake{}}, now: time.Now}
	s.getCert = o.GetCertificate
	if s.getCert == nil && o.TLSCert != nil {
		s.getCert = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return o.TLSCert, nil }
	}
	s.hc = &http.Client{ // plain HTTP to the backend: never a PROXY header, never an env proxy
		Transport:     &http.Transport{DisableKeepAlives: true, MaxResponseHeaderBytes: maxHeaderBytes},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return s
}

// join is one signaling connection.
type join struct {
	s         *SignalServer
	conn      net.Conn      // deadlines
	rw        io.ReadWriter // plain or TLS
	localPort int
	start     time.Time
	src       netip.Addr
	trusted   bool // src is the player's own address (Ruling R36)
}

// ServeConn handles one connection accepted on localPort and closes it: one
// request, one response, as BDS does.
func (s *SignalServer) ServeConn(ctx context.Context, conn net.Conn, localPort int) {
	j := &join{s: s, localPort: localPort, start: time.Now()}
	defer conn.Close()
	_ = conn.SetDeadline(j.start.Add(s.o.RequestTimeout))
	j.conn, j.src, j.trusted = s.source(conn, localPort)
	perIP := netip.Addr{} // the relay's address is shared by every player behind it
	if j.trusted {
		perIP = j.src
	}
	if ok, scope, logIt := s.limiter.allow(perIP, s.now()); !ok {
		s.o.Metrics.signal("rate_limited")
		if logIt {
			logrus.WithFields(logrus.Fields{"scope": scope, "ip": perIP}).Warn("nethernet: signaling rate limited")
		}
		return
	}

	br := bufio.NewReaderSize(j.conn, 5+maxTLSRecord)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	j.rw = struct {
		io.Reader
		io.Writer
	}{br, j.conn}
	if first[0] == 0x16 {
		tc, ok := s.terminateTLS(ctx, j.conn, br)
		if !ok {
			return
		}
		defer tc.Close()
		j.rw = tc
	}
	j.serve(ctx)
}

// source finds who is signaling. On a legacy listener it is the relay; on the
// signal port it is the PROXY v2 source when a trusted proxy sent a header,
// the peer itself when the peer is not a trusted proxy (a direct client, whose
// header, if any, is never read), and untrusted when a trusted proxy sent none.
func (s *SignalServer) source(conn net.Conn, localPort int) (net.Conn, netip.Addr, bool) {
	var peer netip.Addr
	if ap, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		peer = ap.Addr().Unmap()
	}
	if localPort != s.o.SignalPort {
		return conn, peer, false
	}
	if !slices.ContainsFunc(s.o.TrustedProxies, func(p netip.Prefix) bool { return p.Contains(peer) }) {
		return conn, peer, peer.IsValid()
	}
	// No header timeout of its own: conn's deadline (RequestTimeout) bounds it.
	pc := proxyproto.NewConn(conn, proxyproto.WithPolicy(proxyproto.USE), proxyproto.SetReadHeaderTimeout(0))
	if h := pc.ProxyHeader(); h != nil {
		if a, ok := h.SourceAddr.(*net.TCPAddr); ok {
			if ip, ok := netip.AddrFromSlice(a.IP); ok && !ip.IsUnspecified() {
				return pc, ip.Unmap(), true
			}
		}
	}
	return pc, peer, false
}

// terminateTLS reads the ClientHello record and serves TLS when its SNI is one
// of ours; otherwise it sends BDS's handshake_failure alert. The caller closes.
func (s *SignalServer) terminateTLS(ctx context.Context, conn net.Conn, br *bufio.Reader) (*tls.Conn, bool) {
	hdr, err := br.Peek(5)
	if err != nil {
		return nil, false
	}
	sni := ""
	if n := int(binary.BigEndian.Uint16(hdr[3:5])); n <= maxTLSRecord {
		rec, err := br.Peek(5 + n) // the record may span segments
		if err != nil {
			return nil, false
		}
		sni = clientHelloSNI(rec)
	}
	cert := s.certFor(sni)
	if cert == nil {
		s.o.Metrics.tlsHandshake("refused_sni")
		s.o.Metrics.signal("tls_refused")
		_, _ = conn.Write(tlsHandshakeFailure)
		return nil, false
	}
	// The pair just checked is the pair served, even if the loader swaps it now.
	tc := tls.Server(bufferedConn{Conn: conn, r: br}, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}})
	if err := tc.HandshakeContext(ctx); err != nil {
		s.o.Metrics.tlsHandshake("failed")
		logrus.WithError(err).Debug("nethernet: TLS handshake failed")
		return nil, false
	}
	s.o.Metrics.tlsHandshake("ok")
	return tc, true
}

// certFor returns the certificate to serve for sni, or nil when TLS must be
// refused: the name must be under one of TLSDomains and covered by the leaf
// the loader serves now (spec §6.3: never a certificate whose name does not
// match), so the certificate stays the source of truth across renewals.
func (s *SignalServer) certFor(sni string) *tls.Certificate {
	sni = strings.TrimSuffix(strings.ToLower(sni), ".")
	if s.getCert == nil || !s.ownsSNI(sni) {
		return nil
	}
	cert, err := s.getCert(&tls.ClientHelloInfo{ServerName: sni})
	if err != nil || cert == nil || len(cert.Certificate) == 0 {
		return nil
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return nil
		}
	}
	if leaf.VerifyHostname(sni) != nil {
		return nil
	}
	return cert
}

func (s *SignalServer) ownsSNI(sni string) bool {
	if sni == "" {
		return false
	}
	for _, d := range s.o.TLSDomains {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && (sni == d || strings.HasSuffix(sni, "."+d)) {
			return true
		}
	}
	return false
}

var errSniffed = errors.New("sniffed")

// clientHelloSNI lets crypto/tls parse one ClientHello record and returns its
// server name ("" when it has none or does not parse).
func clientHelloSNI(record []byte) string {
	sni := ""
	_ = tls.Server(sniffConn{bytes.NewReader(record)}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = h.ServerName
			return nil, errSniffed
		},
	}).Handshake()
	return sni
}

// sniffConn feeds a recorded ClientHello to crypto/tls and discards its writes.
type sniffConn struct{ r io.Reader }

func (c sniffConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (sniffConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (sniffConn) Close() error                     { return nil }
func (sniffConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (sniffConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (sniffConn) SetDeadline(time.Time) error      { return nil }
func (sniffConn) SetReadDeadline(time.Time) error  { return nil }
func (sniffConn) SetWriteDeadline(time.Time) error { return nil }

// bufferedConn reads what was peeked before it reads the connection.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (j *join) serve(ctx context.Context) {
	s := j.s
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(j.rw, maxHeaderBytes+s.o.MaxBody)))
	if err != nil {
		s.o.Metrics.signal("bad_request")
		return
	}
	if req.ContentLength > s.o.MaxBody {
		j.reply(http.StatusRequestEntityTooLarge, nil, nil, "too_large")
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, s.o.MaxBody+1))
	if err != nil {
		s.o.Metrics.signal("bad_request")
		return
	}
	if int64(len(body)) > s.o.MaxBody {
		j.reply(http.StatusRequestEntityTooLarge, nil, nil, "too_large")
		return
	}
	get := req.Method == http.MethodGet && req.URL.Path == "/v1/join"
	if !get && (req.Method != http.MethodPost || !joinPostPath.MatchString(req.URL.Path)) {
		j.reply(http.StatusNotFound, nil, nil, "not_found")
		return
	}
	b, ok := s.route(req.Host, j.localPort)
	if !ok {
		j.reply(http.StatusNotFound, nil, nil, "not_found")
		return
	}

	// From here the request's context ends when the client hangs up (net/http
	// does the same), so a join the player gave up on never wakes a server.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_ = j.conn.SetReadDeadline(time.Time{})
	go func() {
		var buf [1]byte
		for {
			if _, err := j.rw.Read(buf[:]); err != nil {
				cancel()
				return
			}
		}
	}()

	if get {
		j.card(ctx, req, b)
		return
	}
	if !s.ready(ctx, b) {
		if _, ok := j.wake(ctx, req, body, b); !ok {
			return
		}
	}
	j.answer(ctx, req, body)
}

func (s *SignalServer) route(host string, localPort int) (Backend, bool) {
	if b, ok := s.o.Routes.ByHost(host); ok {
		return b, true
	}
	return s.o.Routes.ByLegacyPort(localPort)
}

// ready: an asleep server has no ready pod, and a pod counts only once its
// signaling port accepts a connection (BDS has no readiness probe).
func (s *SignalServer) ready(ctx context.Context, b Backend) bool {
	return len(b.PodIPs) > 0 && Ready(ctx, b.Addr, s.o.ProbeTimeout)
}

// card forwards the server-list request to an awake server, or answers the
// asleep card itself. It never wakes anything.
func (j *join) card(ctx context.Context, req *http.Request, b Backend) {
	if j.s.ready(ctx, b) {
		resp, body, err := j.s.forward(ctx, b, req, nil)
		if err != nil {
			logrus.WithError(err).WithField("serverId", b.ServerID).Debug("nethernet: card forward failed")
			j.reply(http.StatusBadGateway, nil, nil, "bad_gateway")
			return
		}
		j.reply(resp.StatusCode, resp.Header, body, "forwarded")
		return
	}
	card, _ := json.Marshal(struct {
		Name       string `json:"name"`
		Level      string `json:"level"`
		Players    int    `json:"players"`
		MaxPlayers int    `json:"maxPlayers"`
		GameType   string `json:"gameType"`
	}{b.AsleepMOTD, "", 0, 0, "Survival"})
	j.reply(http.StatusOK, http.Header{"Content-Type": {"application/json"}}, card, "asleep_card")
}

// wake verifies the player, wakes the server through the API and holds the
// join until the server is ready, all within WakeHold of the accept. It
// answers the client itself when it returns false.
func (j *join) wake(ctx context.Context, req *http.Request, offer []byte, b Backend) (Backend, bool) {
	s := j.s
	hold, cancel := context.WithDeadline(ctx, j.start.Add(s.o.WakeHold))
	defer cancel()
	refuse := func(status int, outcome string) (Backend, bool) {
		s.o.Metrics.wakeHold(outcome)
		result := "unavailable"
		if status == http.StatusForbidden {
			result = "forbidden"
		}
		j.reply(status, nil, nil, result)
		return Backend{}, false
	}
	if b.LegacyPort <= 0 { // the wake API is keyed by the pool port
		return refuse(http.StatusServiceUnavailable, "no_legacy_port")
	}
	if s.o.Identity == nil {
		return refuse(http.StatusForbidden, "identity_rejected")
	}
	// Verify ignores cancellation (a shared JWKS fetch, up to 10 s): it runs on
	// the hold's clock, and the hold is checked again after it.
	who, err := s.o.Identity.Verify(hold, string(offer))
	if err != nil {
		logrus.WithError(err).WithField("serverId", b.ServerID).Debug("nethernet: join refused before wake")
		return refuse(http.StatusForbidden, "identity_rejected")
	}
	if ctx.Err() != nil {
		return refuse(http.StatusServiceUnavailable, "cancelled")
	}
	if hold.Err() != nil {
		return refuse(http.StatusServiceUnavailable, "timeout")
	}
	res, cached := s.backoff.get(b.LegacyPort, s.now()) // err is nil here: Verify passed
	if !cached {
		at, ok := s.wakes.reserve(who.XUID, s.now())
		if !ok {
			logrus.WithFields(logrus.Fields{"serverId": b.ServerID, "xuid": who.XUID}).Warn("nethernet: player wake limit reached")
			return refuse(http.StatusServiceUnavailable, "player_limit")
		}
		res, err = s.o.Waker.Wake(hold, b.LegacyPort, who)
		if err != nil || !res.Woken {
			s.wakes.release(who.XUID, at)
		}
		if err == nil && !res.Woken { // an API answer; a failure (network, timeout, non-200) is retried
			s.backoff.put(b.LegacyPort, cachedWake{at: s.now(), res: res})
		}
	}
	if err != nil || !res.Woken && !res.Booting {
		logrus.WithError(err).WithFields(logrus.Fields{"serverId": b.ServerID, "message": res.Message, "cached": cached}).Info("nethernet: wake refused")
		return refuse(http.StatusServiceUnavailable, "refused")
	}
	logrus.WithFields(logrus.Fields{"serverId": b.ServerID, "woken": res.Woken, "gamertag": who.Gamertag}).
		Info("nethernet: holding a join while the server boots")
	tick := time.NewTicker(pollEvery)
	defer tick.Stop()
	for {
		if fresh, ok := s.route(req.Host, j.localPort); ok && s.ready(hold, fresh) {
			s.o.Metrics.wakeHold("ready")
			return fresh, true
		}
		select {
		case <-hold.Done():
			if ctx.Err() != nil { // the player hung up, not a slow boot
				return refuse(http.StatusServiceUnavailable, "cancelled")
			}
			return refuse(http.StatusServiceUnavailable, "timeout")
		case <-tick.C:
		}
	}
}

// answer forwards the offer, registers the session with the relay and returns
// the answer rewritten to the one public candidate. Any failure after the
// forward is a 502: the unrewritten answer never leaves the router.
func (j *join) answer(ctx context.Context, req *http.Request, offer []byte) {
	s := j.s
	b, ok := s.route(req.Host, j.localPort)
	if !ok {
		j.reply(http.StatusBadGateway, nil, nil, "bad_gateway")
		return
	}
	resp, answer, err := s.forward(ctx, b, req, offer)
	if err != nil {
		logrus.WithError(err).WithField("serverId", b.ServerID).Debug("nethernet: offer forward failed")
		j.reply(http.StatusBadGateway, nil, nil, "bad_gateway")
		return
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 { // BDS's own refusal: its status, never its body
		j.reply(resp.StatusCode, nil, nil, "backend_status")
		return
	}
	fail := func(why string, err error) {
		logrus.WithError(err).WithField("serverId", b.ServerID).Warn("nethernet: answer refused: " + why)
		j.reply(http.StatusBadGateway, nil, nil, "bad_gateway")
	}
	off, err := ParseSDP(string(offer))
	if err != nil {
		fail("offer", err)
		return
	}
	ans, err := ParseSDP(string(answer))
	if err != nil {
		fail("answer", err)
		return
	}
	// PodIPs as of the answer, but only of the Service that answered: a route
	// that moved to another Service meanwhile must not lend it its pods.
	if fresh, ok := s.route(req.Host, j.localPort); ok && fresh.Addr == b.Addr {
		b = fresh
	}
	var target netip.AddrPort
	for _, ip := range b.PodIPs { // R25: the relay target is the backend's own pod, whatever the answer says
		if t, err := PickRelayTarget(ans.Candidates, ip); err == nil {
			target = t
			break
		}
	}
	if !target.IsValid() {
		fail("no candidate at the pod address", fmt.Errorf("pods %v", b.PodIPs))
		return
	}
	rewritten, err := RewriteAnswer(string(answer), s.o.PublicAddr)
	if err != nil {
		fail("rewrite", err)
		return
	}
	err = s.o.Relay.Register(ctx, ans.IceUfrag+":"+off.IceUfrag, Session{
		ServerID: b.ServerID, Target: target, IcePwd: ans.IcePwd, SignalIP: j.src, SignalIPTrusted: j.trusted,
	})
	if errors.Is(err, ErrSessionCap) {
		j.reply(http.StatusServiceUnavailable, nil, nil, "session_cap")
		return
	}
	if err != nil {
		fail("register", err)
		return
	}
	j.reply(http.StatusOK, resp.Header, []byte(rewritten), "answered")
}

// forward sends the request to the backend's signaling port as plain HTTP
// with the original Host, and reads the response (at most MaxBody).
func (s *SignalServer) forward(ctx context.Context, b Backend, req *http.Request, body []byte) (*http.Response, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, req.Method, "http://"+b.Addr.String()+req.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	out.Header = req.Header.Clone()
	out.Host = req.Host
	resp, err := s.hc.Do(out)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, s.o.MaxBody+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(rb)) > s.o.MaxBody {
		return nil, nil, errors.New("backend response over MaxBody")
	}
	return resp, rb, nil
}

// reply writes one response and asks the client to close, as BDS does.
func (j *join) reply(status int, h http.Header, body []byte, result string) {
	j.s.o.Metrics.signal(result)
	h = h.Clone()
	if h == nil {
		h = http.Header{}
	}
	for _, k := range []string{"Connection", "Keep-Alive", "Content-Length", "Transfer-Encoding"} {
		h.Del(k)
	}
	resp := &http.Response{StatusCode: status, ProtoMajor: 1, ProtoMinor: 1, Header: h, ContentLength: int64(len(body)), Close: true}
	if len(body) > 0 {
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	_ = j.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_ = resp.Write(j.rw)
}

func newWakeLimiter(limit int, window time.Duration) *wakeLimiter {
	return &wakeLimiter{limit: limit, window: window, byXUID: map[string][]time.Time{}}
}

// wakeLimiter counts each player's actual wakes over the last window.
type wakeLimiter struct {
	limit     int
	window    time.Duration
	mu        sync.Mutex
	byXUID    map[string][]time.Time
	lastSweep time.Time
}

// reserve takes one of xuid's wakes before the API call, so concurrent joins
// cannot overshoot; release gives it back when the call woke nothing.
func (l *wakeLimiter) reserve(xuid string, now time.Time) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fresh := func(ts []time.Time) []time.Time {
		return slices.DeleteFunc(ts, func(t time.Time) bool { return now.Sub(t) >= l.window })
	}
	if now.Sub(l.lastSweep) >= ipSweepEvery { // bounds the map to players seen this window
		l.lastSweep = now
		for x, ts := range l.byXUID {
			if ts = fresh(ts); len(ts) == 0 {
				delete(l.byXUID, x)
			} else {
				l.byXUID[x] = ts
			}
		}
	}
	ts := fresh(l.byXUID[xuid])
	if len(ts) >= l.limit {
		l.byXUID[xuid] = ts
		return time.Time{}, false
	}
	l.byXUID[xuid] = append(ts, now)
	return now, true
}

func (l *wakeLimiter) release(xuid string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.byXUID[xuid]
	if i := slices.IndexFunc(ts, at.Equal); i >= 0 {
		l.byXUID[xuid] = slices.Delete(ts, i, i+1)
	}
}

// wakeBackoffCache holds each legacy port's last booting or refused wake
// answer from the API for ttl (Ruling M-5); a failed call is never
// held. Joins that miss together, before the first call returns, each call
// the API: that burst is bounded by the signaling rate limits. It holds at
// most one entry per published legacy port.
type wakeBackoffCache struct {
	ttl    time.Duration
	mu     sync.Mutex
	byPort map[int]cachedWake
}

type cachedWake struct {
	at  time.Time
	res WakeResult
}

func (c *wakeBackoffCache) get(port int, now time.Time) (WakeResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w, ok := c.byPort[port]
	if ok && now.Sub(w.at) >= c.ttl {
		delete(c.byPort, port)
		return WakeResult{}, false
	}
	return w.res, ok
}

func (c *wakeBackoffCache) put(port int, w cachedWake) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byPort[port] = w
}
