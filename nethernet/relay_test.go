package nethernet

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPair = "2c69:QXyz"

// A DTLS 1.2 application-data record header plus a few bytes.
var dtlsData = []byte{0x17, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 7, 0, 3, 'a', 'b', 'c'}

type fakeBDS struct {
	addr netip.AddrPort
	got  chan []byte
}

// startBDS echoes every datagram back to its sender and reports what it got.
func startBDS(t *testing.T) *fakeBDS {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	b := &fakeBDS{addr: conn.LocalAddr().(*net.UDPAddr).AddrPort(), got: make(chan []byte, 64)}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				if isClosed(err) {
					return
				}
				continue
			}
			b.got <- append([]byte(nil), buf[:n]...)
			_, _ = conn.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return b
}

func (b *fakeBDS) expect(t *testing.T, want []byte) {
	t.Helper()
	select {
	case got := <-b.got:
		assert.Equal(t, want, got)
	case <-time.After(2 * time.Second):
		t.Fatal("BDS got nothing")
	}
}

func (b *fakeBDS) expectNothing(t *testing.T) {
	t.Helper()
	select {
	case got := <-b.got:
		t.Fatalf("BDS got an unexpected %d-byte packet", len(got))
	case <-time.After(200 * time.Millisecond):
	}
}

func startRelay(t *testing.T, local, shared Registry, opt RelayOptions) (*Relay, netip.AddrPort) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	r, err := NewRelay(conn, local, shared, opt)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() { _ = r.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done; _ = conn.Close() })
	return r, conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func defaultOpts(m *Metrics) RelayOptions {
	return RelayOptions{UnboundTTL: time.Minute, IdleTimeout: time.Minute, MaxSessions: 100, MaxSessionsPerServer: 100, MaxPerIPPerServer: 100, Metrics: m}
}

func newClient(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func clientAddr(c *net.UDPConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }

func send(t *testing.T, c *net.UDPConn, to netip.AddrPort, pkt []byte) {
	t.Helper()
	_, err := c.WriteToUDPAddrPort(pkt, to)
	require.NoError(t, err)
}

func expectReply(t *testing.T, c *net.UDPConn, from netip.AddrPort, want []byte) {
	t.Helper()
	require.NoError(t, c.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 2048)
	n, src, err := c.ReadFromUDPAddrPort(buf)
	require.NoError(t, err, "client got no reply")
	assert.Equal(t, from, src)
	assert.Equal(t, want, buf[:n])
}

// retransmit sends pkt every 50 ms, as ICE and DTLS do, until BDS gets it and
// the client gets the echo, then drains the duplicates a late resend produced.
func retransmit(t *testing.T, c *net.UDPConn, to netip.AddrPort, pkt []byte, bds *fakeBDS) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for got := false; !got; {
		require.True(t, time.Now().Before(deadline), "BDS never got the retransmitted packet")
		send(t, c, to, pkt)
		select {
		case b := <-bds.got:
			assert.Equal(t, pkt, b)
			got = true
		case <-time.After(50 * time.Millisecond):
		}
	}
	expectReply(t, c, to, pkt)
	time.Sleep(150 * time.Millisecond)
	for len(bds.got) > 0 {
		<-bds.got
	}
	buf := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		if _, _, err := c.ReadFromUDPAddrPort(buf); err != nil {
			return
		}
	}
}

func session(b *fakeBDS) Session { return Session{ServerID: "srv-1", Target: b.addr, IcePwd: testPwd} }

func TestRelayForwardsAfterAVerifiedBind(t *testing.T) {
	bds := startBDS(t)
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(nil))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	stunPkt := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, stunPkt)
	bds.expect(t, stunPkt)
	expectReply(t, c, relayAddr, stunPkt)

	send(t, c, relayAddr, dtlsData)
	bds.expect(t, dtlsData)
	expectReply(t, c, relayAddr, dtlsData)
}

func TestRelayDropsSTUNWithABadIntegrity(t *testing.T) {
	bds := startBDS(t)
	m := NewMetrics(prometheus.NewRegistry())
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(m))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	send(t, c, relayAddr, signedBinding(testPair, "not-the-ice-password-000"))
	bds.expectNothing(t)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.UDPDropped.WithLabelValues("bad_integrity")))
	_, bound := r.boundPair(clientAddr(c))
	assert.False(t, bound)
}

func TestRelayDropsUnknownNonSTUN(t *testing.T) {
	bds := startBDS(t)
	m := NewMetrics(prometheus.NewRegistry())
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(m))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	send(t, c, relayAddr, dtlsData)
	bds.expectNothing(t)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.UDPDropped.WithLabelValues("unknown_peer")))
}

func TestRelayRebindsOnAVerifiedCheckFromANewAddress(t *testing.T) {
	bds := startBDS(t)
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(nil))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	old := newClient(t)
	first := signedBinding(testPair, testPwd)
	send(t, old, relayAddr, first)
	bds.expect(t, first)
	expectReply(t, old, relayAddr, first)

	moved := newClient(t)
	second := signedBinding(testPair, testPwd)
	send(t, moved, relayAddr, second)
	bds.expect(t, second)
	expectReply(t, moved, relayAddr, second)

	send(t, old, relayAddr, dtlsData)
	bds.expectNothing(t)
	_, bound := r.boundPair(clientAddr(old))
	assert.False(t, bound)
	pair, bound := r.boundPair(clientAddr(moved))
	assert.True(t, bound)
	assert.Equal(t, testPair, pair)
}

func TestRelayIgnoresADTLSAlertFromTheClientSide(t *testing.T) {
	bds := startBDS(t)
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(nil))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	stunPkt := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, stunPkt)
	bds.expect(t, stunPkt)

	alert := []byte{0x15, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 9, 0, 2, 2, 0}
	send(t, c, relayAddr, alert)
	bds.expect(t, alert)
	send(t, c, relayAddr, dtlsData)
	bds.expect(t, dtlsData)
	pair, bound := r.boundPair(clientAddr(c))
	assert.True(t, bound)
	assert.Equal(t, testPair, pair)
}

func sharedRedis(t *testing.T) (*miniredis.Miniredis, Registry) {
	mr := miniredis.RunT(t)
	return mr, newTestRedisRegistry(t, mr.Addr())
}

func TestRelayRelaysASessionSignaledOnAnotherReplica(t *testing.T) {
	bds := startBDS(t)
	_, shared := sharedRedis(t)
	a, _ := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	_, bAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	require.NoError(t, a.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	// B learns the pair from the shared registry off its read loop, so the
	// first checks may be dropped; a client retransmits them.
	retransmit(t, c, bAddr, signedBinding(testPair, testPwd), bds)
	send(t, c, bAddr, dtlsData)
	bds.expect(t, dtlsData)
}

func TestRelayForwardsNonSTUNFromAClientBoundOnAnotherReplica(t *testing.T) {
	bds := startBDS(t)
	mr, shared := sharedRedis(t)
	a, aAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	_, bAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	require.NoError(t, a.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	stunPkt := signedBinding(testPair, testPwd)
	send(t, c, aAddr, stunPkt)
	bds.expect(t, stunPkt)
	expectReply(t, c, aAddr, stunPkt)
	assert.Eventually(t, func() bool { return mr.Exists("nn:client:" + clientAddr(c).String()) },
		2*time.Second, 10*time.Millisecond, "bind on A reaches the shared registry")

	// Failover: the next packets of the same client land on B, and they are DTLS.
	retransmit(t, c, bAddr, dtlsData, bds)
}

func TestRelayReapsIdleSessions(t *testing.T) {
	bds := startBDS(t)
	opt := defaultOpts(nil)
	opt.IdleTimeout = 50 * time.Millisecond
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), opt)
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	stunPkt := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, stunPkt)
	bds.expect(t, stunPkt)
	rs := r.activeSession(testPair)
	require.NotNil(t, rs)

	time.Sleep(100 * time.Millisecond)
	assert.Eventually(t, func() bool { _, bound := r.boundPair(clientAddr(c)); return !bound },
		time.Second, 10*time.Millisecond)
	assert.True(t, r.activeSession(testPair) == nil)
	_, err := rs.upstream.Write([]byte{1})
	assert.True(t, isClosed(err), "upstream socket is closed, got %v", err)
}

func TestRelayRefusesBindsBeyondMaxSessions(t *testing.T) {
	bds := startBDS(t)
	m := NewMetrics(prometheus.NewRegistry())
	_, shared := sharedRedis(t)
	opt := defaultOpts(m)
	opt.MaxSessions = 1
	a, _ := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	b, bAddr := startRelay(t, NewMemoryRegistry(), shared, opt)

	// Signal time: B holds one session, so B refuses a second.
	require.NoError(t, b.Register(t.Context(), testPair, session(bds)))
	assert.ErrorIs(t, b.Register(t.Context(), "2c69:Abcd", session(bds)), ErrSessionCap)

	// Bind time: a pair signaled on A also counts once it binds on B.
	const other = "2c69:Efgh"
	require.NoError(t, a.Register(t.Context(), other, session(bds)))
	first := newClient(t)
	p1 := signedBinding(testPair, testPwd)
	send(t, first, bAddr, p1)
	bds.expect(t, p1)

	second := newClient(t)
	for range 10 {
		send(t, second, bAddr, signedBinding(other, testPwd))
		time.Sleep(30 * time.Millisecond)
	}
	bds.expectNothing(t)
	assert.GreaterOrEqual(t, testutil.ToFloat64(m.UDPDropped.WithLabelValues("session_cap")), 1.0)
}

func TestRelayRefusesRegisterBeyondThePerServerCap(t *testing.T) {
	opt := defaultOpts(nil)
	opt.MaxSessionsPerServer = 1
	r, _ := startRelay(t, NewMemoryRegistry(), nil, opt)
	require.NoError(t, r.Register(t.Context(), "aaaa:0001", Session{ServerID: "srv-1", IcePwd: testPwd}))
	assert.ErrorIs(t, r.Register(t.Context(), "aaaa:0002", Session{ServerID: "srv-1", IcePwd: testPwd}), ErrSessionCap)
	assert.NoError(t, r.Register(t.Context(), "aaaa:0003", Session{ServerID: "srv-2", IcePwd: testPwd}))
}

// trusted is a session signaled on the main listener, where PROXY v2 gives the player's own IP.
func trusted(b *fakeBDS, server, ip string) Session {
	s := session(b)
	s.ServerID, s.SignalIP, s.SignalIPTrusted = server, netip.MustParseAddr(ip), true
	return s
}

func TestRelayCapsSessionsPerIPPerServer(t *testing.T) {
	bds := startBDS(t)
	opt := defaultOpts(nil)
	opt.MaxPerIPPerServer = 16
	r, _ := startRelay(t, NewMemoryRegistry(), nil, opt)
	for i := range 16 {
		require.NoError(t, r.Register(t.Context(), fmt.Sprintf("2c69:a%03d", i), trusted(bds, "srv-1", "198.51.100.7")))
	}
	assert.ErrorIs(t, r.Register(t.Context(), "2c69:a016", trusted(bds, "srv-1", "198.51.100.7")), ErrSessionCap, "the 17th is refused")
	assert.ErrorIs(t, r.Register(t.Context(), "2c69:a017", trusted(bds, "srv-1", "::ffff:198.51.100.7")), ErrSessionCap,
		"an IPv4-mapped address is the same IPv4 key")
	assert.NoError(t, r.Register(t.Context(), "2c69:b000", trusted(bds, "srv-2", "198.51.100.7")), "another server is unaffected")
	assert.NoError(t, r.Register(t.Context(), "2c69:c000", trusted(bds, "srv-1", "198.51.100.8")), "another IP is unaffected")
}

func TestRelayBindingDoesNotFreeThePerIPSlot(t *testing.T) {
	bds := startBDS(t)
	opt := defaultOpts(nil)
	opt.MaxPerIPPerServer = 2
	r, relayAddr := startRelay(t, NewMemoryRegistry(), nil, opt)
	require.NoError(t, r.Register(t.Context(), testPair, trusted(bds, "srv-1", "198.51.100.7")))
	require.NoError(t, r.Register(t.Context(), "2c69:0002", trusted(bds, "srv-1", "198.51.100.7")))

	c := newClient(t)
	p := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, p)
	bds.expect(t, p)
	assert.ErrorIs(t, r.Register(t.Context(), "2c69:0003", trusted(bds, "srv-1", "198.51.100.7")), ErrSessionCap,
		"a bound session still holds its signaling IP's slot")
}

func TestRelayDoesNotCountUntrustedSessionsPerIP(t *testing.T) {
	bds := startBDS(t)
	opt := defaultOpts(nil)
	opt.MaxPerIPPerServer, opt.MaxSessionsPerServer = 2, 20
	r, _ := startRelay(t, NewMemoryRegistry(), nil, opt)
	legacy := func() Session { // the legacy listener: every player arrives from the relay's address
		s := session(bds)
		s.SignalIP = netip.MustParseAddr("10.200.0.1")
		return s
	}
	for i := range 20 {
		require.NoError(t, r.Register(t.Context(), fmt.Sprintf("2c69:u%03d", i), legacy()))
	}
	assert.ErrorIs(t, r.Register(t.Context(), "2c69:u020", legacy()), ErrSessionCap, "the per-server cap still applies")
}

func TestRelayGroupsIPv6PerSlash64(t *testing.T) {
	bds := startBDS(t)
	opt := defaultOpts(nil)
	opt.MaxPerIPPerServer = 2
	r, _ := startRelay(t, NewMemoryRegistry(), nil, opt)
	require.NoError(t, r.Register(t.Context(), "2c69:v001", trusted(bds, "srv-1", "2001:db8:1:2::1")))
	require.NoError(t, r.Register(t.Context(), "2c69:v002", trusted(bds, "srv-1", "2001:db8:1:2:ffff:ffff:ffff:ffff")))
	assert.ErrorIs(t, r.Register(t.Context(), "2c69:v003", trusted(bds, "srv-1", "2001:db8:1:2::abcd")), ErrSessionCap, "same /64")
	assert.NoError(t, r.Register(t.Context(), "2c69:v004", trusted(bds, "srv-1", "2001:db8:1:3::1")), "another /64")
}

func TestRelayRejectsATrustedSessionWithoutAnIP(t *testing.T) {
	bds := startBDS(t)
	r, _ := startRelay(t, NewMemoryRegistry(), nil, defaultOpts(nil))
	s := session(bds)
	s.SignalIPTrusted = true
	err := r.Register(t.Context(), testPair, s)
	assert.ErrorIs(t, err, ErrInvalidSignalIP)
	assert.NotErrorIs(t, err, ErrSessionCap)
	assert.True(t, r.activeSession(testPair) == nil, "nothing is recorded")
}

func TestRelayReapsSessionsPastHardReap(t *testing.T) {
	bds := startBDS(t)
	opt := defaultOpts(nil)
	opt.HardReap = 100 * time.Millisecond
	r, relayAddr := startRelay(t, NewMemoryRegistry(), nil, opt)
	// Never is registered first, so it is never younger than testPair: the reap
	// pass that drops testPair has already dropped it.
	require.NoError(t, r.Register(t.Context(), "2c69:Never", session(bds)))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	stunPkt := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, stunPkt)
	bds.expect(t, stunPkt)
	rs := r.activeSession(testPair)
	require.NotNil(t, rs)

	// The client stays busy, so only the hard reap can end the session.
	deadline := time.Now().Add(time.Second)
	for r.activeSession(testPair) != nil && time.Now().Before(deadline) {
		send(t, c, relayAddr, dtlsData)
		time.Sleep(10 * time.Millisecond)
	}
	assert.True(t, r.activeSession(testPair) == nil, "a busy session is reaped past HardReap")
	assert.True(t, r.activeSession("2c69:Never") == nil, "a signaled session is reaped past HardReap")
	_, err := rs.upstream.Write([]byte{1})
	assert.True(t, isClosed(err), "upstream socket is closed, got %v", err)
}

func TestRelayHardReapSurvivesSharedReadoption(t *testing.T) {
	bds := startBDS(t)
	_, shared := sharedRedis(t)
	opt := defaultOpts(nil)
	opt.HardReap = 500 * time.Millisecond
	a, _ := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	b, bAddr := startRelay(t, NewMemoryRegistry(), shared, opt)
	require.NoError(t, a.Register(t.Context(), testPair, session(bds)))

	// B adopts the pair signaled on A, then hard-reaps it while the client is busy.
	c := newClient(t)
	check := signedBinding(testPair, testPwd)
	retransmit(t, c, bAddr, check, bds)
	deadline := time.Now().Add(3 * time.Second)
	for b.activeSession(testPair) != nil && time.Now().Before(deadline) {
		send(t, c, bAddr, check)
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, b.activeSession(testPair) == nil, "hard-reaped on B")
	time.Sleep(50 * time.Millisecond)
	for len(bds.got) > 0 {
		<-bds.got
	}

	// B still knows the pair (its local copy, and the shared one): a verified
	// check must not adopt it again with a fresh age.
	for range 10 {
		send(t, c, bAddr, check)
		time.Sleep(20 * time.Millisecond)
	}
	bds.expectNothing(t)
	assert.True(t, b.activeSession(testPair) == nil, "not re-adopted")
}

func TestRelaySessionsGaugeTracksSignaledAndBound(t *testing.T) {
	bds := startBDS(t)
	m := NewMetrics(prometheus.NewRegistry())
	opt := defaultOpts(m)
	opt.HardReap = 300 * time.Millisecond
	r, relayAddr := startRelay(t, NewMemoryRegistry(), nil, opt)
	gauge := func(state string) float64 { return testutil.ToFloat64(m.Sessions.WithLabelValues("srv-1", state)) }

	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))
	assert.Equal(t, 1.0, gauge("signaled"))
	assert.Equal(t, 0.0, gauge("bound"))

	for range 2 { // bind, then rebind from a new address
		c := newClient(t)
		p := signedBinding(testPair, testPwd)
		send(t, c, relayAddr, p)
		bds.expect(t, p)
		assert.Equal(t, 0.0, gauge("signaled"))
		assert.Equal(t, 1.0, gauge("bound"))
	}

	assert.Eventually(t, func() bool { return gauge("bound") == 0 }, 2*time.Second, 10*time.Millisecond, "reap")
	assert.Equal(t, 0.0, gauge("signaled"))
}

func TestRelayRegisterSurvivesASharedRegistryOutage(t *testing.T) {
	mr, shared := sharedRedis(t)
	mr.Close()
	m := NewMetrics(prometheus.NewRegistry())
	local := NewMemoryRegistry()
	r, _ := startRelay(t, local, shared, defaultOpts(m))
	require.NoError(t, r.Register(t.Context(), testPair, Session{IcePwd: testPwd}))
	_, ok, err := local.GetSession(t.Context(), testPair)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.RegistryErrors))
}

func TestNewRelayRejectsZeroTimeouts(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	for name, zero := range map[string]func(*RelayOptions){
		"UnboundTTL":           func(o *RelayOptions) { o.UnboundTTL = 0 },
		"IdleTimeout":          func(o *RelayOptions) { o.IdleTimeout = 0 },
		"MaxSessions":          func(o *RelayOptions) { o.MaxSessions = 0 },
		"MaxSessionsPerServer": func(o *RelayOptions) { o.MaxSessionsPerServer = -1 },
		"MaxPerIPPerServer":    func(o *RelayOptions) { o.MaxPerIPPerServer = 0 },
	} {
		opt := defaultOpts(nil)
		zero(&opt)
		_, err := NewRelay(conn, NewMemoryRegistry(), nil, opt)
		assert.Error(t, err, name)
	}
	opt := defaultOpts(nil)
	opt.HardReap = 0 // off
	_, err = NewRelay(conn, NewMemoryRegistry(), nil, opt)
	assert.NoError(t, err)
}

// hungRegistry is a shared registry whose every call waits for its context to end,
// like a Dragonfly that accepts and never answers.
type hungRegistry struct{}

func (hungRegistry) PutSession(ctx context.Context, _ string, _ Session, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}
func (hungRegistry) GetSession(ctx context.Context, _ string) (Session, bool, error) {
	<-ctx.Done()
	return Session{}, false, ctx.Err()
}
func (hungRegistry) BindClient(ctx context.Context, _ netip.AddrPort, _ string, _ time.Duration) error {
	<-ctx.Done()
	return ctx.Err()
}
func (hungRegistry) LookupClient(ctx context.Context, _ netip.AddrPort) (string, bool, error) {
	<-ctx.Done()
	return "", false, ctx.Err()
}
func (hungRegistry) DeleteClient(ctx context.Context, _ netip.AddrPort) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestRelayReadLoopNeverWaitsOnASlowSharedRegistry(t *testing.T) {
	bds := startBDS(t)
	r, relayAddr := startRelay(t, NewMemoryRegistry(), hungRegistry{}, defaultOpts(nil))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	c := newClient(t)
	stunPkt := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, stunPkt)
	bds.expect(t, stunPkt)

	for i := range 20 {
		send(t, newClient(t), relayAddr, dtlsData)
		send(t, newClient(t), relayAddr, signedBinding(fmt.Sprintf("zz%02d:QXyz", i), testPwd))
	}
	start := time.Now()
	send(t, c, relayAddr, dtlsData)
	select {
	case got := <-bds.got:
		assert.Equal(t, dtlsData, got)
		assert.Less(t, time.Since(start), 200*time.Millisecond, "a bound client waited on the shared registry")
	case <-time.After(15 * time.Second):
		t.Fatal("BDS got nothing")
	}
}

// countingRegistry counts lookups of client addresses and of sessions.
type countingRegistry struct {
	Registry
	lookups, gets atomic.Int32
}

func (c *countingRegistry) GetSession(ctx context.Context, pair string) (Session, bool, error) {
	c.gets.Add(1)
	return c.Registry.GetSession(ctx, pair)
}

func (c *countingRegistry) LookupClient(ctx context.Context, client netip.AddrPort) (string, bool, error) {
	c.lookups.Add(1)
	return c.Registry.LookupClient(ctx, client)
}

func TestRelayLooksUpOnlyDTLSShapedStrangersOncePerWindow(t *testing.T) {
	shared := &countingRegistry{Registry: NewMemoryRegistry()}
	_, relayAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))

	raknetPing := []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 1}
	stranger := newClient(t)
	send(t, stranger, relayAddr, raknetPing)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(0), shared.lookups.Load(), "a non-DTLS stranger costs no lookup")

	for range 5 {
		send(t, stranger, relayAddr, dtlsData)
	}
	assert.Eventually(t, func() bool { return shared.lookups.Load() == 1 }, time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(1), shared.lookups.Load(), "repeated junk from one address costs one lookup")
}

func TestRelayKeepsABoundAddressOnACheckForAnotherPair(t *testing.T) {
	bds1, bds2 := startBDS(t), startBDS(t)
	m := NewMetrics(prometheus.NewRegistry())
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(m))
	const pair2 = "9f3a:QXyz"
	require.NoError(t, r.Register(t.Context(), testPair, session(bds1)))
	require.NoError(t, r.Register(t.Context(), pair2, Session{ServerID: "srv-2", Target: bds2.addr, IcePwd: testPwd}))

	c := newClient(t)
	first := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, first)
	bds1.expect(t, first)
	expectReply(t, c, relayAddr, first)

	// A correctly signed check for another pair from the bound address (a spoofed
	// takeover, or a reused ip:port) must not move the address.
	send(t, c, relayAddr, signedBinding(pair2, testPwd))
	bds2.expectNothing(t)
	bds1.expectNothing(t)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.UDPDropped.WithLabelValues("pair_mismatch")))

	send(t, c, relayAddr, dtlsData)
	bds1.expect(t, dtlsData)
	pair, bound := r.boundPair(clientAddr(c))
	assert.True(t, bound)
	assert.Equal(t, testPair, pair)
	rs2 := r.activeSession(pair2)
	assert.True(t, rs2 != nil && rs2.upstream == nil, "the other pair stays signaled, not bound")
}

func TestRelayRebindDeletesTheOldClientKey(t *testing.T) {
	bds := startBDS(t)
	mr, shared := sharedRedis(t)
	r, relayAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	old, moved := newClient(t), newClient(t)
	for _, c := range []*net.UDPConn{old, moved} {
		p := signedBinding(testPair, testPwd)
		send(t, c, relayAddr, p)
		bds.expect(t, p)
		expectReply(t, c, relayAddr, p)
	}
	assert.Eventually(t, func() bool {
		return mr.Exists("nn:client:"+clientAddr(moved).String()) && !mr.Exists("nn:client:"+clientAddr(old).String())
	}, 2*time.Second, 10*time.Millisecond, "the shared registry holds only the new address")
}

// slowBindRegistry takes 30 ms per BindClient and records how many ran at once.
type slowBindRegistry struct {
	Registry
	mu            sync.Mutex
	running, peak int
	calls         int
	last          netip.AddrPort
}

func (s *slowBindRegistry) BindClient(ctx context.Context, client netip.AddrPort, pair string, ttl time.Duration) error {
	s.mu.Lock()
	s.running++
	s.calls++
	s.peak = max(s.peak, s.running)
	s.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	s.mu.Lock()
	s.running--
	s.last = client
	s.mu.Unlock()
	return s.Registry.BindClient(ctx, client, pair, ttl)
}

func TestRelayCoalescesSharedWritesOfARebindingSession(t *testing.T) {
	bds := startBDS(t)
	shared := &slowBindRegistry{Registry: NewMemoryRegistry()}
	r, relayAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil))
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))

	var latest netip.AddrPort
	for range 20 {
		c := newClient(t)
		p := signedBinding(testPair, testPwd)
		send(t, c, relayAddr, p)
		bds.expect(t, p)
		latest = clientAddr(c)
	}
	assert.Eventually(t, func() bool {
		shared.mu.Lock()
		defer shared.mu.Unlock()
		return shared.running == 0 && shared.last == latest
	}, 3*time.Second, 10*time.Millisecond, "the latest address wins")
	shared.mu.Lock()
	defer shared.mu.Unlock()
	assert.Equal(t, 1, shared.peak, "at most one shared write in flight per session")
	assert.Less(t, shared.calls, 20, "rebinds are coalesced")
}

func TestRelayServeLeavesNoGoroutinesWhenItsSocketCloses(t *testing.T) {
	settled := func(limit int) bool {
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if runtime.NumGoroutine() <= limit {
				return true
			}
		}
		return false
	}
	before := runtime.NumGoroutine()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	r, err := NewRelay(conn, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(nil))
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- r.Serve(t.Context()) }() // the context stays live
	time.Sleep(50 * time.Millisecond)
	_ = conn.Close()
	select {
	case err := <-done:
		assert.True(t, isClosed(err), "Serve returns the close, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return")
	}
	assert.True(t, settled(before), "workers and reaper exit with Serve: %d goroutines, %d before", runtime.NumGoroutine(), before)
}

// bindingWithUsername is an unsigned STUN binding request whose USERNAME is n bytes.
func bindingWithUsername(n int) []byte {
	attr := (4 + n + 3) &^ 3
	pkt := make([]byte, 20+attr)
	binary.BigEndian.PutUint16(pkt[0:], 0x0001)
	binary.BigEndian.PutUint16(pkt[2:], uint16(attr))
	binary.BigEndian.PutUint32(pkt[4:], stunMagicCookie)
	binary.BigEndian.PutUint16(pkt[20:], stunAttrUsername)
	binary.BigEndian.PutUint16(pkt[22:], uint16(n))
	for i := range n {
		pkt[24+i] = 'a'
	}
	return pkt
}

func TestRelayDropsAnOversizedUsernameWithoutALookup(t *testing.T) {
	m := NewMetrics(prometheus.NewRegistry())
	local, shared := &countingRegistry{Registry: NewMemoryRegistry()}, &countingRegistry{Registry: NewMemoryRegistry()}
	_, relayAddr := startRelay(t, local, shared, defaultOpts(m))
	pkt := bindingWithUsername(514)
	u, ok := STUNUsername(pkt)
	require.True(t, ok)
	require.Len(t, u, 514)

	send(t, newClient(t), relayAddr, pkt)
	assert.Eventually(t, func() bool { return testutil.ToFloat64(m.UDPDropped.WithLabelValues("bad_username")) == 1 },
		time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(0), local.gets.Load()+shared.gets.Load(), "an oversized USERNAME is never a lookup key")
}

func TestRelayCountsAFullQueueAsAQueueFullDrop(t *testing.T) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	m := NewMetrics(prometheus.NewRegistry())
	r, err := NewRelay(conn, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(m))
	require.NoError(t, err)
	for range sharedQueue { // no Serve, so nothing drains the queue
		r.jobs <- func(context.Context) {}
	}
	r.queuePublish(&relaySession{pair: testPair})
	assert.Equal(t, 1.0, testutil.ToFloat64(m.UDPDropped.WithLabelValues("queue_full")))
	assert.Equal(t, 0.0, testutil.ToFloat64(m.RegistryErrors), "a full queue is not a registry error")
}
