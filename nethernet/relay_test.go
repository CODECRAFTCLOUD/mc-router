package nethernet

import (
	"context"
	"fmt"
	"net"
	"net/netip"
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
	return RelayOptions{UnboundTTL: time.Minute, IdleTimeout: time.Minute, MaxSessions: 100, MaxSessionsPerServer: 100, Metrics: m}
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
	assert.Nil(t, r.activeSession(testPair))
	_, err := rs.upstream.Write([]byte{1})
	assert.True(t, isClosed(err), "upstream socket is closed, got %v", err)
}

func TestRelayRefusesBindsBeyondMaxSessions(t *testing.T) {
	bds := startBDS(t)
	m := NewMetrics(prometheus.NewRegistry())
	opt := defaultOpts(m)
	opt.MaxSessions = 1
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), opt)
	require.NoError(t, r.Register(t.Context(), testPair, session(bds)))
	require.NoError(t, r.Register(t.Context(), "2c69:Abcd", session(bds)))

	first := newClient(t)
	p1 := signedBinding(testPair, testPwd)
	send(t, first, relayAddr, p1)
	bds.expect(t, p1)

	second := newClient(t)
	send(t, second, relayAddr, signedBinding("2c69:Abcd", testPwd))
	bds.expectNothing(t)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.UDPDropped.WithLabelValues("session_cap")))
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
		assert.Less(t, time.Since(start), 50*time.Millisecond, "a bound client waited on the shared registry")
	case <-time.After(15 * time.Second):
		t.Fatal("BDS got nothing")
	}
}

// countingRegistry counts shared lookups of client addresses.
type countingRegistry struct {
	Registry
	lookups atomic.Int32
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

func TestRelayMovesABoundAddressToANewPairOnAVerifiedCheck(t *testing.T) {
	bds1, bds2 := startBDS(t), startBDS(t)
	r, relayAddr := startRelay(t, NewMemoryRegistry(), NewMemoryRegistry(), defaultOpts(nil))
	const pair2 = "9f3a:QXyz"
	require.NoError(t, r.Register(t.Context(), testPair, session(bds1)))
	require.NoError(t, r.Register(t.Context(), pair2, Session{ServerID: "srv-2", Target: bds2.addr, IcePwd: testPwd}))

	c := newClient(t)
	first := signedBinding(testPair, testPwd)
	send(t, c, relayAddr, first)
	bds1.expect(t, first)
	expectReply(t, c, relayAddr, first)

	// The same ip:port starts a new join (port-preserving NAT, a quick server switch).
	second := signedBinding(pair2, testPwd)
	send(t, c, relayAddr, second)
	bds2.expect(t, second)
	expectReply(t, c, relayAddr, second)
	bds1.expectNothing(t)
	pair, bound := r.boundPair(clientAddr(c))
	assert.True(t, bound)
	assert.Equal(t, pair2, pair)
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
