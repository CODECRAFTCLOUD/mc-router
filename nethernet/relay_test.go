package nethernet

import (
	"context"
	"net"
	"net/netip"
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
	stunPkt := signedBinding(testPair, testPwd)
	send(t, c, bAddr, stunPkt)
	bds.expect(t, stunPkt)
	expectReply(t, c, bAddr, stunPkt)
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

	// Failover: the next packet of the same client lands on B, and it is DTLS.
	send(t, c, bAddr, dtlsData)
	bds.expect(t, dtlsData)
	expectReply(t, c, bAddr, dtlsData)
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
