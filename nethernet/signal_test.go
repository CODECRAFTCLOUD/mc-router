package nethernet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sigPublic  = "82.26.104.95:19132"
	sigHost    = "survival.uniz.host"
	sigSvc     = "game/mc-a"
	sigLegacy  = 30042
	sigPodIP   = "10.0.0.3"
	sigMOTD    = `Sleeping "Survival" - join to wake`
	sigTarget  = "10.0.0.3:19140"
	sigServer  = "65f0c0ffee"
	sigPostURI = "/v1/join/1234567890"
)

// sigBackend is a fake BDS signaling port: GET answers a card, POST answers
// the captured SDP (or answer(), when set) and records what it got.
type sigBackend struct {
	srv    *httptest.Server
	addr   netip.AddrPort
	posts  atomic.Int32
	n      atomic.Int32
	mu     sync.Mutex
	host   string
	offer  string
	answer func(n int32) string
}

func startSigBackend(t *testing.T) *sigBackend {
	t.Helper()
	b := &sigBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b.mu.Lock()
		b.host, b.offer = r.Host, string(body)
		answer := b.answer
		b.mu.Unlock()
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"awake card"}`))
			return
		}
		b.posts.Add(1)
		w.Header().Set("Content-Type", "application/sdp")
		if answer != nil {
			_, _ = w.Write([]byte(answer(b.n.Add(1))))
			return
		}
		_, _ = w.Write([]byte(readGolden(t, "answer-bds-1.26.52.3.sdp")))
	}))
	t.Cleanup(b.srv.Close)
	b.addr = netip.MustParseAddrPort(b.srv.Listener.Addr().String())
	return b
}

func (b *sigBackend) setAnswer(f func(n int32) string) { b.mu.Lock(); b.answer = f; b.mu.Unlock() }

func (b *sigBackend) last() (host, offer string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.host, b.offer
}

// uniqueAnswers gives every POST its own server ufrag, so each join is its own pair.
func (b *sigBackend) uniqueAnswers(t *testing.T) {
	golden := readGolden(t, "answer-bds-1.26.52.3.sdp")
	b.setAnswer(func(n int32) string {
		return strings.Replace(golden, "a=ice-ufrag:2c69", fmt.Sprintf("a=ice-ufrag:%04d", n), 1)
	})
}

type sigWaker struct {
	mu        sync.Mutex
	calls     []Identity
	ports     []int
	deadlines []bool
	result    func(n int) (WakeResult, error)
	hang      bool // the API call runs until its context ends
}

func (w *sigWaker) Wake(ctx context.Context, legacyPort int, who Identity) (WakeResult, error) {
	w.mu.Lock()
	_, hasDeadline := ctx.Deadline()
	w.calls, w.ports, w.deadlines = append(w.calls, who), append(w.ports, legacyPort), append(w.deadlines, hasDeadline)
	n, f, hang := len(w.calls), w.result, w.hang
	w.mu.Unlock()
	if hang {
		<-ctx.Done()
		return WakeResult{}, fmt.Errorf("nethernet wake: %w", ctx.Err())
	}
	if f == nil {
		return WakeResult{Woken: true}, nil
	}
	return f(n)
}

func (w *sigWaker) count() int { w.mu.Lock(); defer w.mu.Unlock(); return len(w.calls) }

func (w *sigWaker) seen() ([]Identity, []int, []bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls, w.ports, w.deadlines
}

type sigFixture struct {
	backend *sigBackend
	routes  *RouteTable
	relay   *Relay
	waker   *sigWaker
	ident   *identFixture
	metrics *Metrics
	opts    SignalOptions
}

func newSigFixture(t *testing.T) *sigFixture {
	t.Helper()
	f := &sigFixture{backend: startSigBackend(t), routes: NewRouteTable(), waker: &sigWaker{}, ident: identSetup(t),
		metrics: NewMetrics(prometheus.NewRegistry())}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	f.relay, err = NewRelay(conn, NewMemoryRegistry(), nil, defaultOpts(nil))
	require.NoError(t, err)
	f.opts = SignalOptions{
		Routes: f.routes, Relay: f.relay, Waker: f.waker, PublicAddr: netip.MustParseAddrPort(sigPublic),
		TLSDomains: []string{"uniz.host", "mc.uniz.host"}, SignalPort: 19132,
		WakeHold: 2 * time.Second, ProbeTimeout: 300 * time.Millisecond, MaxBody: 1 << 20, RequestTimeout: 5 * time.Second,
		WakesPerPlayer: 5, WakeWindow: time.Hour, WakeBackoff: 5 * time.Second,
		PerIPRate: 5, GlobalRate: 200, LegacyRate: 200, Identity: f.ident.v, Metrics: f.metrics,
	}
	f.awake()
	return f
}

func (f *sigFixture) publish(podIPs []netip.Addr, legacy int) {
	f.routes.Upsert(sigSvc, []string{sigHost}, Backend{ServerID: sigServer, Addr: f.backend.addr, PodIPs: podIPs, LegacyPort: legacy, AsleepMOTD: sigMOTD})
}

func (f *sigFixture) awake()  { f.publish([]netip.Addr{netip.MustParseAddr(sigPodIP)}, sigLegacy) }
func (f *sigFixture) asleep() { f.publish(nil, sigLegacy) }

// serve runs a SignalServer on a loopback listener, passing localPort to
// ServeConn as the port the player dialed. tweak may adjust the server first.
func (f *sigFixture) serve(t *testing.T, localPort int, tweak ...func(*SignalServer)) string {
	t.Helper()
	s := NewSignalServer(f.opts)
	for _, fn := range tweak {
		fn(s)
	}
	return serveOn(t, s, localPort)
}

// serveOn runs s on a fresh loopback listener that stands for localPort, so
// one server can listen on the signal port and a legacy port at once.
func serveOn(t *testing.T, s *SignalServer, localPort int) string {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() { cancel(); _ = l.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { s.ServeConn(ctx, c, localPort) })
		}
	})
	return l.Addr().String()
}

type sigReq struct {
	method, uri, host, body string
	proxySrc                string // when set, a PROXY v2 header with this source IP comes first
	closeAfter              time.Duration
}

// do sends one request on a fresh connection and reads the response; resp is
// nil when the server closed the connection without one.
func sigDo(t *testing.T, addr string, r sigReq) (*http.Response, string) {
	t.Helper()
	c, err := net.Dial("tcp4", addr)
	require.NoError(t, err)
	defer c.Close()
	return sigDoOn(t, c, r)
}

func sigDoOn(t *testing.T, c net.Conn, r sigReq) (*http.Response, string) {
	t.Helper()
	if r.proxySrc != "" {
		h := proxyproto.HeaderProxyFromAddrs(2, &net.TCPAddr{IP: net.ParseIP(r.proxySrc), Port: 51000},
			&net.TCPAddr{IP: net.ParseIP("192.168.1.243"), Port: 19132})
		if _, err := h.WriteTo(c); err != nil {
			return nil, ""
		}
	}
	if r.method == "" {
		r.method = http.MethodPost
	}
	if r.uri == "" {
		r.uri = sigPostURI
		if r.method == http.MethodGet {
			r.uri = "/v1/join?version=1.26.70"
		}
	}
	if r.host == "" {
		r.host = sigHost + ":19132"
	}
	req, err := http.NewRequest(r.method, "http://"+r.host+r.uri, strings.NewReader(r.body))
	require.NoError(t, err)
	if r.body != "" {
		req.Header.Set("Content-Type", "application/sdp")
	}
	if err := req.Write(c); err != nil { // a refused connection may close before the request is sent
		return nil, ""
	}
	if r.closeAfter > 0 {
		time.Sleep(r.closeAfter)
		_ = c.Close()
		return nil, ""
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return nil, ""
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func (f *sigFixture) validOffer(t *testing.T) string { return f.ident.offer(t, nil) }

func (f *sigFixture) offerFor(t *testing.T, xuid string) string {
	return f.ident.offer(t, func(_, c map[string]any) { c["xid"] = xuid })
}

func candidates(sdp string) []string {
	var out []string
	for _, l := range strings.Split(sdp, "\r\n") {
		if strings.HasPrefix(l, "a=candidate:") {
			out = append(out, l)
		}
	}
	return out
}

func TestSignalRoutesByHostAndRewrites(t *testing.T) {
	f := newSigFixture(t)
	addr := f.serve(t, 19132)
	offer := f.validOffer(t)
	resp, body := sigDo(t, addr, sigReq{body: offer})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/sdp", resp.Header.Get("Content-Type"))
	assert.Equal(t, fmt.Sprint(len(body)), resp.Header.Get("Content-Length"), "Content-Length matches the rewritten body")
	assert.Equal(t, []string{"a=candidate:1 1 udp 2122260223 82.26.104.95 19132 typ host generation 0"}, candidates(body))
	assert.NotContains(t, body, sigPodIP, "no pod address leaks")
	host, got := f.backend.last()
	assert.Equal(t, sigHost+":19132", host, "the backend sees the original Host")
	assert.Equal(t, offer, got, "the offer is forwarded unchanged")

	rs := f.relay.activeSession("2c69:QXyz")
	require.NotNil(t, rs, "the pair serverUfrag:clientUfrag is registered")
	assert.Equal(t, netip.MustParseAddrPort(sigTarget), rs.s.Target)
	assert.Equal(t, sigServer, rs.s.ServerID)
	assert.Equal(t, "77jVAiq4D6YxKEPgZS2kvTfD", rs.s.IcePwd, "the server's ice-pwd signs the client's checks")
	assert.Equal(t, 0, f.waker.count(), "an awake server is never woken")
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.SignalingRequests.WithLabelValues("http", "answered")),
		"spec §6.9: a plain request is labelled http")
}

func TestSignalRoutesByLegacyPortWhenHostIsAnIP(t *testing.T) {
	f := newSigFixture(t)
	addr := f.serve(t, sigLegacy)
	resp, _ := sigDo(t, addr, sigReq{host: "82.26.104.95:30042", body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotNil(t, f.relay.activeSession("2c69:QXyz"))
}

// recordingConn keeps every byte the server sent.
type recordingConn struct {
	net.Conn
	mu  sync.Mutex
	got []byte
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.got = append(c.got, p[:n]...)
	c.mu.Unlock()
	return n, err
}

func TestSignalRefusesTLSForAForeignSNI(t *testing.T) {
	f := newSigFixture(t)
	f.opts.TLSCert = sigCert(t)
	addr := f.serve(t, 19132)
	raw, err := net.Dial("tcp4", addr)
	require.NoError(t, err)
	defer raw.Close()
	rec := &recordingConn{Conn: raw}
	err = tls.Client(rec, &tls.Config{ServerName: "play.hoin.gg", InsecureSkipVerify: true}).Handshake()
	require.Error(t, err)
	_ = raw.SetReadDeadline(time.Now().Add(2 * time.Second))
	rest, err := io.ReadAll(rec)
	assert.NoError(t, err, "the server closed the connection")
	assert.Empty(t, rest)
	assert.Equal(t, []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28}, rec.got, "exactly BDS's fatal handshake_failure alert")
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.TLSHandshakes.WithLabelValues("refused_sni")))
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.SignalingRequests.WithLabelValues("tls", "tls_refused")))
}

// sigCert is a self-signed certificate for *.uniz.host and *.mc.uniz.host.
func sigCert(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "*.uniz.host"},
		DNSNames:  []string{"*.uniz.host", "*.mc.uniz.host"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestSignalTerminatesTLSForOurDomain(t *testing.T) {
	f := newSigFixture(t)
	cert := sigCert(t)
	f.opts.TLSCert = cert
	f.asleep()
	addr := f.serve(t, 19132)
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	raw, err := net.Dial("tcp4", addr)
	require.NoError(t, err)
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{ServerName: sigHost, RootCAs: roots})
	resp, body := sigDoOn(t, c, sigReq{method: http.MethodGet})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, body, `"name":`)
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.TLSHandshakes.WithLabelValues("ok")))
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.SignalingRequests.WithLabelValues("tls", "asleep_card")),
		"spec §6.9: a request served over TLS is labelled tls")
}

// Spec §6.3: never present a certificate whose name does not match. A name
// under a TLS domain that the served certificate does not cover gets BDS's
// alert, so the client falls back to plain HTTP.
func TestSignalServesTLSOnlyForNamesTheCertificateCovers(t *testing.T) {
	f := newSigFixture(t)
	f.opts.TLSCert = sigCert(t) // *.uniz.host and *.mc.uniz.host
	addr := f.serve(t, 19132)
	for sni, served := range map[string]bool{
		"a.uniz.host": true, "a.mc.uniz.host": true, "x.y.uniz.host": false, "uniz.host": false,
	} {
		raw, err := net.Dial("tcp4", addr)
		require.NoError(t, err)
		rec := &recordingConn{Conn: raw}
		err = tls.Client(rec, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake() // the test judges the name itself
		if served {
			assert.NoError(t, err, sni)
		} else {
			assert.Error(t, err, sni)
			rec.mu.Lock()
			assert.Equal(t, tlsHandshakeFailure, rec.got, "%s gets BDS's handshake_failure alert", sni)
			rec.mu.Unlock()
		}
		_ = raw.Close()
	}
	assert.Equal(t, 2.0, testutil.ToFloat64(f.metrics.TLSHandshakes.WithLabelValues("refused_sni")))
}

// The certificate checked against the SNI is the one the handshake serves,
// even when the loader hands out another pair in between.
func TestSignalServesTheCertificateItChecked(t *testing.T) {
	f := newSigFixture(t)
	first, second := sigCert(t), sigCert(t)
	var calls atomic.Int32
	f.opts.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if calls.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	}
	addr := f.serve(t, 19132)
	raw, err := net.Dial("tcp4", addr)
	require.NoError(t, err)
	defer raw.Close()
	c := tls.Client(raw, &tls.Config{ServerName: "a.uniz.host", InsecureSkipVerify: true}) // the test compares the served cert itself
	require.NoError(t, c.Handshake())
	assert.Equal(t, first.Leaf.Raw, c.ConnectionState().PeerCertificates[0].Raw, "the pair that was checked is the pair served")
}

func TestSignalSynthesizesTheAsleepCard(t *testing.T) {
	f := newSigFixture(t)
	f.asleep()
	addr := f.serve(t, 19132)
	resp, body := sigDo(t, addr, sigReq{method: http.MethodGet})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	assert.JSONEq(t, `{"name":"Sleeping \"Survival\" - join to wake","level":"","players":0,"maxPlayers":0,"gameType":"Survival"}`, body)
	assert.Equal(t, 0, f.waker.count(), "the card never wakes")

	f.awake()
	resp, body = sigDo(t, addr, sigReq{method: http.MethodGet})
	require.NotNil(t, resp)
	assert.Equal(t, `{"name":"awake card"}`, body, "an awake server's card comes from BDS")
}

func TestSignalHoldsPostWhileWaking(t *testing.T) {
	f := newSigFixture(t)
	f.asleep()
	f.waker.result = func(int) (WakeResult, error) {
		time.AfterFunc(300*time.Millisecond, f.awake)
		return WakeResult{Woken: true}, nil
	}
	addr := f.serve(t, 19132)
	resp, body := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Len(t, candidates(body), 1)
	calls, ports, deadlines := f.waker.seen()
	require.Len(t, calls, 1)
	assert.Equal(t, Identity{XUID: "2535400000000001", Gamertag: "Synthetic Steve"}, calls[0], "the verified player goes to the API")
	assert.Equal(t, []int{sigLegacy}, ports)
	assert.Equal(t, []bool{true}, deadlines, "the wake call carries a deadline")
	assert.NotNil(t, f.relay.activeSession("2c69:QXyz"))
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("ready")))
}

func TestSignalAnswers503WhenTheWakeIsRefused(t *testing.T) {
	f := newSigFixture(t)
	f.asleep()
	f.waker.result = func(int) (WakeResult, error) { return WakeResult{}, errors.New("API refused: no credit") }
	addr := f.serve(t, 19132)
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, int32(0), f.backend.posts.Load())
}

func TestSignalAnswers503AfterTheHold(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakeHold = 200 * time.Millisecond
	f.asleep()
	addr := f.serve(t, 19132)
	start := time.Now()
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, 1, f.waker.count())
	assert.Equal(t, int32(0), f.backend.posts.Load(), "nothing reaches a backend that never became ready")
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout")))
}

// Gate 1 tells a player who hung up during the hold from a slow boot.
func TestSignalCountsAHangUpDuringTheHoldAsCancelled(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakeHold = 5 * time.Second // never ready
	f.asleep()
	addr := f.serve(t, 19132)
	sigDo(t, addr, sigReq{body: f.validOffer(t), closeAfter: 300 * time.Millisecond})
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("cancelled")) == 1
	}, 3*time.Second, 20*time.Millisecond, "the hang-up ends the hold as cancelled")
	assert.Equal(t, 1, f.waker.count(), "the wake was called before the hang-up")
	assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout")))
}

// A hang-up while the wake API call itself runs is cancelled, and the hold
// running out during it is a timeout; neither is the API refusing.
func TestSignalLabelsAWakeCallCutShortByWhyItEnded(t *testing.T) {
	t.Run("the player hung up", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.WakeHold = 5 * time.Second
		f.asleep()
		f.waker.hang = true
		addr := f.serve(t, 19132)
		sigDo(t, addr, sigReq{body: f.validOffer(t), closeAfter: 300 * time.Millisecond})
		require.Eventually(t, func() bool {
			return testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("cancelled")) == 1
		}, 3*time.Second, 20*time.Millisecond)
		assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("refused")))
	})
	t.Run("the hold ran out", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.WakeHold = 300 * time.Millisecond
		f.asleep()
		f.waker.hang = true
		addr := f.serve(t, 19132)
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout")))
		assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("refused")))
	})
	t.Run("a plain error is refused", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.WakeHold = 5 * time.Second
		f.asleep()
		f.waker.result = func(int) (WakeResult, error) { return WakeResult{}, errors.New("nethernet wake: API returned 502") }
		addr := f.serve(t, 19132)
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("refused")))
		assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout")))
		assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("cancelled")))
	})
}

func TestSignalHoldsWhenAlreadyBooting(t *testing.T) {
	f := newSigFixture(t)
	f.asleep()
	f.waker.result = func(int) (WakeResult, error) {
		time.AfterFunc(300*time.Millisecond, f.awake)
		return WakeResult{Booting: true}, nil
	}
	addr := f.serve(t, 19132)
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "a booting server is waited for, not refused")
}

func TestSignalRefusesToWakeWithoutAVerifiedIdentity(t *testing.T) {
	f := newSigFixture(t)
	f.asleep()
	addr := f.serve(t, 19132)
	junk := identLineRE.ReplaceAllString(f.validOffer(t), "a=identity:bm90LWEtdG9rZW4=\r")
	none := identLineRE.ReplaceAllString(f.validOffer(t), "a=ice-options:trickle\r")
	for name, offer := range map[string]string{"junk": junk, "none": none} {
		resp, _ := sigDo(t, addr, sigReq{body: offer})
		require.NotNil(t, resp, name)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode, name)
	}
	assert.Equal(t, 0, f.waker.count(), "a forged join never reaches the wake API")
	assert.Equal(t, 2.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("identity_rejected")))
}

func TestSignalNeverVerifiesIdentityForAnAwakeServer(t *testing.T) {
	f := newSigFixture(t)
	addr := f.serve(t, 19132)
	junk := identLineRE.ReplaceAllString(f.validOffer(t), "a=identity:bm90LWEtdG9rZW4=\r")
	resp, _ := sigDo(t, addr, sigReq{body: junk})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "BDS checks identity itself")
	_, got := f.backend.last()
	assert.Equal(t, junk, got)
}

func TestSignalRefusesARelayTargetThatIsNotThePod(t *testing.T) {
	f := newSigFixture(t)
	f.publish([]netip.Addr{netip.MustParseAddr("10.0.0.9")}, sigLegacy) // the answer names 10.0.0.3, not this pod
	addr := f.serve(t, 19132)
	resp, body := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.NotContains(t, body, "a=candidate")
	assert.Nil(t, f.relay.activeSession("2c69:QXyz"), "nothing is registered")
}

// R25: while the first Service answers, the host moves to a second Service
// whose pod is the address the answer names. That pod must not vouch for an
// answer the first Service wrote.
func TestSignalChecksTheAnswerOnlyAgainstTheServiceThatAnswered(t *testing.T) {
	f := newSigFixture(t)
	f.publish([]netip.Addr{netip.MustParseAddr("10.0.0.9")}, sigLegacy) // game/mc-a: not the answer's 10.0.0.3
	golden := readGolden(t, "answer-bds-1.26.52.3.sdp")
	f.backend.setAnswer(func(int32) string {
		// game/mc-b sorts above game/mc-a, so it now wins the host.
		f.routes.Upsert("game/mc-b", []string{sigHost}, Backend{ServerID: "other", Addr: netip.MustParseAddrPort("10.0.0.3:19132"),
			PodIPs: []netip.Addr{netip.MustParseAddr(sigPodIP)}, LegacyPort: sigLegacy + 1})
		return golden
	})
	addr := f.serve(t, 19132)
	resp, body := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.NotContains(t, body, "a=candidate")
	assert.Nil(t, f.relay.activeSession("2c69:QXyz"), "nothing is registered")
	b, _ := f.routes.ByHost(sigHost)
	require.Equal(t, "other", b.ServerID, "the route did move mid-POST")
}

func TestSignalLimitsWakesPerPlayer(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakeHold = 50 * time.Millisecond // never ready: each join ends in 503 after its wake
	f.asleep()
	f.waker.result = func(call int) (WakeResult, error) {
		switch call {
		case 1:
			return WakeResult{Booting: true}, nil // not an actual wake
		case 2:
			return WakeResult{Message: "no credit"}, nil // a clear refusal: not an actual wake
		}
		return WakeResult{Woken: true}, nil
	}
	clk := &identClock{t: time.Now()}
	addr := f.serve(t, 19132, func(s *SignalServer) { s.now = clk.now })
	offer := f.offerFor(t, "2535400000000777")
	for i := range 7 {
		resp, _ := sigDo(t, addr, sigReq{body: offer})
		require.NotNil(t, resp, i)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, i)
		clk.add(f.opts.WakeBackoff) // past the port's wake back-off (M-5), well inside the hour
	}
	assert.Equal(t, 7, f.waker.count(), "2 non-wakes + 5 actual wakes reach the API")
	resp, _ := sigDo(t, addr, sigReq{body: offer})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, 7, f.waker.count(), "the 6th actual wake from one player is refused before the API")
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("player_limit")))

	resp, _ = sigDo(t, addr, sigReq{body: f.offerFor(t, "2535400000000888")})
	require.NotNil(t, resp)
	assert.Equal(t, 8, f.waker.count(), "another player still wakes")
}

// Spec §6.7: identity is verified before the back-off is read. A port primed
// with a cached answer still refuses a bad identity with 403, holds nothing
// and calls nothing.
func TestSignalVerifiesIdentityBeforeTheBackOff(t *testing.T) {
	for name, primed := range map[string]WakeResult{"booting": {Booting: true}, "refusal": {Message: "no credit"}} {
		t.Run(name, func(t *testing.T) {
			f := newSigFixture(t)
			f.opts.WakeHold = 200 * time.Millisecond // never ready
			f.asleep()
			f.waker.result = func(int) (WakeResult, error) { return primed, nil }
			addr := f.serve(t, 19132, func(s *SignalServer) { at := time.Now(); s.now = func() time.Time { return at } })
			resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
			require.NotNil(t, resp)
			require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "the verified join primes the port")
			require.Equal(t, 1, f.waker.count())
			holds := testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout"))

			junk := identLineRE.ReplaceAllString(f.validOffer(t), "a=identity:bm90LWEtdG9rZW4=\r")
			start := time.Now()
			resp, _ = sigDo(t, addr, sigReq{body: junk})
			require.NotNil(t, resp)
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)
			assert.Less(t, time.Since(start), 150*time.Millisecond, "not held")
			assert.Equal(t, 1, f.waker.count(), "no API call")
			assert.Equal(t, holds, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout")), "no hold")
			assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("identity_rejected")))
		})
	}
}

// Ruling M-5: after a wake call for a legacy port answers booting or a
// refusal, the API is not called for that port again for 5 s, so one lifted
// identity assertion cannot drive a wake-API call per join.
func TestSignalBacksOffTheWakeAPIPerPort(t *testing.T) {
	t.Run("a refusal answers 503 from the cached answer", func(t *testing.T) {
		f := newSigFixture(t)
		f.asleep()
		f.waker.result = func(int) (WakeResult, error) { return WakeResult{Message: "no credit"}, nil }
		clk := &identClock{t: time.Now()}
		addr := f.serve(t, 19132, func(s *SignalServer) { s.now = clk.now })
		for i := range 2 {
			resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
			require.NotNil(t, resp, i)
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, i)
		}
		assert.Equal(t, 1, f.waker.count(), "two joins within 5 s make one API call")
		assert.Equal(t, 2.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("refused")))

		clk.add(5 * time.Second)
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp)
		assert.Equal(t, 2, f.waker.count(), "after 5 s the API is asked again")
	})
	t.Run("booting goes straight to the hold", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.WakeHold = 200 * time.Millisecond // never ready
		f.asleep()
		f.waker.result = func(int) (WakeResult, error) { return WakeResult{Booting: true}, nil }
		clk := &identClock{t: time.Now()}
		addr := f.serve(t, 19132, func(s *SignalServer) { s.now = clk.now })
		for i := range 2 {
			resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
			require.NotNil(t, resp, i)
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, i)
		}
		assert.Equal(t, 1, f.waker.count(), "two joins within 5 s make one API call")
		assert.Equal(t, 2.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout")), "both joins were held")
		assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("refused")))
	})
	t.Run("an API failure is not cached", func(t *testing.T) {
		var calls atomic.Int32
		api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		t.Cleanup(api.Close)
		f := newSigFixture(t)
		f.asleep()
		f.opts.Waker = NewAPIWaker(api.URL, "router-token", api.Client())
		addr := f.serve(t, 19132, func(s *SignalServer) { at := time.Now(); s.now = func() time.Time { return at } })
		for i := range 2 {
			resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
			require.NotNil(t, resp, i)
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, i)
		}
		assert.Equal(t, int32(2), calls.Load(), "an API 500 is not a refusal: the next join within 5 s asks again")
	})
	t.Run("the back-off is per port", func(t *testing.T) {
		f := newSigFixture(t)
		f.asleep()
		f.routes.Upsert("game/mc-other", []string{"other.uniz.host"}, Backend{ServerID: "other", Addr: f.backend.addr, LegacyPort: sigLegacy + 1})
		f.waker.result = func(int) (WakeResult, error) { return WakeResult{Message: "manually stopped"}, nil }
		addr := f.serve(t, 19132, func(s *SignalServer) { at := time.Now(); s.now = func() time.Time { return at } })
		sigDo(t, addr, sigReq{body: f.validOffer(t)})
		sigDo(t, addr, sigReq{host: "other.uniz.host:19132", body: f.validOffer(t)})
		_, ports, _ := f.waker.seen()
		assert.Equal(t, []int{sigLegacy, sigLegacy + 1}, ports)
	})
}

// The per-player wake limit, its window and the port back-off are options
// (spec §6.8), and the server uses the values it is given.
func TestSignalUsesTheConfiguredWakeLimits(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakesPerPlayer, f.opts.WakeWindow, f.opts.WakeBackoff = 2, 10*time.Minute, 2*time.Second
	s := NewSignalServer(f.opts)
	t0 := time.Now()
	for i := range 2 {
		_, ok := s.wakes.reserve("x", t0)
		require.True(t, ok, i)
	}
	_, ok := s.wakes.reserve("x", t0)
	assert.False(t, ok, "the 3rd wake is over a limit of 2")
	_, ok = s.wakes.reserve("x", t0.Add(10*time.Minute))
	assert.True(t, ok, "a 10-minute window has passed")

	s.backoff.put(sigLegacy, cachedWake{at: t0, res: WakeResult{Booting: true}})
	_, cached := s.backoff.get(sigLegacy, t0.Add(time.Second))
	assert.True(t, cached, "inside a 2 s back-off")
	_, cached = s.backoff.get(sigLegacy, t0.Add(2*time.Second))
	assert.False(t, cached, "a 2 s back-off is over")
}

// R34 is a rolling hour: a wake stops counting an hour after it.
func TestWakeLimiterForgetsAWakeAfterAnHour(t *testing.T) {
	l := newWakeLimiter(5, time.Hour)
	t0 := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	for i := range 5 {
		_, ok := l.reserve("x", t0.Add(time.Duration(i)*time.Minute))
		require.True(t, ok, i)
	}
	_, ok := l.reserve("x", t0.Add(59*time.Minute))
	assert.False(t, ok, "the 6th wake inside the hour is refused")
	_, ok = l.reserve("x", t0.Add(time.Hour))
	assert.True(t, ok, "an hour after the first wake, it no longer counts")
	_, ok = l.reserve("x", t0.Add(time.Hour+30*time.Second))
	assert.False(t, ok, "the second wake still counts until its own hour is up")
}

// The minute sweep drops players with no wake in the last hour, so the map
// holds only players seen this hour.
func TestWakeLimiterSweepsPlayersWithNoWakeThisHour(t *testing.T) {
	l := newWakeLimiter(5, time.Hour)
	t0 := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	l.reserve("old", t0)
	l.reserve("recent", t0.Add(30*time.Minute))
	l.reserve("new", t0.Add(time.Hour+time.Minute))
	assert.ElementsMatch(t, []string{"recent", "new"}, slices.Collect(maps.Keys(l.byXUID)), "an hour-old player is swept")

	l.reserve("late", t0.Add(time.Hour+time.Minute+30*time.Second+30*time.Minute))
	assert.Contains(t, l.byXUID, "late")
	assert.NotContains(t, l.byXUID, "recent", "swept once its wake is an hour old")
}

// Ruling C-1: only a clear answer from the API (not woken) hands the wake
// back. On an error or a cancellation the API may still have woken the
// server, so the wake stays counted against the player. (A clear refusal and
// a booting answer handing it back: TestSignalLimitsWakesPerPlayer.)
func TestSignalKeepsAWakeCountedWhenTheAPIGaveNoClearAnswer(t *testing.T) {
	limitOne := func(t *testing.T) (*sigFixture, string) {
		f := newSigFixture(t)
		f.opts.WakesPerPlayer = 1
		f.asleep()
		addr := f.serve(t, 19132, func(s *SignalServer) { at := time.Now(); s.now = func() time.Time { return at } })
		return f, addr
	}
	t.Run("an error", func(t *testing.T) {
		f, addr := limitOne(t)
		f.waker.result = func(int) (WakeResult, error) { return WakeResult{}, errors.New("nethernet wake: API returned 502") }
		for i := range 2 {
			resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
			require.NotNil(t, resp, i)
			assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, i)
		}
		assert.Equal(t, 1, f.waker.count(), "the second join is over the player's limit, before the API")
		assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("player_limit")))
	})
	t.Run("a cancellation", func(t *testing.T) {
		f, addr := limitOne(t)
		f.waker.hang = true
		sigDo(t, addr, sigReq{body: f.validOffer(t), closeAfter: 300 * time.Millisecond})
		require.Eventually(t, func() bool {
			return testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("cancelled")) == 1
		}, 3*time.Second, 20*time.Millisecond)
		f.waker.mu.Lock()
		f.waker.hang = false
		f.waker.mu.Unlock()
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		assert.Equal(t, 1, f.waker.count(), "the second join is over the player's limit, before the API")
		assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("player_limit")))
	})
}

// Ruling C-6: a dial failure never reached the API, so nothing was woken and
// the wake goes back to the player; nothing is cached either.
func TestSignalHandsBackAWakeTheAPINeverReceived(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakeHold = 50 * time.Millisecond // never ready: the 6th join ends in 503 after its wake
	f.asleep()
	f.waker.result = func(call int) (WakeResult, error) {
		if call <= 5 {
			dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
			return WakeResult{}, fmt.Errorf("nethernet wake: %w", &url.Error{Op: "Post", URL: "http://uniz-api", Err: dial})
		}
		return WakeResult{Woken: true}, nil
	}
	addr := f.serve(t, 19132)
	for i := range 6 {
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp, i)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, i)
	}
	assert.Equal(t, 6, f.waker.count(), "5 dial failures did not use the player's 5 wakes")
	assert.Equal(t, 5.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("refused")))
	assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("player_limit")))
}

// The API received the request and the hold ran out before it answered: it
// may still wake the server, so the wake stays counted (C-1, not C-6).
func TestSignalKeepsAWakeCountedWhenTheAPITimedOutAfterTheRequest(t *testing.T) {
	var got atomic.Int32
	release := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(api.Close)
	t.Cleanup(func() { close(release) }) // runs before api.Close, which waits for the handler
	f := newSigFixture(t)
	f.opts.WakesPerPlayer = 1
	f.opts.WakeHold = 300 * time.Millisecond
	f.opts.Waker = NewAPIWaker(api.URL, "t", api.Client())
	f.asleep()
	addr := f.serve(t, 19132)
	for i := range 2 {
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp, i)
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, i)
	}
	assert.Equal(t, int32(1), got.Load(), "the second join is over the player's limit, before the API")
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("timeout")))
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("player_limit")))
}

func TestSignalAnswers503ForALegacyPortZeroWithoutCallingTheAPI(t *testing.T) {
	f := newSigFixture(t)
	f.publish(nil, 0)
	addr := f.serve(t, 19132)
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Equal(t, 0, f.waker.count())
}

func TestSignalTurnsARefusedWakeInto503(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakeHold = 5 * time.Second
	f.asleep()
	f.waker.result = func(int) (WakeResult, error) { return WakeResult{Message: "idle-only"}, nil }
	addr := f.serve(t, 19132)
	start := time.Now()
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Less(t, time.Since(start), time.Second, "no hold")
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.WakeHolds.WithLabelValues("refused")))
}

// slowJWKS makes the verifier's cold-cache fetch take d.
func (f *sigFixture) slowJWKS(t *testing.T, d time.Duration) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(d)
		_, _ = w.Write(*f.ident.jwks.body.Load())
	}))
	t.Cleanup(slow.Close)
	f.ident.v = NewIdentityVerifier(slow.URL, slow.Client(), f.ident.clock.now)
	f.opts.Identity = f.ident.v
}

func TestSignalNeverWakesAJoinCancelledDuringVerify(t *testing.T) {
	f := newSigFixture(t)
	f.slowJWKS(t, 600*time.Millisecond)
	f.asleep()
	addr := f.serve(t, 19132)
	sigDo(t, addr, sigReq{body: f.validOffer(t), closeAfter: 100 * time.Millisecond})
	time.Sleep(time.Second) // Verify ends (it ignores cancellation) and the handler decides
	assert.Equal(t, 0, f.waker.count(), "a join the player gave up on never wakes the server")
}

func TestSignalBudgetsVerifyInsideTheHold(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakeHold = 300 * time.Millisecond
	f.slowJWKS(t, 500*time.Millisecond)
	f.asleep()
	addr := f.serve(t, 19132)
	start := time.Now()
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Less(t, time.Since(start), 900*time.Millisecond, "the hold ends WakeHold after the join, not after Verify")
	assert.Equal(t, 0, f.waker.count(), "no wake once the hold is spent")
}

func TestSignalRegistersTheRealClientIP(t *testing.T) {
	t.Run("PROXY header from a trusted proxy", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
		addr := f.serve(t, 19132)
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t), proxySrc: "203.0.113.7"})
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		rs := f.relay.activeSession("2c69:QXyz")
		require.NotNil(t, rs)
		assert.Equal(t, netip.MustParseAddr("203.0.113.7"), rs.s.SignalIP)
		assert.True(t, rs.s.SignalIPTrusted)
	})
	t.Run("an untrusted peer is the client itself", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.77.77.0/24")}
		addr := f.serve(t, 19132)
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		rs := f.relay.activeSession("2c69:QXyz")
		require.NotNil(t, rs)
		assert.Equal(t, netip.MustParseAddr("127.0.0.1"), rs.s.SignalIP)
		assert.True(t, rs.s.SignalIPTrusted)
	})
}

func TestSignalIgnoresAPROXYHeaderFromAnUntrustedPeer(t *testing.T) {
	f := newSigFixture(t)
	f.opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.77.77.0/24")}
	addr := f.serve(t, 19132)
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t), proxySrc: "203.0.113.7"})
	if resp != nil {
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	}
	assert.Nil(t, f.relay.activeSession("2c69:QXyz"), "a forged source is never registered")
}

func TestSignalTrustedProxyWithoutHeaderIsNotPerIPLimited(t *testing.T) {
	f := newSigFixture(t)
	f.opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	f.relay.opt.MaxPerIPPerServer = 2
	f.opts.PerIPRate = 1
	f.backend.uniqueAnswers(t)
	addr := f.serve(t, 19132, func(s *SignalServer) { at := time.Now(); s.now = func() time.Time { return at } })
	offer := f.validOffer(t)
	for i := range 20 {
		resp, _ := sigDo(t, addr, sigReq{body: offer})
		require.NotNil(t, resp, i)
		require.Equal(t, http.StatusOK, resp.StatusCode, i)
		rs := f.relay.activeSession(fmt.Sprintf("%04d:QXyz", i+1))
		require.NotNil(t, rs, i)
		assert.False(t, rs.s.SignalIPTrusted, i)
	}
}

func TestSignalLegacyJoinsAreNotPerIPLimited(t *testing.T) {
	f := newSigFixture(t)
	f.relay.opt.MaxPerIPPerServer = 2
	f.opts.PerIPRate = 1
	f.backend.uniqueAnswers(t)
	addr := f.serve(t, sigLegacy, func(s *SignalServer) { at := time.Now(); s.now = func() time.Time { return at } })
	offer := f.validOffer(t)
	for i := range 20 {
		resp, _ := sigDo(t, addr, sigReq{host: "82.26.104.95:30042", body: offer})
		require.NotNil(t, resp, i)
		require.Equal(t, http.StatusOK, resp.StatusCode, i)
		rs := f.relay.activeSession(fmt.Sprintf("%04d:QXyz", i+1))
		require.NotNil(t, rs, i)
		assert.False(t, rs.s.SignalIPTrusted, i)
	}
}

func TestSignalNeverReturnsAnUnrewrittenAnswer(t *testing.T) {
	f := newSigFixture(t)
	golden := readGolden(t, "answer-bds-1.26.52.3.sdp")
	var only []string
	for _, l := range strings.Split(golden, "\r\n") {
		if !strings.HasPrefix(l, "a=candidate:") {
			only = append(only, l)
		}
		if strings.HasPrefix(l, "c=IN IP4") {
			only = append(only, "a=candidate:1 1 udp 2122260223 127.0.0.1 19140 typ host generation 0")
		}
	}
	f.backend.setAnswer(func(int32) string { return strings.Join(only, "\r\n") })
	f.publish([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, sigLegacy)
	addr := f.serve(t, 19132)
	resp, body := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
	assert.NotContains(t, body, "127.0.0.1")
	assert.Nil(t, f.relay.activeSession("2c69:QXyz"))
}

func TestSignal404sUnknownHostsAndPaths(t *testing.T) {
	f := newSigFixture(t)
	addr := f.serve(t, 19132)
	for _, r := range []sigReq{
		{method: http.MethodGet, host: "unknown.uniz.host:19132"},
		{host: "unknown.uniz.host:19132", body: "x"},
		{method: http.MethodGet, uri: "/"},
		{method: http.MethodGet, uri: "/v1/joinx"},
		{uri: "/v1/join/abc", body: "x"},
		{uri: "/v1/join/", body: "x"},
		{method: http.MethodPut, uri: sigPostURI, body: "x"},
		{method: http.MethodPost, uri: "/v1/join", body: "x"},
	} {
		resp, _ := sigDo(t, addr, r)
		require.NotNil(t, resp, r)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode, r)
	}
	assert.Equal(t, int32(0), f.backend.posts.Load())
}

func TestSignalRejectsAnOversizedBody(t *testing.T) {
	f := newSigFixture(t)
	f.opts.MaxBody = 1024
	addr := f.serve(t, 19132)
	resp, _ := sigDo(t, addr, sigReq{body: strings.Repeat("a", 2048)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	assert.Equal(t, int32(0), f.backend.posts.Load())
}

func TestSignalRateLimitsPerIP(t *testing.T) {
	f := newSigFixture(t)
	f.opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	f.asleep()
	frozen := func(s *SignalServer) { at := time.Now(); s.now = func() time.Time { return at } }
	addr := f.serve(t, 19132, frozen)
	card := func(src string) *http.Response {
		resp, _ := sigDo(t, addr, sigReq{method: http.MethodGet, proxySrc: src})
		return resp
	}
	for i := range 20 {
		require.NotNil(t, card("203.0.113.7"), "burst request %d", i+1)
	}
	assert.Nil(t, card("203.0.113.7"), "the 21st burst request from one IP is refused")
	assert.NotNil(t, card("203.0.113.8"), "another IP still passes")
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.SignalingRequests.WithLabelValues("", "rate_limited")),
		"refused before a byte is read: the transport is not known")

	t.Run("legacy listener: only the global tier", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.PerIPRate = 1
		f.asleep()
		addr := f.serve(t, sigLegacy, frozen)
		for i := range 30 {
			resp, _ := sigDo(t, addr, sigReq{method: http.MethodGet, host: "82.26.104.95:30042"})
			require.NotNil(t, resp, "legacy request %d", i+1)
		}
	})
	t.Run("the global tier", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.GlobalRate = 2 // burst 4
		f.asleep()
		addr := f.serve(t, 19132, frozen)
		passed := 0
		for range 8 {
			if resp, _ := sigDo(t, addr, sigReq{method: http.MethodGet}); resp != nil {
				passed++
			}
		}
		assert.Equal(t, 4, passed, "the global burst")
	})
	t.Run("the legacy tier", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.LegacyRate = 2 // burst 4
		f.asleep()
		addr := f.serve(t, sigLegacy, frozen)
		passed := 0
		for range 8 {
			if resp, _ := sigDo(t, addr, sigReq{method: http.MethodGet, host: "82.26.104.95:30042"}); resp != nil {
				passed++
			}
		}
		assert.Equal(t, 4, passed, "the legacy burst")
	})
}

// Review I-1 (probe A): the legacy listeners spend a bucket of their own, so a
// flood from one source on a pool port never refuses a join on the signal port.
func TestSignalALegacyFloodLeavesTheSignalPortAlone(t *testing.T) {
	f := newSigFixture(t)
	f.opts.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	f.asleep()
	s := NewSignalServer(f.opts)
	at := time.Now()
	s.now = func() time.Time { return at }
	signal, legacy := serveOn(t, s, 19132), serveOn(t, s, sigLegacy)

	for range 410 { // the legacy burst (400) and ten more, all empty
		c, err := net.Dial("tcp4", legacy)
		require.NoError(t, err)
		_ = c.Close()
	}
	limited := f.metrics.SignalingRequests.WithLabelValues("", "rate_limited")
	require.Eventually(t, func() bool { return testutil.ToFloat64(limited) == 10 }, 5*time.Second, 10*time.Millisecond,
		"every flood connection was counted against a bucket")

	resp, _ := sigDo(t, signal, sigReq{method: http.MethodGet, proxySrc: "198.51.100.9"})
	require.NotNil(t, resp, "a fresh player on the signal port is not refused")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp, _ = sigDo(t, legacy, sigReq{method: http.MethodGet, host: "82.26.104.95:30042"})
	assert.Nil(t, resp, "the legacy bucket itself stays bounded")
}

func TestSignalAnswers503AtTheSessionCap(t *testing.T) {
	f := newSigFixture(t)
	f.relay.opt.MaxSessionsPerServer = 1
	f.backend.uniqueAnswers(t)
	addr := f.serve(t, 19132)
	resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp, body := sigDo(t, addr, sigReq{body: f.validOffer(t)})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.False(t, bytes.Contains([]byte(body), []byte("a=candidate")))
}

// Spec §14 seam (review M-4): one join through both halves. The POST goes
// through the signal server, and the check the client then signs from the
// rewritten answer reaches the fake BDS through the relay's own socket. The
// relay never dials loopback, so its dial to the pod address is pointed at the
// fake BDS, standing in for the pod network.
func TestSignalAndRelayCarryOneJoinEndToEnd(t *testing.T) {
	f := newSigFixture(t)
	bds := startBDS(t)
	dialed := make(chan netip.AddrPort, 1)
	relay, relayAddr := startRelay(t, NewMemoryRegistry(), nil, defaultOpts(nil), func(r *Relay) {
		r.dialUpstream = func(to netip.AddrPort) (*net.UDPConn, error) {
			dialed <- to
			return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bds.addr))
		}
	})
	f.opts.Relay, f.opts.PublicAddr = relay, relayAddr

	offer := f.validOffer(t)
	resp, body := sigDo(t, f.serve(t, 19132), sigReq{body: offer})
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	off, err := ParseSDP(offer)
	require.NoError(t, err)
	ans, err := ParseSDP(body)
	require.NoError(t, err)
	require.Len(t, ans.Candidates, 1)
	require.Equal(t, relayAddr, ans.Candidates[0].Addr, "the answer points the client at the relay")

	c := newClient(t)
	pair := ans.IceUfrag + ":" + off.IceUfrag // RFC 8445: the remote ufrag first
	check := signedBinding(pair, ans.IcePwd)
	send(t, c, ans.Candidates[0].Addr, check)
	bds.expect(t, check)
	expectReply(t, c, relayAddr, check)
	assert.Equal(t, netip.MustParseAddrPort(sigTarget), <-dialed, "the relay targets the answer's candidate at the pod")
	got, bound := relay.boundPair(clientAddr(c))
	assert.True(t, bound)
	assert.Equal(t, pair, got)
	send(t, c, relayAddr, dtlsData)
	bds.expect(t, dtlsData)
}

// Gate 1 across the seam: the POST lands on replica A, the client's checks on
// replica B, which adopts the session from the shared registry. B's first
// forwarded check nominates its own address, signed with the answer's ice-pwd.
func TestSignalAndAnAdoptingRelayNominateTheNewPath(t *testing.T) {
	f := newSigFixture(t)
	bds := startBDS(t)
	_, shared := sharedRedis(t)
	toBDS := func(r *Relay) {
		r.dialUpstream = func(netip.AddrPort) (*net.UDPConn, error) {
			return net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(bds.addr))
		}
	}
	a, aAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil), toBDS)
	_, bAddr := startRelay(t, NewMemoryRegistry(), shared, defaultOpts(nil), toBDS)
	f.opts.Relay, f.opts.PublicAddr = a, aAddr

	offer := f.validOffer(t)
	resp, body := sigDo(t, f.serve(t, 19132), sigReq{body: offer})
	require.NotNil(t, resp)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	off, err := ParseSDP(offer)
	require.NoError(t, err)
	ans, err := ParseSDP(body)
	require.NoError(t, err)

	pair := ans.IceUfrag + ":" + off.IceUfrag
	got := sendUntilBDS(t, newClient(t), bAddr, controllingBinding(pair, ans.IcePwd), bds)
	assertNominates(t, got, ans.IcePwd)
}

// noPodAnswer is the golden answer with its pod candidate moved off the pod
// address and its own server ufrag: BDS's answer while its NetherNet transport
// is still starting (prod, Gate 1, 2026-10-15).
func noPodAnswer(t *testing.T, n int32) string {
	golden := readGolden(t, "answer-bds-1.26.52.3.sdp")
	golden = strings.Replace(golden, "10.0.0.3 19140", "10.0.0.77 19140", 1)
	return strings.Replace(golden, "a=ice-ufrag:2c69", fmt.Sprintf("a=ice-ufrag:%04d", n), 1)
}

func fastRetry(d time.Duration) func(*SignalServer) {
	return func(s *SignalServer) { s.answerRetry = d }
}

func TestSignalRetriesTheOfferUntilTheAnswerNamesThePod(t *testing.T) {
	f := newSigFixture(t)
	golden := readGolden(t, "answer-bds-1.26.52.3.sdp")
	var offers []string
	f.backend.setAnswer(func(n int32) string {
		_, got := f.backend.last()
		offers = append(offers, got)
		if n <= 2 {
			return noPodAnswer(t, n)
		}
		return strings.Replace(golden, "a=ice-ufrag:2c69", fmt.Sprintf("a=ice-ufrag:%04d", n), 1)
	})
	addr := f.serve(t, 19132, fastRetry(20*time.Millisecond))
	offer := f.validOffer(t)
	resp, body := sigDo(t, addr, sigReq{body: offer})
	require.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, []string{"a=candidate:1 1 udp 2122260223 82.26.104.95 19132 typ host generation 0"}, candidates(body))
	assert.Contains(t, body, "a=ice-ufrag:0003", "the client gets the answer that named the pod")
	assert.Equal(t, int32(3), f.backend.posts.Load())
	require.Len(t, offers, 3)
	for i, o := range offers {
		assert.True(t, o == offer, "forward %d carries the same offer", i+1)
	}
	assert.Nil(t, f.relay.activeSession("0001:QXyz"))
	assert.Nil(t, f.relay.activeSession("0002:QXyz"))
	rs := f.relay.activeSession("0003:QXyz")
	require.NotNil(t, rs, "the relay registers the final answer's pair only")
	assert.Equal(t, netip.MustParseAddrPort(sigTarget), rs.s.Target)
	assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.AnswerRetries.WithLabelValues("recovered")))
	assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.AnswerRetries.WithLabelValues("exhausted")))
}

func TestSignalGivesUpOnAnAnswerThatNeverNamesThePod(t *testing.T) {
	t.Run("after five forwards", func(t *testing.T) {
		f := newSigFixture(t)
		f.backend.setAnswer(func(n int32) string { return noPodAnswer(t, n) })
		addr := f.serve(t, 19132, fastRetry(20*time.Millisecond))
		resp, body := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
		assert.NotContains(t, body, "a=candidate")
		assert.Equal(t, int32(5), f.backend.posts.Load())
		for n := 1; n <= 5; n++ {
			assert.Nil(t, f.relay.activeSession(fmt.Sprintf("%04d:QXyz", n)))
		}
		assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.AnswerRetries.WithLabelValues("exhausted")))
		assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.AnswerRetries.WithLabelValues("recovered")))
	})
	t.Run("when the join's time runs out first", func(t *testing.T) {
		f := newSigFixture(t)
		f.opts.WakeHold = 500 * time.Millisecond
		f.backend.setAnswer(func(n int32) string { return noPodAnswer(t, n) })
		addr := f.serve(t, 19132, fastRetry(200*time.Millisecond))
		start := time.Now()
		resp, _ := sigDo(t, addr, sigReq{body: f.validOffer(t)})
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
		assert.Less(t, time.Since(start), 700*time.Millisecond, "no retry past WakeHold from the accept")
		assert.Less(t, f.backend.posts.Load(), int32(5))
		assert.Equal(t, 1.0, testutil.ToFloat64(f.metrics.AnswerRetries.WithLabelValues("exhausted")))
	})
}

func TestSignalStopsRetryingWhenTheClientHangsUp(t *testing.T) {
	f := newSigFixture(t)
	f.opts.WakeHold = 10 * time.Second
	f.backend.setAnswer(func(n int32) string { return noPodAnswer(t, n) })
	addr := f.serve(t, 19132, fastRetry(300*time.Millisecond))
	sigDo(t, addr, sigReq{body: f.validOffer(t), closeAfter: 100 * time.Millisecond})
	require.Eventually(t, func() bool {
		return testutil.ToFloat64(f.metrics.SignalingRequests.WithLabelValues("http", "bad_gateway")) == 1
	}, 2*time.Second, 10*time.Millisecond)
	posts := f.backend.posts.Load()
	time.Sleep(700 * time.Millisecond)
	assert.Equal(t, int32(1), posts, "the hang-up ends the wait before the next forward")
	assert.Equal(t, posts, f.backend.posts.Load(), "no forward after the hang-up")
	assert.Equal(t, 0.0, testutil.ToFloat64(f.metrics.AnswerRetries.WithLabelValues("exhausted")), "a hang-up is not a failed retry")
}
