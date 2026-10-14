// Command nethernet-router routes Bedrock NetherNet joins: TLS/HTTP signaling
// on one TCP port (plus each server's legacy pool port), relayed UDP on one
// port. It runs as its own DaemonSet, never inside the Java mc-router pods.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/itzg/go-flagsfiller"
	"github.com/itzg/mc-router/nethernet"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	certCheckEvery   = 30 * time.Second
	identityRefresh  = 6 * time.Hour // R35: a key Microsoft removes stops being trusted
	shutdownGrace    = 5 * time.Second
	metricsReadLimit = 5 * time.Second
)

// Config is read from flags, or from NETHERNET_<NAME> env (never the
// <SERVICE>_PORT vars Kubernetes injects).
type Config struct {
	SignalPort                int           `default:"19132" usage:"TCP port for NetherNet signaling (HTTP and TLS); PROXY v2 is read here only"`
	UdpPort                   int           `default:"19132" usage:"UDP port for the relay"`
	LegacyPortMin             int           `default:"30000" usage:"First legacy pool port to listen on for signaling (host:port addresses)"`
	LegacyPortMax             int           `default:"31000" usage:"Last legacy pool port to listen on for signaling"`
	PublicIp                  string        `usage:"Required. The IPv4 literal every SDP answer advertises (a hostname makes the client fail with Door)"`
	TlsCert                   string        `usage:"Path to the TLS certificate (PEM); re-read when the file changes"`
	TlsKey                    string        `usage:"Path to the TLS private key (PEM)"`
	TlsDomains                []string      `default:"uniz.host,mc.uniz.host" usage:"TLS is served for an SNI under one of these that the certificate covers; any other SNI gets a handshake_failure alert"`
	TrustedProxies            []string      `usage:"CIDRs whose PROXY v2 header is read on the signal port"`
	RedisAddr                 string        `usage:"host:port of the shared session registry; empty keeps sessions in this replica only"`
	RedisPassword             string        `usage:"Password for the shared session registry"`
	ApiUrl                    string        `usage:"Base URL of the uniz.host API (the wake endpoint)"`
	ApiToken                  string        `usage:"Required. The router's own token for the API's NetherNet wake endpoint"`
	Namespace                 string        `default:"game" usage:"Namespace whose Services publish NetherNet routes"`
	WakeHold                  time.Duration `default:"25s" usage:"How long a join to an asleep server is held while it boots (the client waits 30s)"`
	ProbeTimeout              time.Duration `default:"300ms" usage:"Dial timeout of the backend readiness probe"`
	IdentityJwksUrl           string        `default:"https://authorization.franchise.minecraft-services.net/.well-known/keys" usage:"Microsoft's JWKS for the Minecraft identity token"`
	MaxSessions               int           `default:"4096" usage:"Relay sessions per replica"`
	MaxSessionsPerServer      int           `default:"256" usage:"Relay sessions per server per replica"`
	MaxSessionsPerIpPerServer int           `default:"16" usage:"Relay sessions per player IP (IPv6 /64) per server per replica"`
	UnboundTtl                time.Duration `default:"60s" usage:"How long a signaled session waits for its first verified STUN check"`
	IdleTimeout               time.Duration `default:"30s" usage:"A bound session with no client datagram for this long is dropped"`
	HardReap                  time.Duration `default:"0s" usage:"Drop any session this old; 0 disables"`
	SignalRatePerIp           int           `default:"5" usage:"Signaling connections per second per player IP (IPv6 /64), bursting to 4x; the player's own address only, never a relay's; 0 disables"`
	SignalRateGlobal          int           `default:"200" usage:"Signaling connections per second in all, bursting to 2x; 0 disables"`
	MaxBody                   int64         `default:"1048576" usage:"Largest signaling request or backend answer body, in bytes"`
	RequestTimeout            time.Duration `default:"5s" usage:"Time from accept to a fully read signaling request: PROXY header, TLS handshake, headers and body"`
	WakeLimitPerPlayer        int           `default:"5" usage:"Actual wakes one verified player may cause per --wake-limit-window on this replica"`
	WakeLimitWindow           time.Duration `default:"1h" usage:"Rolling window of --wake-limit-per-player"`
	WakeBackoff               time.Duration `default:"5s" usage:"After the API answers booting or refuses a port's wake, reuse that answer this long instead of calling it again"`
	MetricsBinding            string        `default:":8080" usage:"host:port serving /metrics and /healthz only"`
	Debug                     bool          `usage:"Enable debug logs"`
}

func parseConfig(args []string) (*Config, error) {
	var c Config
	fs := flag.NewFlagSet("nethernet-router", flag.ContinueOnError)
	if err := flagsfiller.New(flagsfiller.WithEnv("NETHERNET")).Fill(fs, &c); err != nil {
		return nil, err
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return &c, c.validate()
}

func (c *Config) validate() error {
	ip, err := netip.ParseAddr(c.PublicIp)
	if err != nil || !ip.Unmap().Is4() {
		return fmt.Errorf("--public-ip must be an IPv4 literal, got %q", c.PublicIp)
	}
	for _, p := range []int{c.SignalPort, c.UdpPort, c.LegacyPortMin, c.LegacyPortMax} {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d is out of range", p)
		}
	}
	if c.LegacyPortMin > c.LegacyPortMax {
		return fmt.Errorf("--legacy-port-min %d is above --legacy-port-max %d", c.LegacyPortMin, c.LegacyPortMax)
	}
	if c.SignalPort >= c.LegacyPortMin && c.SignalPort <= c.LegacyPortMax {
		return fmt.Errorf("--signal-port %d is inside the legacy range", c.SignalPort)
	}
	if c.ApiUrl == "" {
		return errors.New("--api-url is required: the router wakes servers through the API")
	}
	if c.ApiToken == "" {
		return errors.New("--api-token is required: the API refuses every wake without it")
	}
	if (c.TlsCert == "") != (c.TlsKey == "") {
		return errors.New("--tls-cert and --tls-key go together")
	}
	if _, err := c.trustedProxies(); err != nil {
		return err
	}
	if c.WakeHold <= 0 || c.ProbeTimeout <= 0 {
		return errors.New("--wake-hold and --probe-timeout must be > 0")
	}
	if c.MaxBody <= 0 || c.RequestTimeout <= 0 {
		return errors.New("--max-body and --request-timeout must be > 0")
	}
	if c.WakeLimitPerPlayer <= 0 || c.WakeLimitWindow <= 0 || c.WakeBackoff <= 0 {
		return errors.New("--wake-limit-per-player, --wake-limit-window and --wake-backoff must be > 0")
	}
	if c.SignalRatePerIp < 0 || c.SignalRateGlobal < 0 {
		return errors.New("--signal-rate-per-ip and --signal-rate-global must be >= 0 (0 disables)")
	}
	return nil
}

func (c *Config) trustedProxies() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range c.TrustedProxies {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("--trusted-proxies: %q is not a CIDR", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	if err != nil {
		logrus.WithError(err).Fatal("nethernet-router: bad configuration")
	}
	if cfg.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if err := run(cfg); err != nil {
		logrus.WithError(err).Fatal("nethernet-router: stopped")
	}
}

type listener struct {
	net.Listener
	port int
}

func run(cfg *Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Every bind first: a port that cannot be bound is fatal at start.
	udp, err := net.ListenUDP("udp", &net.UDPAddr{Port: cfg.UdpPort})
	if err != nil {
		return fmt.Errorf("relay UDP %d: %w", cfg.UdpPort, err)
	}
	var listeners []listener
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for _, port := range append([]int{cfg.SignalPort}, legacyPorts(cfg)...) {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			return fmt.Errorf("signaling TCP %d: %w", port, err)
		}
		listeners = append(listeners, listener{l, port})
	}
	metricsL, err := net.Listen("tcp", cfg.MetricsBinding)
	if err != nil {
		return fmt.Errorf("metrics %s: %w", cfg.MetricsBinding, err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	metrics := nethernet.NewMetrics(reg)
	certFailures := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "nethernet_tls_cert_reload_failures_total", Help: "TLS certificate reloads that failed; the last good pair stays in use.",
	})
	reg.MustRegister(certFailures)
	var ready atomic.Bool
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready.Load() {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	})
	metricsSrv := &http.Server{Handler: mux, ReadHeaderTimeout: metricsReadLimit}
	go func() { _ = metricsSrv.Serve(metricsL) }()
	defer metricsSrv.Close()

	var tlsGet func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if cfg.TlsCert != "" {
		certs, err := newCertLoader(cfg.TlsCert, cfg.TlsKey, certCheckEvery, certFailures)
		if err != nil {
			return err
		}
		tlsGet = certs.get
	} else {
		logrus.Warn("nethernet-router: no --tls-cert; every TLS ClientHello is refused")
	}

	var shared nethernet.Registry
	if cfg.RedisAddr != "" {
		shared, err = nethernet.NewRedisRegistry(redis.NewClient(&redis.Options{
			Addr: cfg.RedisAddr, Password: cfg.RedisPassword, ContextTimeoutEnabled: true,
		}))
		if err != nil {
			return err
		}
		logrus.WithField("addr", cfg.RedisAddr).Info("nethernet-router: shared session registry: redis")
	} else {
		logrus.Info("nethernet-router: no --redis-addr; sessions are in this replica's memory only")
	}
	relay, err := nethernet.NewRelay(udp, nethernet.NewMemoryRegistry(), shared, nethernet.RelayOptions{
		UnboundTTL: cfg.UnboundTtl, IdleTimeout: cfg.IdleTimeout, HardReap: cfg.HardReap,
		MaxSessions: cfg.MaxSessions, MaxSessionsPerServer: cfg.MaxSessionsPerServer,
		MaxPerIPPerServer: cfg.MaxSessionsPerIpPerServer, Metrics: metrics,
	})
	if err != nil {
		return err
	}
	relayCtx, stopRelay := context.WithCancel(context.Background())
	defer stopRelay()
	go func() {
		if err := relay.Serve(relayCtx); err != nil {
			logrus.WithError(err).Error("nethernet-router: relay stopped")
		}
	}()

	identity := nethernet.NewIdentityVerifier(cfg.IdentityJwksUrl, nil, nil)
	// Never awaited at shutdown: a fetch ignores cancellation for up to 10 s.
	go refreshIdentity(ctx, identity)

	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("in-cluster config: %w", err)
	}
	kube, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return err
	}
	routes := nethernet.NewRouteTable()
	if err := nethernet.WatchServices(ctx, kube, cfg.Namespace, routes); err != nil {
		return err
	}

	opts := cfg.signalOptions()
	opts.Routes, opts.Relay, opts.Waker = routes, relay, nethernet.NewAPIWaker(cfg.ApiUrl, cfg.ApiToken, nil)
	opts.GetCertificate, opts.Identity, opts.Metrics = tlsGet, identity, metrics
	server := nethernet.NewSignalServer(opts)

	// In-flight signaling outlives ctx by up to shutdownGrace.
	sigCtx, stopSignaling := context.WithCancel(context.Background())
	defer stopSignaling()
	var acceptors, inflight sync.WaitGroup
	for _, l := range listeners {
		acceptors.Go(func() { accept(sigCtx, l, server, &inflight) })
	}
	ready.Store(true)
	logrus.WithFields(logrus.Fields{
		"signal": cfg.SignalPort, "udp": cfg.UdpPort, "legacy": fmt.Sprintf("%d-%d", cfg.LegacyPortMin, cfg.LegacyPortMax),
		"publicIp": cfg.PublicIp,
	}).Info("nethernet-router: serving")

	<-ctx.Done()
	ready.Store(false)
	logrus.Info("nethernet-router: stopping; in-flight signaling gets a grace period")
	for _, l := range listeners {
		_ = l.Close()
	}
	listeners = nil
	acceptors.Wait() // no inflight.Go after this, so Wait cannot race an Add
	drained := make(chan struct{})
	go func() { inflight.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(shutdownGrace):
		logrus.Warn("nethernet-router: grace period over; abandoning in-flight signaling")
	}
	return nil
}

// signalOptions carries the configuration into the signal server; run adds
// the live parts (routes, relay, waker, certificate, identity, metrics).
func (c *Config) signalOptions() nethernet.SignalOptions {
	trusted, _ := c.trustedProxies() // validated
	return nethernet.SignalOptions{
		PublicAddr: netip.AddrPortFrom(netip.MustParseAddr(c.PublicIp).Unmap(), uint16(c.UdpPort)),
		TLSDomains: c.TlsDomains, SignalPort: c.SignalPort, TrustedProxies: trusted,
		WakeHold: c.WakeHold, ProbeTimeout: c.ProbeTimeout, MaxBody: c.MaxBody, RequestTimeout: c.RequestTimeout,
		PerIPRate: c.SignalRatePerIp, GlobalRate: c.SignalRateGlobal,
		WakesPerPlayer: c.WakeLimitPerPlayer, WakeWindow: c.WakeLimitWindow, WakeBackoff: c.WakeBackoff,
	}
}

func legacyPorts(cfg *Config) []int {
	var ports []int
	for p := cfg.LegacyPortMin; p <= cfg.LegacyPortMax; p++ {
		ports = append(ports, p)
	}
	return ports
}

func accept(ctx context.Context, l listener, server *nethernet.SignalServer, inflight *sync.WaitGroup) {
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil { // e.g. out of file descriptors: back off, keep the listener
			logrus.WithError(err).WithField("port", l.port).Warn("nethernet-router: accept failed")
			time.Sleep(100 * time.Millisecond)
			continue
		}
		inflight.Go(func() { server.ServeConn(ctx, c, l.port) })
	}
}

func refreshIdentity(ctx context.Context, v *nethernet.IdentityVerifier) {
	t := time.NewTicker(identityRefresh)
	defer t.Stop()
	for {
		if err := v.Refresh(ctx); err != nil {
			logrus.WithError(err).Warn("nethernet-router: Minecraft JWKS refresh failed; keeping cached keys")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// certLoader serves the TLS pair and re-reads it, at most once per every, when
// either file's mtime or size changed: cert-manager renews the Secret and the
// kubelet swaps the mounted files without a restart (Ruling R29). A pair that
// fails to load keeps the last good one, and is logged and counted.
type certLoader struct {
	certFile, keyFile string
	every             time.Duration
	failures          prometheus.Counter

	mu      sync.Mutex
	cert    *tls.Certificate
	stamps  [2][2]int64 // mtime (unix nanos) and size of each file as loaded
	checked time.Time
}

func newCertLoader(certFile, keyFile string, every time.Duration, failures prometheus.Counter) (*certLoader, error) {
	l := &certLoader{certFile: certFile, keyFile: keyFile, every: every, failures: failures, checked: time.Now()}
	if err := l.reloadLocked(); err != nil {
		return nil, fmt.Errorf("TLS pair: %w", err)
	}
	return l, nil
}

func (l *certLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.checked) >= l.every {
		l.checked = now
		if err := l.reloadLocked(); err != nil {
			l.failures.Inc()
			logrus.WithError(err).Warn("nethernet-router: TLS pair failed to load; serving the last good one")
		}
	}
	return l.cert, nil
}

func (l *certLoader) reloadLocked() error {
	var stamps [2][2]int64
	for i, f := range []string{l.certFile, l.keyFile} {
		st, err := os.Stat(f)
		if err != nil {
			return err
		}
		stamps[i] = [2]int64{st.ModTime().UnixNano(), st.Size()}
	}
	if l.cert != nil && stamps == l.stamps {
		return nil
	}
	pair, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return err
	}
	l.cert, l.stamps = &pair, stamps
	logrus.WithField("cert", l.certFile).Info("nethernet-router: TLS pair loaded")
	return nil
}
