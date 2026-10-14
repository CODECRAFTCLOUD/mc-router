package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigDefaults(t *testing.T) {
	c, err := parseConfig([]string{"--public-ip", "82.26.104.95", "--api-url", "http://uniz-api.game.svc", "--api-token", "t"})
	require.NoError(t, err)
	assert.Equal(t, 19132, c.SignalPort)
	assert.Equal(t, 19132, c.UdpPort)
	assert.Equal(t, 30000, c.LegacyPortMin)
	assert.Equal(t, 31000, c.LegacyPortMax)
	assert.Equal(t, []string{"uniz.host", "mc.uniz.host"}, c.TlsDomains)
	assert.Equal(t, "game", c.Namespace)
	assert.Equal(t, 25*time.Second, c.WakeHold)
	assert.Equal(t, 300*time.Millisecond, c.ProbeTimeout)
	assert.Equal(t, "https://authorization.franchise.minecraft-services.net/.well-known/keys", c.IdentityJwksUrl)
	assert.Equal(t, 4096, c.MaxSessions)
	assert.Equal(t, 256, c.MaxSessionsPerServer)
	assert.Equal(t, 16, c.MaxSessionsPerIpPerServer)
	assert.Equal(t, 60*time.Second, c.UnboundTtl)
	assert.Equal(t, 30*time.Second, c.IdleTimeout)
	assert.Equal(t, time.Duration(0), c.HardReap)
	assert.Equal(t, ":8080", c.MetricsBinding)
}

// Spec §6.8: every limit is a flag. The signaling limits default to the values
// they had as constants, and each flag reaches the signal server.
func TestConfigSignalingLimitsReachSignalOptions(t *testing.T) {
	base := []string{"--public-ip", "82.26.104.95", "--api-url", "http://api", "--api-token", "t"}
	c, err := parseConfig(base)
	require.NoError(t, err)
	o := c.signalOptions()
	assert.Equal(t, 5, o.PerIPRate)
	assert.Equal(t, 200, o.GlobalRate)
	assert.Equal(t, int64(1048576), o.MaxBody)
	assert.Equal(t, 5*time.Second, o.RequestTimeout)

	c, err = parseConfig(append(base, "--signal-rate-per-ip", "7", "--signal-rate-global", "300",
		"--max-body", "65536", "--request-timeout", "8s"))
	require.NoError(t, err)
	o = c.signalOptions()
	assert.Equal(t, 7, o.PerIPRate)
	assert.Equal(t, 300, o.GlobalRate)
	assert.Equal(t, int64(65536), o.MaxBody)
	assert.Equal(t, 8*time.Second, o.RequestTimeout)

	t.Setenv("NETHERNET_SIGNAL_RATE_PER_IP", "9")
	t.Setenv("NETHERNET_SIGNAL_RATE_GLOBAL", "400")
	t.Setenv("NETHERNET_MAX_BODY", "2048")
	t.Setenv("NETHERNET_REQUEST_TIMEOUT", "3s")
	c, err = parseConfig(base)
	require.NoError(t, err)
	o = c.signalOptions()
	assert.Equal(t, 9, o.PerIPRate)
	assert.Equal(t, 400, o.GlobalRate)
	assert.Equal(t, int64(2048), o.MaxBody)
	assert.Equal(t, 3*time.Second, o.RequestTimeout)
}

func TestConfigWakeLimitsReachSignalOptions(t *testing.T) {
	base := []string{"--public-ip", "82.26.104.95", "--api-url", "http://api", "--api-token", "t"}
	c, err := parseConfig(base)
	require.NoError(t, err)
	o := c.signalOptions()
	assert.Equal(t, 5, o.WakesPerPlayer)
	assert.Equal(t, time.Hour, o.WakeWindow)
	assert.Equal(t, 5*time.Second, o.WakeBackoff)

	c, err = parseConfig(append(base, "--wake-limit-per-player", "3", "--wake-limit-window", "30m", "--wake-backoff", "10s"))
	require.NoError(t, err)
	o = c.signalOptions()
	assert.Equal(t, 3, o.WakesPerPlayer)
	assert.Equal(t, 30*time.Minute, o.WakeWindow)
	assert.Equal(t, 10*time.Second, o.WakeBackoff)

	t.Setenv("NETHERNET_WAKE_LIMIT_PER_PLAYER", "7")
	t.Setenv("NETHERNET_WAKE_LIMIT_WINDOW", "2h")
	t.Setenv("NETHERNET_WAKE_BACKOFF", "3s")
	c, err = parseConfig(base)
	require.NoError(t, err)
	o = c.signalOptions()
	assert.Equal(t, 7, o.WakesPerPlayer)
	assert.Equal(t, 2*time.Hour, o.WakeWindow)
	assert.Equal(t, 3*time.Second, o.WakeBackoff)
}

func TestConfigRejectsUnusableSignalingLimits(t *testing.T) {
	base := []string{"--public-ip", "82.26.104.95", "--api-url", "http://api", "--api-token", "t"}
	for _, bad := range [][]string{
		{"--max-body", "0"}, {"--request-timeout", "0s"}, {"--signal-rate-per-ip", "-1"}, {"--signal-rate-global", "-1"},
		{"--wake-limit-per-player", "0"}, {"--wake-limit-window", "0s"}, {"--wake-backoff", "0s"},
	} {
		_, err := parseConfig(append(slices.Clone(base), bad...))
		assert.ErrorContains(t, err, strings.TrimPrefix(bad[0], "--"), bad)
	}
}

func TestConfigRejectsAHostnamePublicIP(t *testing.T) {
	_, err := parseConfig([]string{"--public-ip", "relay.uniz.host", "--api-url", "http://api", "--api-token", "t"})
	assert.ErrorContains(t, err, "public-ip")
	_, err = parseConfig([]string{"--api-url", "http://api", "--api-token", "t"})
	assert.ErrorContains(t, err, "public-ip", "it is required")
}

func TestConfigRejectsInvertedLegacyRange(t *testing.T) {
	_, err := parseConfig([]string{"--public-ip", "82.26.104.95", "--api-url", "http://api", "--api-token", "t",
		"--legacy-port-min", "31000", "--legacy-port-max", "30000"})
	assert.ErrorContains(t, err, "legacy")
	_, err = parseConfig([]string{"--public-ip", "82.26.104.95", "--api-url", "http://api", "--api-token", "t",
		"--legacy-port-min", "19000", "--legacy-port-max", "20000"})
	assert.ErrorContains(t, err, "signal-port", "the signal port must not fall inside the legacy range")
}

func TestConfigRefusesAnEmptyApiToken(t *testing.T) {
	_, err := parseConfig([]string{"--public-ip", "82.26.104.95", "--api-url", "http://api"})
	assert.ErrorContains(t, err, "api-token", "without a token the API refuses every wake")
}

func TestConfigRejectsABadTrustedProxy(t *testing.T) {
	_, err := parseConfig([]string{"--public-ip", "82.26.104.95", "--api-url", "http://api", "--api-token", "t",
		"--trusted-proxies", "10.77.77.0/24,not-a-cidr"})
	assert.ErrorContains(t, err, "trusted-proxies")
}

func TestConfigReadsPrefixedEnv(t *testing.T) {
	t.Setenv("NETHERNET_PUBLIC_IP", "82.26.104.95")
	t.Setenv("NETHERNET_API_URL", "http://uniz-api.game.svc")
	t.Setenv("NETHERNET_API_TOKEN", "from-env")
	t.Setenv("NETHERNET_TRUSTED_PROXIES", "10.77.77.0/24,192.168.1.215/32")
	t.Setenv("NETHERNET_MAX_SESSIONS_PER_IP_PER_SERVER", "8")
	c, err := parseConfig(nil)
	require.NoError(t, err)
	assert.Equal(t, "82.26.104.95", c.PublicIp)
	assert.Equal(t, "from-env", c.ApiToken)
	assert.Equal(t, []string{"10.77.77.0/24", "192.168.1.215/32"}, c.TrustedProxies)
	assert.Equal(t, 8, c.MaxSessionsPerIpPerServer)
}

// writePair writes a self-signed certificate with serial, and its key, as PEM.
func writePair(t *testing.T, dir string, serial int64) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "*.uniz.host"},
		DNSNames: []string{"*.uniz.host"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	kder, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	cert, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600))
	later := time.Now().Add(time.Duration(serial) * time.Minute) // a distinct mtime per pair
	require.NoError(t, os.Chtimes(cert, later, later))
	require.NoError(t, os.Chtimes(keyFile, later, later))
	return cert, keyFile
}

// servedSerial runs one TLS handshake against the loader and returns the
// serial of the certificate the server presented.
func servedSerial(t *testing.T, l *certLoader) int64 {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _ = tls.Server(a, &tls.Config{GetCertificate: l.get}).Handshake() }()
	c := tls.Client(b, &tls.Config{ServerName: "play.uniz.host", InsecureSkipVerify: true}) // the test inspects the served cert itself
	require.NoError(t, c.Handshake())
	return c.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func newFailures() prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: "f"})
}

func TestTLSReloadsARenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, 1)
	failures := newFailures()
	l, err := newCertLoader(cert, key, 0, failures)
	require.NoError(t, err)
	assert.Equal(t, int64(1), servedSerial(t, l))

	writePair(t, dir, 2) // cert-manager renewed the Secret; the kubelet swapped the files
	assert.Equal(t, int64(2), servedSerial(t, l), "the next handshake serves the renewed pair")
	assert.Equal(t, 0.0, testutil.ToFloat64(failures))
}

func TestTLSKeepsTheLastGoodPairOnABadFile(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, 1)
	failures := newFailures()
	l, err := newCertLoader(cert, key, 0, failures)
	require.NoError(t, err)
	require.Equal(t, int64(1), servedSerial(t, l))

	require.NoError(t, os.WriteFile(cert, []byte("not a certificate"), 0o600))
	later := time.Now().Add(time.Hour)
	require.NoError(t, os.Chtimes(cert, later, later))
	assert.Equal(t, int64(1), servedSerial(t, l), "a pair that fails to load keeps the last good one")
	assert.Equal(t, 1.0, testutil.ToFloat64(failures), "and is counted")
}

func TestTLSChecksTheFilesAtMostEveryInterval(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, 1)
	l, err := newCertLoader(cert, key, time.Hour, newFailures())
	require.NoError(t, err)
	writePair(t, dir, 2)
	assert.Equal(t, int64(1), servedSerial(t, l), "no re-read inside the interval")
}

func TestTLSRefusesToStartWithABadPair(t *testing.T) {
	dir := t.TempDir()
	cert, key := writePair(t, dir, 1)
	require.NoError(t, os.WriteFile(key, []byte("garbage"), 0o600))
	_, err := newCertLoader(cert, key, 0, newFailures())
	assert.Error(t, err)
}
