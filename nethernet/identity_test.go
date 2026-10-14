package nethernet

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every key here is generated per test run: no real token or key is committed.

var (
	identKeysOnce           sync.Once
	identRSA, identOtherRSA *rsa.PrivateKey
	identCPK, identOtherCPK *ecdsa.PrivateKey
	identP256               *ecdsa.PrivateKey
	identFingerprintA       = "sha-256 CF:14:30:E1:94:92:52:CD:C0:82:76:FF:58:5E:4F:D4:6A:AA:C3:7D:CB:59:78:2F:B2:E4:E3:09:AF:79:64:EA"
	identFingerprintB       = "sha-256 0A:0B:0C:0D:94:92:52:CD:C0:82:76:FF:58:5E:4F:D4:6A:AA:C3:7D:CB:59:78:2F:B2:E4:E3:09:AF:79:64:EA"
	identStart              = time.Unix(1_800_000_000, 0)
	identLineRE             = regexp.MustCompile(`(?m)^a=identity:.*$`)
	identFingerprintLineRE  = regexp.MustCompile(`(?m)^a=fingerprint:[^\r\n]*`)
)

func identKeys(t *testing.T) {
	t.Helper()
	identKeysOnce.Do(func() {
		var err error
		identRSA, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		identOtherRSA, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		identCPK, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		identOtherCPK, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		identP256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
	})
}

type identClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *identClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *identClock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

type identJWKS struct {
	srv     *httptest.Server
	fetches atomic.Int32
	down    atomic.Bool
	body    atomic.Pointer[[]byte]
}

func identServeJWKS(t *testing.T, keys map[string]*rsa.PublicKey) *identJWKS {
	t.Helper()
	j := &identJWKS{}
	j.setKeys(keys)
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.fetches.Add(1)
		if j.down.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(*j.body.Load())
	}))
	t.Cleanup(j.srv.Close)
	return j
}

// setKeys replaces the key set the JWKS serves (a Microsoft key rotation).
func (j *identJWKS) setKeys(keys map[string]*rsa.PublicKey) {
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	for kid, k := range keys {
		set.Keys = append(set.Keys, map[string]string{
			"kty": "RSA", "use": "sig", "kid": kid, "x5t": kid,
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
		})
	}
	body, err := json.Marshal(set)
	if err != nil {
		panic(err)
	}
	j.body.Store(&body)
}

func identB64(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func identDefaultClaims(clock *identClock) map[string]any {
	der, err := x509.MarshalPKIXPublicKey(&identCPK.PublicKey)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"iss":   "https://authorization.franchise.minecraft-services.net/",
		"aud":   "api://auth-minecraft-services/multiplayer",
		"exp":   clock.now().Add(4 * time.Hour).Unix(),
		"xid":   "2535400000000001",
		"xname": "Synthetic Steve",
		"cpk":   base64.StdEncoding.EncodeToString(der),
	}
}

func identToken(header, claims map[string]any, key *rsa.PrivateKey) string {
	input := identB64(header) + "." + identB64(claims)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// identFingerprintsJWS signs the canonical JSON of the given "a=fingerprint" values
// (Mojang NetherNet onboarding guide §5.1 step 4) as a detached ES384 JWS.
func identFingerprintsJWS(key *ecdsa.PrivateKey, alg string, fingerprints ...string) string {
	type fp struct {
		Algorithm string `json:"algorithm"`
		Digest    string `json:"digest"`
	}
	var list []fp
	for _, f := range fingerprints {
		var a, d string
		for i := range f {
			if f[i] == ' ' {
				a, d = f[:i], f[i+1:]
				break
			}
		}
		list = append(list, fp{a, d})
	}
	payload, err := json.Marshal(map[string]any{"fingerprint": list})
	if err != nil {
		panic(err)
	}
	header := identB64(map[string]string{"alg": alg})
	input := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha512.Sum384([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		panic(err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*size)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return header + ".." + base64.RawURLEncoding.EncodeToString(sig)
}

func identEnvelope(token, fingerprints string) string {
	assertion, err := json.Marshal(map[string]string{"fingerprints": fingerprints, "token": token})
	if err != nil {
		panic(err)
	}
	env, err := json.Marshal(map[string]any{
		"assertion": string(assertion),
		"idp":       map[string]string{"domain": "authorization.franchise.minecraft-services.net", "protocol": "default"},
	})
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(env)
}

// identOffer is the redacted real Windows offer with a synthetic identity line
// and the given fingerprint.
func identOffer(t *testing.T, identityValue, fingerprint string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "offer-win-1.26.52.sdp"))
	require.NoError(t, err)
	sdp := identFingerprintLineRE.ReplaceAllString(string(raw), "a=fingerprint:"+fingerprint)
	return identLineRE.ReplaceAllString(sdp, "a=identity:"+identityValue+"\r")
}

type identFixture struct {
	clock *identClock
	jwks  *identJWKS
	v     *IdentityVerifier
}

func identSetup(t *testing.T) *identFixture {
	t.Helper()
	identKeys(t)
	clock := &identClock{t: identStart}
	jwks := identServeJWKS(t, map[string]*rsa.PublicKey{"kid-1": &identRSA.PublicKey})
	return &identFixture{clock: clock, jwks: jwks, v: NewIdentityVerifier(jwks.srv.URL, jwks.srv.Client(), clock.now)}
}

func (f *identFixture) offer(t *testing.T, mutate func(header, claims map[string]any)) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": "kid-1", "typ": "JWT"}
	claims := identDefaultClaims(f.clock)
	if mutate != nil {
		mutate(header, claims)
	}
	token := identToken(header, claims, identRSA)
	return identOffer(t, identEnvelope(token, identFingerprintsJWS(identCPK, "ES384", identFingerprintA)), identFingerprintA)
}

func TestIdentityAcceptsAValidOffer(t *testing.T) {
	f := identSetup(t)
	got, err := f.v.Verify(context.Background(), f.offer(t, nil))
	require.NoError(t, err)
	assert.Equal(t, Identity{XUID: "2535400000000001", Gamertag: "Synthetic Steve"}, got,
		"only what a consumer reads: XUID (wake limiter, API) and gamertag (API wake event)")
}

func TestIdentityAcceptsAnAudienceArray(t *testing.T) {
	f := identSetup(t)
	_, err := f.v.Verify(context.Background(), f.offer(t, func(_, c map[string]any) {
		c["aud"] = []string{"api://other", "api://auth-minecraft-services/multiplayer"}
	}))
	assert.NoError(t, err)
}

func TestIdentityAcceptsAnExpiryWithinTheSkew(t *testing.T) {
	f := identSetup(t)
	_, err := f.v.Verify(context.Background(), f.offer(t, func(_, c map[string]any) {
		c["exp"] = identStart.Add(-30 * time.Second).Unix()
	}))
	assert.NoError(t, err)
}

func TestIdentityRejectsAnExpiredToken(t *testing.T) {
	f := identSetup(t)
	_, err := f.v.Verify(context.Background(), f.offer(t, func(_, c map[string]any) {
		c["exp"] = identStart.Add(-61 * time.Second).Unix()
	}))
	assert.Error(t, err)
	_, err = f.v.Verify(context.Background(), f.offer(t, func(_, c map[string]any) { delete(c, "exp") }))
	assert.Error(t, err, "a token without exp never expires, so it is refused")
}

func TestIdentityRejectsAWrongIssuer(t *testing.T) {
	f := identSetup(t)
	for _, iss := range []string{"https://evil.example/", "https://authorization.franchise.minecraft-services.net", ""} {
		_, err := f.v.Verify(context.Background(), f.offer(t, func(_, c map[string]any) { c["iss"] = iss }))
		assert.Error(t, err, iss)
	}
}

func TestIdentityRejectsAWrongAudience(t *testing.T) {
	f := identSetup(t)
	for _, aud := range []any{"api://auth-minecraft-services/other", []string{"api://other"}, nil} {
		_, err := f.v.Verify(context.Background(), f.offer(t, func(_, c map[string]any) { c["aud"] = aud }))
		assert.Error(t, err, aud)
	}
}

func TestIdentityRejectsANoneOrHS256Algorithm(t *testing.T) {
	f := identSetup(t)
	claims := identDefaultClaims(f.clock)
	fps := identFingerprintsJWS(identCPK, "ES384", identFingerprintA)

	none := identB64(map[string]any{"alg": "none", "kid": "kid-1"}) + "." + identB64(claims) + "."
	_, err := f.v.Verify(context.Background(), identOffer(t, identEnvelope(none, fps), identFingerprintA))
	assert.Error(t, err, "alg none")

	// The classic confusion attack: HMAC keyed with the RSA public key.
	input := identB64(map[string]any{"alg": "HS256", "kid": "kid-1"}) + "." + identB64(claims)
	mac := hmac.New(sha256.New, x509.MarshalPKCS1PublicKey(&identRSA.PublicKey))
	mac.Write([]byte(input))
	hs := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	_, err = f.v.Verify(context.Background(), identOffer(t, identEnvelope(hs, fps), identFingerprintA))
	assert.Error(t, err, "alg HS256")

	// A valid RS256 signature from the real key under a header naming another alg.
	rs512 := identToken(map[string]any{"alg": "RS512", "kid": "kid-1"}, claims, identRSA)
	_, err = f.v.Verify(context.Background(), identOffer(t, identEnvelope(rs512, fps), identFingerprintA))
	assert.Error(t, err, "alg RS512 header")
}

func TestIdentityRejectsATamperedToken(t *testing.T) {
	f := identSetup(t)
	header := map[string]any{"alg": "RS256", "kid": "kid-1"}
	token := identToken(header, identDefaultClaims(f.clock), identRSA)
	claims := identDefaultClaims(f.clock)
	claims["xname"] = "Someone Else"
	forged := identB64(header) + "." + identB64(claims) + token[identLastDot(token):] // original signature
	_, err := f.v.Verify(context.Background(), identOffer(t, identEnvelope(forged, identFingerprintsJWS(identCPK, "ES384", identFingerprintA)), identFingerprintA))
	assert.Error(t, err)
}

func identLastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func TestIdentityRejectsATokenSignedByAnUnknownKey(t *testing.T) {
	f := identSetup(t)
	_, err := f.v.Verify(context.Background(), f.offer(t, nil)) // warms the cache
	require.NoError(t, err)
	require.EqualValues(t, 1, f.jwks.fetches.Load())
	f.clock.add(2 * time.Minute)

	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-attacker"}, identDefaultClaims(f.clock), identOtherRSA)
	offer := identOffer(t, identEnvelope(token, identFingerprintsJWS(identCPK, "ES384", identFingerprintA)), identFingerprintA)
	_, err = f.v.Verify(context.Background(), offer)
	assert.Error(t, err)
	assert.EqualValues(t, 2, f.jwks.fetches.Load(), "an unknown kid refetches once")

	_, err = f.v.Verify(context.Background(), offer)
	assert.Error(t, err)
	assert.EqualValues(t, 2, f.jwks.fetches.Load(), "at most one refetch a minute")

	// A known kid with the attacker's signature also fails.
	token = identToken(map[string]any{"alg": "RS256", "kid": "kid-1"}, identDefaultClaims(f.clock), identOtherRSA)
	_, err = f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, identFingerprintsJWS(identCPK, "ES384", identFingerprintA)), identFingerprintA))
	assert.Error(t, err)
}

func TestIdentityRejectsFingerprintsForAnotherOffer(t *testing.T) {
	f := identSetup(t)
	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-1"}, identDefaultClaims(f.clock), identRSA)
	// The JWS is valid for fingerprint A; the offer carries fingerprint B.
	_, err := f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, identFingerprintsJWS(identCPK, "ES384", identFingerprintA)), identFingerprintB))
	assert.Error(t, err)
}

func TestIdentityRejectsFingerprintsSignedByAnotherKey(t *testing.T) {
	f := identSetup(t)
	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-1"}, identDefaultClaims(f.clock), identRSA)
	_, err := f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, identFingerprintsJWS(identOtherCPK, "ES384", identFingerprintA)), identFingerprintA))
	assert.Error(t, err, "the JWS must be signed by the token's cpk")
}

func TestIdentityRejectsFingerprintsThatAreNotES384(t *testing.T) {
	f := identSetup(t)
	der, err := x509.MarshalPKIXPublicKey(&identP256.PublicKey)
	require.NoError(t, err)
	claims := identDefaultClaims(f.clock)
	claims["cpk"] = base64.StdEncoding.EncodeToString(der)
	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-1"}, claims, identRSA)
	_, err = f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, identFingerprintsJWS(identP256, "ES256", identFingerprintA)), identFingerprintA))
	assert.Error(t, err, "a P-256 cpk / ES256 JWS is refused")
}

func TestIdentityRejectsAnAttachedPayload(t *testing.T) {
	f := identSetup(t)
	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-1"}, identDefaultClaims(f.clock), identRSA)
	jws := identFingerprintsJWS(identCPK, "ES384", identFingerprintA)
	attached := jws[:identLastDot(jws)-1] + ".eyJ4IjoxfQ" + jws[identLastDot(jws):]
	_, err := f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, attached), identFingerprintA))
	assert.Error(t, err)
}

func TestIdentityRejectsAMissingIdentityLine(t *testing.T) {
	f := identSetup(t)
	offer := identLineRE.ReplaceAllString(f.offer(t, nil), "a=extmap-allow-mixed\r")
	_, err := f.v.Verify(context.Background(), offer)
	assert.Error(t, err)
	assert.EqualValues(t, 0, f.jwks.fetches.Load(), "a request without identity never reaches the JWKS")
}

func TestIdentityRejectsGarbageIdentity(t *testing.T) {
	f := identSetup(t)
	for _, v := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("{}")),
		base64.StdEncoding.EncodeToString([]byte(`{"assertion":"{\"token\":\"a.b.c\",\"fingerprints\":\"x..y\"}"}`))} {
		_, err := f.v.Verify(context.Background(), identOffer(t, v, identFingerprintA))
		assert.Error(t, err, v)
	}
}

func TestIdentityRejectsAMissingPlayer(t *testing.T) {
	f := identSetup(t)
	_, err := f.v.Verify(context.Background(), f.offer(t, func(_, c map[string]any) { delete(c, "xid") }))
	assert.Error(t, err)
}

func TestIdentityUsesCachedKeysWhenTheJWKSIsDown(t *testing.T) {
	f := identSetup(t)
	_, err := f.v.Verify(context.Background(), f.offer(t, nil))
	require.NoError(t, err)

	f.jwks.down.Store(true)
	f.clock.add(2 * time.Minute)
	// An unknown kid forces a refetch, which fails...
	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-new"}, identDefaultClaims(f.clock), identOtherRSA)
	_, err = f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, identFingerprintsJWS(identCPK, "ES384", identFingerprintA)), identFingerprintA))
	assert.Error(t, err)
	assert.EqualValues(t, 2, f.jwks.fetches.Load())

	// ...and the cached key still verifies.
	_, err = f.v.Verify(context.Background(), f.offer(t, nil))
	assert.NoError(t, err)
}

func TestIdentityErrorsWithNoKeysAtAll(t *testing.T) {
	f := identSetup(t)
	f.jwks.down.Store(true)
	_, err := f.v.Verify(context.Background(), f.offer(t, nil))
	assert.Error(t, err)
}

func TestIdentityRejectsTwoIdentityLines(t *testing.T) {
	f := identSetup(t)
	offer := identLineRE.ReplaceAllStringFunc(f.offer(t, nil), func(l string) string {
		// The garbage line comes first, so "last line wins" would accept the offer.
		return "a=identity:" + base64.StdEncoding.EncodeToString([]byte("{}")) + "\r\n" + l
	})
	_, err := f.v.Verify(context.Background(), offer)
	assert.Error(t, err, "an ambiguous offer is refused, whichever line is valid")
}

func TestIdentityRejectsAFingerprintsHeaderThatIsNotES384(t *testing.T) {
	f := identSetup(t)
	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-1"}, identDefaultClaims(f.clock), identRSA)
	// A correct P-384/SHA-384 signature under a header that claims ES256.
	jws := identFingerprintsJWS(identCPK, "ES256", identFingerprintA)
	_, err := f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, jws), identFingerprintA))
	assert.Error(t, err)
}

// R35: a JWKS fetch is shared state and must not die with one player's request.
func TestIdentityACancelledRequestDoesNotBlockTheNextFetch(t *testing.T) {
	f := identSetup(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = f.v.Verify(cancelled, f.offer(t, nil)) // a player who hung up, on a cold replica

	f.clock.add(10 * time.Second) // well inside the minute
	_, err := f.v.Verify(context.Background(), f.offer(t, nil))
	assert.NoError(t, err, "the next player still verifies")
}

func TestIdentityRetriesSoonerWithNoKeys(t *testing.T) {
	f := identSetup(t)
	f.jwks.down.Store(true)
	_, err := f.v.Verify(context.Background(), f.offer(t, nil))
	assert.Error(t, err)
	assert.EqualValues(t, 1, f.jwks.fetches.Load())

	f.clock.add(4 * time.Second)
	_, err = f.v.Verify(context.Background(), f.offer(t, nil))
	assert.Error(t, err)
	assert.EqualValues(t, 1, f.jwks.fetches.Load(), "an empty cache still waits 5 s between fetches")

	f.jwks.down.Store(false)
	f.clock.add(time.Second)
	_, err = f.v.Verify(context.Background(), f.offer(t, nil))
	assert.NoError(t, err, "with no keys the retry comes after 5 s, not a minute")
	assert.EqualValues(t, 2, f.jwks.fetches.Load())
}

func TestIdentityRefreshKeepsCachedKeysOnFailure(t *testing.T) {
	f := identSetup(t)
	require.NoError(t, f.v.Refresh(context.Background()))
	assert.EqualValues(t, 1, f.jwks.fetches.Load())

	f.jwks.down.Store(true)
	assert.Error(t, f.v.Refresh(context.Background()))
	assert.EqualValues(t, 2, f.jwks.fetches.Load(), "Refresh fetches now, whatever the refetch limit")
	_, err := f.v.Verify(context.Background(), f.offer(t, nil))
	assert.NoError(t, err, "the cached key still verifies")
}

func TestIdentityRefreshPicksUpARotatedKey(t *testing.T) {
	f := identSetup(t)
	_, err := f.v.Verify(context.Background(), f.offer(t, nil)) // warms the cache with kid-1
	require.NoError(t, err)

	f.jwks.setKeys(map[string]*rsa.PublicKey{"kid-2": &identOtherRSA.PublicKey}) // kid-1 rotated out
	require.NoError(t, f.v.Refresh(context.Background()))                        // inside the minute

	token := identToken(map[string]any{"alg": "RS256", "kid": "kid-2"}, identDefaultClaims(f.clock), identOtherRSA)
	_, err = f.v.Verify(context.Background(), identOffer(t, identEnvelope(token, identFingerprintsJWS(identCPK, "ES384", identFingerprintA)), identFingerprintA))
	assert.NoError(t, err, "the new key verifies")
	_, err = f.v.Verify(context.Background(), f.offer(t, nil))
	assert.Error(t, err, "a key Microsoft removed is no longer trusted")
}
