package nethernet

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	identityIssuer   = "https://authorization.franchise.minecraft-services.net/"
	identityAudience = "api://auth-minecraft-services/multiplayer"
	identitySkew     = 60 * time.Second
	jwksRefetchEvery = time.Minute
)

var errIdentity = errors.New("identity rejected")

func identityErr(reason string) error { return fmt.Errorf("%w: %s", errIdentity, reason) }

// IdentityVerifier checks the Minecraft identity a NetherNet offer carries
// (spec §19.14) before the router may wake a server. It never logs a token.
type IdentityVerifier struct {
	jwksURL string
	hc      *http.Client
	now     func() time.Time

	fetchMu   sync.Mutex // one JWKS fetch at a time
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

func NewIdentityVerifier(jwksURL string, hc *http.Client, now func() time.Time) *IdentityVerifier {
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	return &IdentityVerifier{jwksURL: jwksURL, hc: hc, now: now, keys: map[string]*rsa.PublicKey{}}
}

// Verify reads the offer's a=identity (Mojang NetherNet onboarding guide
// §5.1): the GameServerToken must be an RS256 JWT from Microsoft's keys with
// the expected iss, aud and exp, and its detached ES384 "fingerprints" JWS,
// signed by the token's cpk, must cover exactly this offer's a=fingerprint
// lines. That binds the token to this offer: a lifted token cannot be replayed
// with another offer.
func (v *IdentityVerifier) Verify(ctx context.Context, offerSDP string) (Identity, error) {
	var identity string
	var fps []sdpFingerprint
	seen := 0
	for _, l := range sdpLines(offerSDP) {
		if val, ok := strings.CutPrefix(l, "a=identity:"); ok {
			identity, seen = strings.TrimSpace(val), seen+1
		} else if val, ok := strings.CutPrefix(l, "a=fingerprint:"); ok {
			f := strings.Fields(val)
			if len(f) != 2 {
				return Identity{}, identityErr("malformed a=fingerprint")
			}
			fps = append(fps, sdpFingerprint{Algorithm: f[0], Digest: f[1]})
		}
	}
	if seen != 1 || identity == "" {
		return Identity{}, identityErr("offer needs exactly one a=identity")
	}
	if len(fps) == 0 {
		return Identity{}, identityErr("offer has no a=fingerprint")
	}

	raw, err := decodeAnyBase64(identity)
	if err != nil {
		return Identity{}, identityErr("a=identity is not base64")
	}
	var envelope struct {
		Assertion string `json:"assertion"`
	}
	var assertion struct {
		Token        string `json:"token"`
		Fingerprints string `json:"fingerprints"`
	}
	if json.Unmarshal(raw, &envelope) != nil || json.Unmarshal([]byte(envelope.Assertion), &assertion) != nil ||
		assertion.Token == "" || assertion.Fingerprints == "" {
		return Identity{}, identityErr("malformed identity assertion")
	}

	claims, err := v.verifyToken(ctx, assertion.Token)
	if err != nil {
		return Identity{}, err
	}
	cpk, err := parseCPK(claims.CPK)
	if err != nil {
		return Identity{}, err
	}
	if err := verifyFingerprints(assertion.Fingerprints, fps, cpk); err != nil {
		return Identity{}, err
	}
	return Identity{XUID: claims.XID, Gamertag: claims.XName, ExpiresAt: time.Unix(claims.Exp, 0)}, nil
}

type tokenClaims struct {
	Iss   string          `json:"iss"`
	Aud   json.RawMessage `json:"aud"`
	Exp   int64           `json:"exp"`
	XID   string          `json:"xid"`
	XName string          `json:"xname"`
	CPK   string          `json:"cpk"`
}

type jwsHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Crit []string `json:"crit"`
}

func (v *IdentityVerifier) verifyToken(ctx context.Context, token string) (tokenClaims, error) {
	var claims tokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, identityErr("token is not a JWS")
	}
	var h jwsHeader
	if decodeJSONSegment(parts[0], &h) != nil || h.Alg != "RS256" || len(h.Crit) > 0 {
		return claims, identityErr("token alg must be RS256")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims, identityErr("token signature is not base64url")
	}
	key, err := v.key(ctx, h.Kid)
	if err != nil {
		return claims, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig) != nil {
		return claims, identityErr("token signature does not verify")
	}
	if decodeJSONSegment(parts[1], &claims) != nil {
		return claims, identityErr("token claims are malformed")
	}
	if claims.Iss != identityIssuer {
		return claims, identityErr("token issuer")
	}
	if !audienceHas(claims.Aud, identityAudience) {
		return claims, identityErr("token audience")
	}
	if claims.Exp == 0 || v.now().After(time.Unix(claims.Exp, 0).Add(identitySkew)) {
		return claims, identityErr("token expired")
	}
	if claims.XID == "" || claims.XName == "" {
		return claims, identityErr("token names no player")
	}
	return claims, nil
}

func audienceHas(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, want)
}

// parseCPK reads the token's cpk claim: base64 DER (PKIX) of a P-384 key, as
// the same issuer's login token carries it (gophertunnel login.ParsePublicKey).
func parseCPK(cpk string) (*ecdsa.PublicKey, error) {
	der, err := decodeAnyBase64(cpk)
	if err != nil {
		return nil, identityErr("cpk is not base64")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, identityErr("cpk is not a public key")
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P384() {
		return nil, identityErr("cpk must be a P-384 key")
	}
	return ec, nil
}

type sdpFingerprint struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

// canonicalFingerprints is the detached payload of guide §5.1 step 4: every
// a=fingerprint as {"fingerprint":[{"algorithm":…,"digest":…}]}, keys sorted,
// no whitespace, minimal escaping.
func canonicalFingerprints(fps []sdpFingerprint) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		Fingerprint []sdpFingerprint `json:"fingerprint"`
	}{fps}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func verifyFingerprints(jws string, fps []sdpFingerprint, cpk *ecdsa.PublicKey) error {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[1] != "" {
		return identityErr("fingerprints must be a detached JWS")
	}
	var h jwsHeader
	if decodeJSONSegment(parts[0], &h) != nil || h.Alg != "ES384" || len(h.Crit) > 0 {
		return identityErr("fingerprints alg must be ES384")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 96 {
		return identityErr("fingerprints signature must be 96 bytes r||s")
	}
	payload, err := canonicalFingerprints(fps)
	if err != nil {
		return identityErr("fingerprints payload")
	}
	sum := sha512.Sum384([]byte(parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)))
	r, s := new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:])
	if !ecdsa.Verify(cpk, sum[:], r, s) {
		return identityErr("fingerprints do not match this offer")
	}
	return nil
}

// key returns the JWKS key for kid. An unknown kid refetches the JWKS at most
// once per jwksRefetchEvery; a failed fetch keeps the cached keys.
func (v *IdentityVerifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if k := v.cachedKey(kid); k != nil {
		return k, nil
	}
	v.fetchMu.Lock()
	defer v.fetchMu.Unlock()
	if k := v.cachedKey(kid); k != nil { // fetched while we waited
		return k, nil
	}
	v.mu.RLock()
	last := v.lastFetch
	v.mu.RUnlock()
	if now := v.now(); last.IsZero() || now.Sub(last) >= jwksRefetchEvery {
		keys, err := v.fetchJWKS(ctx)
		v.mu.Lock()
		v.lastFetch = now
		if err == nil {
			v.keys = keys
		}
		v.mu.Unlock()
		if err != nil {
			logrus.WithError(err).Warn("nethernet: JWKS fetch failed; keeping cached keys")
		}
	}
	if k := v.cachedKey(kid); k != nil {
		return k, nil
	}
	v.mu.RLock()
	empty := len(v.keys) == 0
	v.mu.RUnlock()
	if empty {
		return nil, identityErr("no Minecraft signing keys loaded")
	}
	return nil, identityErr("token signed by an unknown key")
}

func (v *IdentityVerifier) cachedKey(kid string) *rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.keys[kid]
}

func (v *IdentityVerifier) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty, Use, Kid, N, E string
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, fmt.Errorf("JWKS decode: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || k.Kid == "" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(k.N)
		e, errE := base64.RawURLEncoding.DecodeString(k.E)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS has no usable RSA signing keys")
	}
	return keys, nil
}

func decodeJSONSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// decodeAnyBase64 accepts standard or URL-safe base64, padded or not: the
// guide says only "base64" for a=identity.
func decodeAnyBase64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
