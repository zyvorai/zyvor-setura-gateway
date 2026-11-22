package gateway

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- token and key helpers ----

type jwtKey struct {
	kid  string
	alg  string
	priv crypto.Signer
	jwk  map[string]any
}

func be64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newRSAKey(t *testing.T, kid string) *jwtKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &jwtKey{kid: kid, alg: "RS256", priv: k, jwk: map[string]any{"kty": "RSA", "kid": kid, "use": "sig",
		"n": be64(k.N.Bytes()), "e": be64(big.NewInt(int64(k.E)).Bytes())}}
}

func newECKey(t *testing.T, kid string) *jwtKey {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &jwtKey{kid: kid, alg: "ES256", priv: k, jwk: map[string]any{"kty": "EC", "crv": "P-256", "kid": kid,
		"x": be64(k.X.FillBytes(make([]byte, 32))), "y": be64(k.Y.FillBytes(make([]byte, 32)))}}
}

func newEdKey(t *testing.T, kid string) *jwtKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &jwtKey{kid: kid, alg: "EdDSA", priv: priv, jwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": be64(pub)}}
}

func jwksDoc(keys ...*jwtKey) []byte {
	var ks []any
	for _, k := range keys {
		ks = append(ks, k.jwk)
	}
	return mustJSON(m{"keys": ks})
}

// sign makes a compact JWS; header and claims are marshalled as given, so a
// test can build an invalid token on purpose.
func (k *jwtKey) sign(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	if header == nil {
		header = map[string]any{}
	}
	if _, ok := header["alg"]; !ok {
		header["alg"] = k.alg
	}
	if _, ok := header["kid"]; !ok && k.kid != "" {
		header["kid"] = k.kid
	}
	signed := be64(mustJSON(header)) + "." + be64(mustJSON(claims))
	var sig []byte
	switch p := k.priv.(type) {
	case *rsa.PrivateKey:
		d := sha256.Sum256([]byte(signed))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, p, crypto.SHA256, d[:])
	case *ecdsa.PrivateKey:
		d := sha256.Sum256([]byte(signed))
		r, s, _ := ecdsa.Sign(rand.Reader, p, d[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(p, []byte(signed))
	}
	return signed + "." + be64(sig)
}

var t0 = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func claims(extra map[string]any) map[string]any {
	c := map[string]any{"iss": "https://idp.test", "aud": "api", "sub": "alice", "exp": t0.Add(10 * time.Minute).Unix(), "nbf": t0.Add(-time.Minute).Unix()}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func verifier(t *testing.T, p JWTPolicy, keys ...*jwtKey) *jwtVerifier {
	t.Helper()
	p.JWKS = jwksDoc(keys...)
	v, err := compileJWT(&p)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func wantFail(t *testing.T, v *jwtVerifier, tok string, now time.Time, status int, code, frag string) {
	t.Helper()
	_, je := v.verify(tok, now, false)
	if je == nil {
		t.Fatalf("token accepted, want %d %s %q", status, code, frag)
	}
	if je.status != status || je.code != code || !strings.Contains(je.desc, frag) {
		t.Fatalf("got %d %s %q, want %d %s %q", je.status, je.code, je.desc, status, code, frag)
	}
}

func TestJWTAlgorithms(t *testing.T) {
	for _, k := range []*jwtKey{newRSAKey(t, "r"), newECKey(t, "e"), newEdKey(t, "d")} {
		v := verifier(t, JWTPolicy{Issuer: "https://idp.test", Audience: []string{"api"}}, k)
		c, je := v.verify(k.sign(t, nil, claims(nil)), t0, false)
		if je != nil || c["sub"] != "alice" {
			t.Errorf("%s: %v", k.alg, je)
		}
		// A key never verifies a token claiming another algorithm.
		other := "ES256"
		if k.alg == "ES256" {
			other = "RS256"
		}
		wantFail(t, v, k.sign(t, map[string]any{"alg": other}, claims(nil)), t0, 401, "invalid_token", "")
	}
}

func TestJWTRejectsUnsafeTokens(t *testing.T) {
	k := newRSAKey(t, "k1")
	v := verifier(t, JWTPolicy{Audience: []string{"api"}}, k)
	good := k.sign(t, nil, claims(nil))
	if _, je := v.verify(good, t0, false); je != nil {
		t.Fatal(je)
	}
	// alg none
	none := be64([]byte(`{"alg":"none"}`)) + "." + be64(mustJSON(claims(nil))) + "."
	wantFail(t, v, none, t0, 401, "invalid_token", "algorithm")
	// HS256 signed with the public modulus as the secret (algorithm confusion)
	pub := k.priv.Public().(*rsa.PublicKey)
	signed := be64([]byte(`{"alg":"HS256","kid":"k1"}`)) + "." + be64(mustJSON(claims(nil)))
	mac := hmac.New(sha256.New, pub.N.Bytes())
	mac.Write([]byte(signed))
	wantFail(t, v, signed+"."+be64(mac.Sum(nil)), t0, 401, "invalid_token", "algorithm")
	// tampered payload
	parts := strings.Split(good, ".")
	wantFail(t, v, parts[0]+"."+be64(mustJSON(claims(map[string]any{"sub": "mallory"})))+"."+parts[2], t0, 401, "invalid_token", "signature")
	// signed by an unknown key with the same kid
	evil := newRSAKey(t, "k1")
	wantFail(t, v, evil.sign(t, nil, claims(nil)), t0, 401, "invalid_token", "signature")
	// critical headers, garbage, oversize
	wantFail(t, v, k.sign(t, map[string]any{"crit": []string{"x"}}, claims(nil)), t0, 401, "invalid_token", "critical")
	wantFail(t, v, "not-a-token", t0, 401, "invalid_token", "compact")
	wantFail(t, v, "a.b.c", t0, 401, "invalid_token", "base64")
	wantFail(t, v, strings.Repeat("a", maxTokenBytes+1), t0, 401, "invalid_token", "large")
	// no exp
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"exp": nil})), t0, 401, "invalid_token", "no exp")
	// an algorithm outside the policy
	v2 := verifier(t, JWTPolicy{Algorithms: []string{"ES256"}, Audience: []string{"api"}}, k)
	wantFail(t, v2, good, t0, 401, "invalid_token", "algorithm")
	if _, err := compileJWT(&JWTPolicy{Algorithms: []string{"HS256"}, JWKS: jwksDoc(k)}); err == nil {
		t.Error("HS256 must not be configurable")
	}
}

func TestJWTTimeAndClaims(t *testing.T) {
	k := newECKey(t, "k")
	v := verifier(t, JWTPolicy{Issuer: "https://idp.test", Audience: []string{"api", "api2"}, ClockSkew: "30s"}, k)
	tok := k.sign(t, nil, claims(nil))
	exp := t0.Add(10 * time.Minute)
	for _, c := range []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{"fresh", t0, true},
		{"just before exp+skew", exp.Add(29 * time.Second), true},
		{"at exp+skew", exp.Add(30 * time.Second), false},
		{"nbf within skew", t0.Add(-time.Minute - 29*time.Second), true},
		{"nbf beyond skew", t0.Add(-time.Minute - 31*time.Second), false},
	} {
		_, je := v.verify(tok, c.now, false)
		if (je == nil) != c.ok {
			t.Errorf("%s: err %v, want ok=%v", c.name, je, c.ok)
		}
	}
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"iss": "https://other"})), t0, 401, "invalid_token", "issuer")
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"aud": "elsewhere"})), t0, 401, "invalid_token", "audience")
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"aud": nil})), t0, 401, "invalid_token", "audience")
	if _, je := v.verify(k.sign(t, nil, claims(map[string]any{"aud": []string{"x", "api2"}})), t0, false); je != nil {
		t.Errorf("audience array: %v", je)
	}
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"exp": "tomorrow"})), t0, 401, "invalid_token", "not a number")
}

func TestJWTRequiredClaimsAndForwarding(t *testing.T) {
	k := newEdKey(t, "k")
	v := verifier(t, JWTPolicy{Audience: []string{"api"},
		RequiredClaims: map[string][]string{"scope": {"read", "admin"}, "email": nil, "realm_access.roles": {"ops"}},
		ClaimHeaders:   map[string]string{"X-User": "sub", "X-Roles": "realm_access.roles", "X-Scope": "scope"}}, k)
	ok := claims(map[string]any{"scope": "profile read", "email": "a@x", "realm_access": map[string]any{"roles": []string{"dev", "ops"}}})
	c, je := v.verify(k.sign(t, nil, ok), t0, false)
	if je != nil {
		t.Fatal(je)
	}
	if got := claimHeaderValue(mustClaim(c, "realm_access.roles")); got != "dev,ops" {
		t.Errorf("roles header = %q", got)
	}
	// Missing or wrong claim values are a 403: authenticated, not permitted.
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"scope": "profile", "email": "a@x", "realm_access": map[string]any{"roles": []string{"ops"}}})), t0, 403, "insufficient_scope", "scope")
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"scope": "read", "realm_access": map[string]any{"roles": []string{"ops"}}})), t0, 403, "insufficient_scope", "email")
	wantFail(t, v, k.sign(t, nil, claims(map[string]any{"scope": "read", "email": "a@x"})), t0, 403, "insufficient_scope", "realm_access.roles")
	// A claim cannot split a header.
	if got := claimHeaderValue("a\r\nX-Evil: 1"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("header injection: %q", got)
	}
}

func mustClaim(c jwtClaims, name string) any { v, _ := claimAt(c, name); return v }

func TestJWKSRefreshOnUnknownKidIsRateLimited(t *testing.T) {
	k1, k2 := newRSAKey(t, "one"), newRSAKey(t, "two")
	var fetches atomic.Int32
	doc := jwksDoc(k1)
	clock := t0
	s := newJWKSSource("https://user:pw@idp.test/jwks?apikey=SECRET", time.Hour, 30*time.Second)
	s.fetch = func(ctx context.Context) ([]byte, error) { fetches.Add(1); return doc, nil }
	now := func() time.Time { return clock }

	if _, err := s.keysFor("one", "RS256", now(), false); err != nil || fetches.Load() != 1 {
		t.Fatalf("first lookup: %v, %d fetches", err, fetches.Load())
	}
	// A token with an unknown kid does not refetch inside the minimum interval.
	for i := 0; i < 5; i++ {
		if _, err := s.keysFor("two", "RS256", now(), false); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if fetches.Load() != 1 {
		t.Errorf("%d fetches inside the refresh interval, want 1", fetches.Load())
	}
	// Rotation: after the interval, one unknown kid triggers one refetch that finds the key.
	doc = jwksDoc(k1, k2)
	clock = clock.Add(31 * time.Second)
	if _, err := s.keysFor("two", "RS256", now(), false); err != nil || fetches.Load() != 2 {
		t.Fatalf("after rotation: %v, %d fetches", err, fetches.Load())
	}
	// TTL expiry refetches; a failing fetch keeps serving the old keys and never leaks the URL.
	clock = clock.Add(2 * time.Hour)
	s.fetch = func(ctx context.Context) ([]byte, error) {
		fetches.Add(1)
		return nil, errors.New("responder down: " + redactURL(s.url))
	}
	if ks, err := s.keysFor("one", "RS256", now(), false); err != nil || len(ks) != 1 {
		t.Fatalf("stale keys must survive a failed refresh: %v", err)
	}
	if strings.Contains(s.lastErr, "SECRET") || strings.Contains(s.lastErr, "pw") {
		t.Errorf("error leaks credentials: %s", s.lastErr)
	}
	// Offline never fetches.
	n := fetches.Load()
	if _, err := newJWKSSource("https://idp.test/jwks", time.Hour, time.Second).keysFor("x", "RS256", now(), true); !errors.Is(err, errOfflineJWKS) {
		t.Errorf("offline: %v", err)
	}
	if fetches.Load() != n {
		t.Error("offline lookup fetched")
	}
}

func TestJWKSFetchFromServer(t *testing.T) {
	k := newECKey(t, "k")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/jwks":
			w.Write(jwksDoc(k))
		case "/redirect":
			http.Redirect(w, r, "/jwks", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s := newJWKSSource(srv.URL+"/jwks?key=SECRET", time.Hour, time.Second)
	if ks, err := s.keysFor("k", "ES256", time.Now(), false); err != nil || len(ks) != 1 {
		t.Fatal(err)
	}
	s = newJWKSSource(srv.URL+"/redirect?key=SECRET", time.Hour, time.Second)
	_, err := s.keysFor("k", "ES256", time.Now(), false)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("redirects must not be followed and errors must not carry the query: %v", err)
	}
	s = newJWKSSource(srv.URL+"/missing", time.Hour, time.Second)
	if _, err := s.keysFor("k", "ES256", time.Now(), false); err == nil {
		t.Error("404 JWKS accepted")
	}
}

func TestJWKSRejectsWeakKeys(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	doc := mustJSON(m{"keys": l{m{"kty": "RSA", "kid": "s", "n": be64(small.N.Bytes()), "e": "AQAB"}, m{"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"}, m{"kty": "oct", "k": "AAAA"}}})
	keys, skipped, err := parseJWKS(doc)
	if err != nil || len(keys) != 0 || skipped != 3 {
		t.Errorf("keys %d skipped %d err %v", len(keys), skipped, err)
	}
}
