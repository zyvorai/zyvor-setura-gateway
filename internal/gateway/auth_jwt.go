package gateway

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// JWTPolicy validates a bearer JSON Web Token.
//
// Accepted: RS256, ES256 (P-256) and EdDSA (Ed25519), keys from a JWKS. Never
// accepted: "none", HMAC algorithms (a public key must not become an HMAC
// secret), any algorithm that does not match the type of the key it selects,
// tokens without exp, and tokens with a "crit" header.
type JWTPolicy struct {
	Issuer   string   `json:"issuer,omitempty"`
	Audience []string `json:"audience,omitempty"`
	// JWKSURI is fetched, cached and refreshed; JWKS is an inline key set.
	// Exactly one is required.
	JWKSURI string          `json:"jwksUri,omitempty"`
	JWKS    json.RawMessage `json:"jwks,omitempty"`
	// Algorithms restricts the accepted algorithms (default RS256, ES256, EdDSA).
	Algorithms []string `json:"algorithms,omitempty"`
	// ClockSkew is the tolerance for exp and nbf (default 60s).
	ClockSkew string `json:"clockSkew,omitempty"`
	// RequiredClaims maps a claim to the values it may have; an empty list
	// only demands that the claim exists. Dotted names reach into objects
	// ("realm_access.roles"). A string claim equals one value, an array claim
	// contains one, and a space separated string (scope) is split.
	RequiredClaims map[string][]string `json:"requiredClaims,omitempty"`
	// ClaimHeaders maps an upstream header to the claim copied into it.
	ClaimHeaders map[string]string `json:"claimHeaders,omitempty"`
	// StripToken removes the token from the request sent upstream.
	StripToken bool `json:"stripToken,omitempty"`
	// JWKSTTL is how long fetched keys are trusted (default 10m);
	// JWKSMinRefresh is the shortest time between two fetches, which bounds
	// what a stream of tokens with unknown key ids can cost (default 30s).
	JWKSTTL        string `json:"jwksTtl,omitempty"`
	JWKSMinRefresh string `json:"jwksMinRefresh,omitempty"`
}

const maxTokenBytes = 16 << 10

// jwtError carries the HTTP outcome of a failed validation. desc is safe to
// show: it never contains token content.
type jwtError struct {
	status int
	code   string // invalid_token or insufficient_scope
	desc   string
}

func (e *jwtError) Error() string { return e.code + ": " + e.desc }

func invalidToken(format string, a ...any) *jwtError {
	return &jwtError{http.StatusUnauthorized, "invalid_token", fmt.Sprintf(format, a...)}
}

type jwtVerifier struct {
	p       *JWTPolicy
	algs    map[string]bool
	skew    time.Duration
	src     *jwksSource
	aud     map[string]bool
	claimHd []string
}

var supportedJWTAlgs = map[string]bool{"RS256": true, "ES256": true, "EdDSA": true}

func compileJWT(p *JWTPolicy) (*jwtVerifier, error) {
	v := &jwtVerifier{p: p, algs: map[string]bool{}, skew: time.Minute}
	algs := p.Algorithms
	if len(algs) == 0 {
		algs = []string{"RS256", "ES256", "EdDSA"}
	}
	for _, a := range algs {
		if !supportedJWTAlgs[a] {
			return nil, fmt.Errorf("jwt.algorithms: %q is not supported (want RS256, ES256 or EdDSA)", a)
		}
		v.algs[a] = true
	}
	if p.ClockSkew != "" {
		d, err := time.ParseDuration(p.ClockSkew)
		if err != nil || d < 0 || d > time.Hour {
			return nil, fmt.Errorf("jwt.clockSkew %q: want a duration from 0 to 1h", p.ClockSkew)
		}
		v.skew = d
	}
	if len(p.Audience) > 0 {
		v.aud = map[string]bool{}
		for _, a := range p.Audience {
			v.aud[a] = true
		}
	}
	for h := range p.ClaimHeaders {
		if h == "" || strings.ContainsAny(h, " :\r\n") {
			return nil, fmt.Errorf("jwt.claimHeaders: bad header name %q", h)
		}
		v.claimHd = append(v.claimHd, h)
	}
	ttl, minRefresh := 10*time.Minute, 30*time.Second
	var err error
	if p.JWKSTTL != "" {
		if ttl, err = time.ParseDuration(p.JWKSTTL); err != nil || ttl <= 0 {
			return nil, fmt.Errorf("jwt.jwksTtl %q: want a positive duration", p.JWKSTTL)
		}
	}
	if p.JWKSMinRefresh != "" {
		if minRefresh, err = time.ParseDuration(p.JWKSMinRefresh); err != nil || minRefresh < 0 {
			return nil, fmt.Errorf("jwt.jwksMinRefresh %q: want a duration", p.JWKSMinRefresh)
		}
	}
	switch {
	case p.JWKSURI != "" && len(p.JWKS) > 0:
		return nil, errors.New("jwt: give jwksUri or jwks, not both")
	case p.JWKSURI != "":
		u, err := url.Parse(p.JWKSURI)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("jwt.jwksUri %s: want an http(s) URL", redactURL(p.JWKSURI))
		}
		v.src = sharedJWKS(p.JWKSURI, ttl, minRefresh)
	case len(p.JWKS) > 0:
		keys, _, err := parseJWKS(p.JWKS)
		if err != nil {
			return nil, fmt.Errorf("jwt.jwks: %w", err)
		}
		if len(keys) == 0 {
			return nil, errors.New("jwt.jwks: no usable keys (RSA, P-256 or Ed25519)")
		}
		v.src = &jwksSource{keys: keys, inline: true}
	default:
		return nil, errors.New("jwt: jwksUri or jwks is required")
	}
	return v, nil
}

// token extracts the bearer token; "" when the request carries none.
func bearerToken(r *http.Request) string {
	a := r.Header.Get("Authorization")
	if len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		return strings.TrimSpace(a[7:])
	}
	return ""
}

func (v *jwtVerifier) strip(r *http.Request) {
	if v.p.StripToken && bearerToken(r) != "" {
		r.Header.Del("Authorization")
	}
}

// jwtClaims is the verified payload.
type jwtClaims map[string]any

type jwtHeader struct {
	Alg  string          `json:"alg"`
	Kid  string          `json:"kid"`
	Typ  string          `json:"typ"`
	Crit json.RawMessage `json:"crit"`
}

// verify checks a token at the given time. A nil error means every check
// passed. The returned claims are valid only then.
func (v *jwtVerifier) verify(token string, now time.Time, offline bool) (jwtClaims, *jwtError) {
	if len(token) > maxTokenBytes {
		return nil, invalidToken("token is too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalidToken("token is not a compact JWS")
	}
	hb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, invalidToken("token is not base64url")
	}
	var h jwtHeader
	if json.Unmarshal(hb, &h) != nil {
		return nil, invalidToken("token header is not JSON")
	}
	if len(h.Crit) > 0 {
		return nil, invalidToken("critical header parameters are not supported")
	}
	if !v.algs[h.Alg] {
		return nil, invalidToken("algorithm %q is not accepted", clip(h.Alg, 16))
	}
	keys, err := v.src.keysFor(h.Kid, h.Alg, now, offline)
	if err != nil {
		var je *jwtError
		switch {
		case errors.As(err, &je):
			return nil, je
		case errors.Is(err, errOfflineJWKS):
			return nil, &jwtError{0, "offline", err.Error()}
		}
		return nil, &jwtError{http.StatusServiceUnavailable, "", err.Error()}
	}
	signed := []byte(parts[0] + "." + parts[1])
	ok := false
	for _, k := range keys {
		if k.verify(h.Alg, signed, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, invalidToken("signature does not verify")
	}
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.UseNumber()
	var c jwtClaims
	if dec.Decode(&c) != nil || c == nil {
		return nil, invalidToken("token payload is not a JSON object")
	}
	if je := v.checkClaims(c, now); je != nil {
		return nil, je
	}
	return c, nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func numericDate(c jwtClaims, name string) (time.Time, bool, bool) {
	raw, ok := c[name]
	if !ok {
		return time.Time{}, false, true
	}
	n, isNum := raw.(json.Number)
	if !isNum {
		return time.Time{}, true, false
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1e12 {
		return time.Time{}, true, false
	}
	return time.Unix(int64(f), 0), true, true
}

func (v *jwtVerifier) checkClaims(c jwtClaims, now time.Time) *jwtError {
	exp, has, ok := numericDate(c, "exp")
	switch {
	case !ok:
		return invalidToken("exp is not a number")
	case !has:
		return invalidToken("token has no exp claim")
	case !now.Before(exp.Add(v.skew)):
		return invalidToken("token has expired")
	}
	if nbf, has, ok := numericDate(c, "nbf"); !ok {
		return invalidToken("nbf is not a number")
	} else if has && now.Add(v.skew).Before(nbf) {
		return invalidToken("token is not valid yet")
	}
	if v.p.Issuer != "" {
		if iss, _ := c["iss"].(string); iss != v.p.Issuer {
			return invalidToken("issuer is not accepted")
		}
	}
	if v.aud != nil {
		matched := false
		switch a := c["aud"].(type) {
		case string:
			matched = v.aud[a]
		case []any:
			for _, x := range a {
				if s, ok := x.(string); ok && v.aud[s] {
					matched = true
				}
			}
		}
		if !matched {
			return invalidToken("audience is not accepted")
		}
	}
	for _, name := range sortedKeys(v.p.RequiredClaims) {
		want := v.p.RequiredClaims[name]
		got, ok := claimAt(c, name)
		if !ok {
			return &jwtError{http.StatusForbidden, "insufficient_scope", "required claim " + name + " is missing"}
		}
		if len(want) == 0 {
			continue
		}
		if !claimHasAny(got, want) {
			return &jwtError{http.StatusForbidden, "insufficient_scope", "claim " + name + " does not have an accepted value"}
		}
	}
	return nil
}

// claimAt reads a claim, descending through objects along a dotted name. A
// name that exists literally wins over the dotted reading.
func claimAt(c map[string]any, name string) (any, bool) {
	if v, ok := c[name]; ok {
		return v, true
	}
	first, rest, dotted := strings.Cut(name, ".")
	if !dotted {
		return nil, false
	}
	m, ok := c[first].(map[string]any)
	if !ok {
		return nil, false
	}
	return claimAt(m, rest)
}

func claimStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return strings.Fields(x)
	case json.Number:
		return []string{x.String()}
	case bool:
		return []string{strconv.FormatBool(x)}
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, claimStrings(e)...)
		}
		return out
	}
	return nil
}

func claimHasAny(got any, want []string) bool {
	if s, ok := got.(string); ok { // a whole-string match first: values may contain spaces
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	for _, g := range claimStrings(got) {
		for _, w := range want {
			if g == w {
				return true
			}
		}
	}
	return false
}

// claimHeaderValue renders a claim for a header: scalars as text, arrays
// joined by commas. Control characters are dropped so a claim cannot split
// a header.
func claimHeaderValue(v any) string {
	var vals []string
	switch x := v.(type) {
	case string:
		vals = []string{x}
	default:
		vals = claimStrings(v)
	}
	s := strings.Join(vals, ",")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// ---- JWKS ----

type jwkKey struct {
	kid string
	alg string // optional restriction from the JWK
	pub crypto.PublicKey
}

func (k *jwkKey) verify(alg string, signed, sig []byte) bool {
	if k.alg != "" && k.alg != alg {
		return false
	}
	switch pub := k.pub.(type) {
	case *rsa.PublicKey:
		if alg != "RS256" {
			return false
		}
		d := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig) == nil
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return false
		}
		d := sha256.Sum256(signed)
		return ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case ed25519.PublicKey:
		return alg == "EdDSA" && ed25519.Verify(pub, signed, sig)
	}
	return false
}

func (k *jwkKey) matchesAlg(alg string) bool {
	switch k.pub.(type) {
	case *rsa.PublicKey:
		return alg == "RS256"
	case *ecdsa.PublicKey:
		return alg == "ES256"
	case ed25519.PublicKey:
		return alg == "EdDSA"
	}
	return false
}

type rawJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWKS(raw []byte) (keys []*jwkKey, skipped int, err error) {
	var doc struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, errors.New("not a JWKS document")
	}
	dec := func(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); return b }
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			skipped++
			continue
		}
		jk := &jwkKey{kid: k.Kid, alg: k.Alg}
		switch k.Kty {
		case "RSA":
			n, e := new(big.Int).SetBytes(dec(k.N)), new(big.Int).SetBytes(dec(k.E))
			if n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
				skipped++
				continue
			}
			jk.pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
		case "EC":
			if k.Crv != "P-256" {
				skipped++
				continue
			}
			x, y := new(big.Int).SetBytes(dec(k.X)), new(big.Int).SetBytes(dec(k.Y))
			if !elliptic.P256().IsOnCurve(x, y) {
				skipped++
				continue
			}
			jk.pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		case "OKP":
			x := dec(k.X)
			if k.Crv != "Ed25519" || len(x) != ed25519.PublicKeySize {
				skipped++
				continue
			}
			jk.pub = ed25519.PublicKey(x)
		default:
			skipped++
			continue
		}
		keys = append(keys, jk)
	}
	return keys, skipped, nil
}

// jwksSource holds the keys of one JWKS and keeps a fetched one fresh.
type jwksSource struct {
	inline bool
	url    string // raw, secret: never printed
	ttl    time.Duration
	min    time.Duration
	client *http.Client
	// fetch is replaceable by tests; it returns the document body.
	fetch func(ctx context.Context) ([]byte, error)

	fmu         sync.Mutex // serialises fetches
	mu          sync.Mutex // guards the fields below
	keys        []*jwkKey
	fetchedAt   time.Time
	lastAttempt time.Time
	gen         int
	lastErr     string
	fetches     int
}

var (
	jwksMu       sync.Mutex
	jwksRegistry = map[string]*jwksSource{}
)

// sharedJWKS returns the cache for a JWKS URL; configuration reloads and
// routes that name the same URL share it, so a reload does not refetch.
func sharedJWKS(rawURL string, ttl, min time.Duration) *jwksSource {
	key := rawURL + "\x00" + ttl.String() + "\x00" + min.String()
	jwksMu.Lock()
	defer jwksMu.Unlock()
	if s := jwksRegistry[key]; s != nil {
		return s
	}
	s := newJWKSSource(rawURL, ttl, min)
	jwksRegistry[key] = s
	return s
}

func newJWKSSource(rawURL string, ttl, min time.Duration) *jwksSource {
	s := &jwksSource{url: rawURL, ttl: ttl, min: min}
	s.client = &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	s.fetch = s.httpFetch
	return s
}

func (s *jwksSource) httpFetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, errors.New("bad JWKS URL")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		// net/url errors embed the URL; keep the failure but not the URL.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, fmt.Errorf("fetching %s: %w", redactURL(s.url), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: status %d", redactURL(s.url), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return nil, fmt.Errorf("fetching %s: unreadable or oversized body", redactURL(s.url))
	}
	return b, nil
}

func (s *jwksSource) match(kid, alg string) []*jwkKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*jwkKey
	for _, k := range s.keys {
		if (kid == "" || k.kid == kid) && k.matchesAlg(alg) {
			out = append(out, k)
		}
	}
	return out
}

func (s *jwksSource) canTry(now time.Time) (bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAttempt.IsZero() || now.Sub(s.lastAttempt) >= s.min, s.gen
}

// refresh fetches the key set. gen is the generation the caller saw: if
// another goroutine refreshed meanwhile, this one does not fetch again.
func (s *jwksSource) refresh(gen int, now time.Time) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	s.mu.Lock()
	if s.gen != gen {
		s.mu.Unlock()
		return
	}
	s.lastAttempt = now
	s.gen++
	s.fetches++
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	body, err := s.fetch(ctx)
	var keys []*jwkKey
	if err == nil {
		keys, _, err = parseJWKS(body)
		if err == nil && len(keys) == 0 {
			err = errors.New("the JWKS has no usable keys")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastErr = err.Error() // the old keys stay in service
		return
	}
	s.keys, s.fetchedAt, s.lastErr = keys, now, ""
}

// keysFor returns the keys to try for a token. An unknown kid triggers one
// refresh, but never more often than once per minimum refresh interval.
func (s *jwksSource) keysFor(kid, alg string, now time.Time, offline bool) ([]*jwkKey, error) {
	if s.inline {
		if ks := s.match(kid, alg); len(ks) > 0 {
			return ks, nil
		}
		return nil, invalidToken("no key for this token")
	}
	s.mu.Lock()
	stale := len(s.keys) == 0 || now.Sub(s.fetchedAt) >= s.ttl
	s.mu.Unlock()
	if offline {
		if stale {
			return nil, errOfflineJWKS
		}
		if ks := s.match(kid, alg); len(ks) > 0 {
			return ks, nil
		}
		return nil, invalidToken("no key for this token")
	}
	if ok, gen := s.canTry(now); stale && ok {
		s.refresh(gen, now)
	}
	ks := s.match(kid, alg)
	if len(ks) == 0 {
		s.mu.Lock()
		have := len(s.keys) > 0
		msg := s.lastErr
		s.mu.Unlock()
		if !have {
			if msg == "" {
				msg = "no JWKS has been fetched yet"
			}
			return nil, fmt.Errorf("JWKS unavailable: %s", msg)
		}
		if ok, gen := s.canTry(now); ok {
			s.refresh(gen, now)
			ks = s.match(kid, alg)
		}
	}
	if len(ks) == 0 {
		return nil, invalidToken("no key for this token")
	}
	return ks, nil
}

var errOfflineJWKS = errors.New("the JWKS is fetched from a URL and is not cached here")
