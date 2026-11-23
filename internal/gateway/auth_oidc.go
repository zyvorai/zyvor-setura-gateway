package gateway

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OIDCPolicy turns a rule into an OpenID Connect relying party: a browser
// without a session is sent to the identity provider (authorization code flow
// with PKCE, state and nonce), comes back to the callback path, and gets an
// encrypted or signed session cookie. The ID token is validated with the same
// code as the JWT policy. See docs/oidc.md.
type OIDCPolicy struct {
	// Issuer is the provider's issuer URL, exactly as its discovery document
	// and ID tokens spell it (Keycloak: https://HOST/realms/REALM).
	Issuer   string `json:"issuer"`
	ClientID string `json:"clientId"`
	// ClientSecret is omitted for a public client (PKCE only).
	ClientSecret *AISecretRef `json:"clientSecret,omitempty"`
	// TokenAuthMethod is client_secret_basic (default) or client_secret_post.
	TokenAuthMethod string `json:"tokenAuthMethod,omitempty"`
	// RedirectURL is the callback the provider returns to. Absolute is best
	// (https://app.example.com/oauth2/callback); a path is completed with the
	// request's Host. The rule must match this path.
	RedirectURL string `json:"redirectUrl"`
	// Scopes requested besides openid (default: profile, email).
	Scopes []string `json:"scopes,omitempty"`
	// CookieKeys are the secrets of the session cookie (at least 32 characters
	// each). The first one seals new cookies; every one opens, so a rotation
	// is: add the new key first, later remove the old one.
	CookieKeys []AISecretRef `json:"cookieKeys"`
	// CookieMode is encrypted (AES-256-GCM, default) or signed (HMAC-SHA256,
	// readable by the browser).
	CookieMode string      `json:"cookieMode,omitempty"`
	Cookie     *OIDCCookie `json:"cookie,omitempty"`
	// SessionTTL is the longest a session lasts from login (default 8h).
	SessionTTL string `json:"sessionTtl,omitempty"`
	// SessionClaims keeps only these claims in the session (default all of
	// the ID token's). Useful when a token carries a long group list.
	SessionClaims []string `json:"sessionClaims,omitempty"`
	// LogoutPath ends the session (default /oauth2/logout) and, when the
	// provider has an end_session_endpoint, continues there.
	LogoutPath string `json:"logoutPath,omitempty"`
	// PostLogoutRedirectURL is where the provider sends the browser after logout.
	PostLogoutRedirectURL string `json:"postLogoutRedirectUrl,omitempty"`
	// DenyRedirect: auto (default) answers 401 to XHR and API calls and
	// redirects browser navigations; always redirects every request; never
	// answers 401 to every request.
	DenyRedirect string `json:"denyRedirect,omitempty"`
	// Endpoint overrides, for providers without (or with a wrong) discovery
	// document. With authorizationEndpoint, tokenEndpoint and jwksUri all
	// set, discovery is not used.
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string `json:"tokenEndpoint,omitempty"`
	JWKSURI               string `json:"jwksUri,omitempty"`
	UserinfoEndpoint      string `json:"userinfoEndpoint,omitempty"`
	EndSessionEndpoint    string `json:"endSessionEndpoint,omitempty"`
	// Userinfo merges the userinfo response into the claims at login.
	Userinfo bool `json:"userinfo,omitempty"`
	// DisableRefresh keeps the refresh token out of the session and never refreshes.
	DisableRefresh bool `json:"disableRefresh,omitempty"`
	// AuthParams are extra authorization request parameters (kc_idp_hint, prompt, ...).
	AuthParams map[string]string `json:"authParams,omitempty"`
	// ClockSkew is the tolerance for the ID token's exp and nbf (default 60s).
	ClockSkew string `json:"clockSkew,omitempty"`
	// ClaimHeaders maps an upstream header to a claim, as for the jwt policy.
	ClaimHeaders map[string]string `json:"claimHeaders,omitempty"`
	// AccessTokenHeader forwards the access token upstream, with AccessTokenScheme
	// in front ("Bearer" for Authorization); IDTokenHeader forwards the ID token.
	AccessTokenHeader string `json:"accessTokenHeader,omitempty"`
	AccessTokenScheme string `json:"accessTokenScheme,omitempty"`
	IDTokenHeader     string `json:"idTokenHeader,omitempty"`
	// ForwardCookies sends the session cookies upstream (default: removed).
	ForwardCookies bool `json:"forwardCookies,omitempty"`
}

// OIDCCookie sets the session cookie's attributes.
type OIDCCookie struct {
	Name     string `json:"name,omitempty"`     // default setura_session
	Domain   string `json:"domain,omitempty"`   // default: the request host only
	Path     string `json:"path,omitempty"`     // default /
	SameSite string `json:"sameSite,omitempty"` // Lax (default), Strict or None
	// Secure defaults to true. Only false for plain-http development.
	Secure *bool `json:"secure,omitempty"`
}

const (
	oidcMaxChunks   = 5
	oidcChunkSize   = 3600
	oidcDiscoverTTL = time.Hour
	oidcRetryAfter  = 10 * time.Second
	oidcRefreshLead = 10 * time.Second
	oidcTxTTL       = 10 * time.Minute
	oidcMaxBody     = 1 << 20
)

var cookieNameRE = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

type compiledOIDC struct {
	p          *OIDCPolicy
	scopes     []string
	redirect   *url.URL
	cbPath     string
	logoutPath string
	skew, ttl  time.Duration
	signed     bool
	name       string
	secure     bool
	sameSite   http.SameSite
	silent     string
	prov       *oidcProvider
	own        []string // headers the policy sets, stripped from client requests
	keepClaims map[string]bool

	vmu sync.Mutex
	v   *jwtVerifier
	vu  string

	rmu      sync.Mutex
	inflight map[string]*refreshCall
	recent   map[string]refreshDone
}

func httpURL(s string) (*url.URL, bool) {
	u, err := url.Parse(s)
	return u, err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}

func compileOIDC(p *OIDCPolicy) (*compiledOIDC, error) {
	o := &compiledOIDC{p: p, skew: time.Minute, ttl: 8 * time.Hour, name: "setura_session", secure: true, sameSite: http.SameSiteLaxMode, silent: "auto"}
	if _, ok := httpURL(p.Issuer); !ok {
		return nil, fmt.Errorf("oidc.issuer %s: want an http(s) URL", redactURL(p.Issuer))
	}
	if p.ClientID == "" {
		return nil, errors.New("oidc.clientId is required")
	}
	if err := validateSecretRef("oidc.clientSecret", p.ClientSecret, false); err != nil {
		return nil, err
	}
	switch p.TokenAuthMethod {
	case "", "client_secret_basic", "client_secret_post":
	default:
		return nil, fmt.Errorf("oidc.tokenAuthMethod %q: want client_secret_basic or client_secret_post", p.TokenAuthMethod)
	}
	u, err := url.Parse(p.RedirectURL)
	switch {
	case p.RedirectURL == "" || err != nil || u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("oidc.redirectUrl is required: an absolute URL or a path, without query or fragment")
	case u.Scheme != "" && (u.Host == "" || (u.Scheme != "https" && u.Scheme != "http")):
		return nil, fmt.Errorf("oidc.redirectUrl %q: want an http(s) URL or a path", p.RedirectURL)
	case u.Scheme == "" && !strings.HasPrefix(u.Path, "/"):
		return nil, fmt.Errorf("oidc.redirectUrl %q: a path must start with /", p.RedirectURL)
	case u.Path == "" || u.Path == "/":
		return nil, errors.New("oidc.redirectUrl needs a path of its own (for example /oauth2/callback)")
	}
	o.redirect, o.cbPath = u, u.Path
	o.logoutPath = p.LogoutPath
	if o.logoutPath == "" {
		o.logoutPath = "/oauth2/logout"
	}
	if !strings.HasPrefix(o.logoutPath, "/") || o.logoutPath == o.cbPath {
		return nil, errors.New("oidc.logoutPath must start with / and differ from the callback path")
	}
	if p.PostLogoutRedirectURL != "" {
		if pu, err := url.Parse(p.PostLogoutRedirectURL); err != nil || (pu.Scheme == "" && !strings.HasPrefix(pu.Path, "/")) || (pu.Scheme != "" && pu.Host == "") {
			return nil, errors.New("oidc.postLogoutRedirectUrl: want an absolute URL or a path")
		}
	}
	o.scopes = []string{"openid"}
	scopes := p.Scopes
	if scopes == nil {
		scopes = []string{"profile", "email"}
	}
	for _, s := range scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n\"\\") {
			return nil, fmt.Errorf("oidc.scopes: bad scope %q", s)
		}
		if s != "openid" {
			o.scopes = append(o.scopes, s)
		}
	}
	if len(p.CookieKeys) == 0 || len(p.CookieKeys) > 4 {
		return nil, errors.New("oidc.cookieKeys: give one to four keys (the first seals, all open)")
	}
	for i := range p.CookieKeys {
		if err := validateSecretRef(fmt.Sprintf("oidc.cookieKeys[%d]", i), &p.CookieKeys[i], true); err != nil {
			return nil, err
		}
	}
	switch p.CookieMode {
	case "", "encrypted":
	case "signed":
		o.signed = true
	default:
		return nil, fmt.Errorf("oidc.cookieMode %q: want encrypted or signed", p.CookieMode)
	}
	if ck := p.Cookie; ck != nil {
		if ck.Name != "" {
			if !cookieNameRE.MatchString(ck.Name) || len(ck.Name) > 64 {
				return nil, fmt.Errorf("oidc.cookie.name %q is not a valid cookie name", ck.Name)
			}
			o.name = ck.Name
		}
		if ck.Secure != nil {
			o.secure = *ck.Secure
		}
		switch strings.ToLower(ck.SameSite) {
		case "", "lax":
		case "strict":
			o.sameSite = http.SameSiteStrictMode
		case "none":
			o.sameSite = http.SameSiteNoneMode
			if !o.secure {
				return nil, errors.New("oidc.cookie: sameSite None requires secure")
			}
		default:
			return nil, fmt.Errorf("oidc.cookie.sameSite %q: want Lax, Strict or None", ck.SameSite)
		}
		if ck.Path != "" && !strings.HasPrefix(ck.Path, "/") {
			return nil, errors.New("oidc.cookie.path must start with /")
		}
		if strings.ContainsAny(ck.Domain, " ;,\r\n") {
			return nil, errors.New("oidc.cookie.domain is not a valid domain")
		}
	}
	if strings.HasPrefix(o.name, "__Host-") && (!o.secure || (p.Cookie != nil && (p.Cookie.Domain != "" || (p.Cookie.Path != "" && p.Cookie.Path != "/")))) {
		return nil, errors.New("oidc.cookie: a __Host- cookie must be secure, without domain, with path /")
	}
	if p.SessionTTL != "" {
		d, err := time.ParseDuration(p.SessionTTL)
		if err != nil || d < time.Minute || d > 30*24*time.Hour {
			return nil, fmt.Errorf("oidc.sessionTtl %q: want a duration from 1m to 720h", p.SessionTTL)
		}
		o.ttl = d
	}
	if p.ClockSkew != "" {
		d, err := time.ParseDuration(p.ClockSkew)
		if err != nil || d < 0 || d > time.Hour {
			return nil, fmt.Errorf("oidc.clockSkew %q: want a duration from 0 to 1h", p.ClockSkew)
		}
		o.skew = d
	}
	switch p.DenyRedirect {
	case "", "auto":
	case "always", "never":
		o.silent = p.DenyRedirect
	default:
		return nil, fmt.Errorf("oidc.denyRedirect %q: want auto, always or never", p.DenyRedirect)
	}
	for _, e := range []struct{ n, v string }{{"authorizationEndpoint", p.AuthorizationEndpoint}, {"tokenEndpoint", p.TokenEndpoint},
		{"jwksUri", p.JWKSURI}, {"userinfoEndpoint", p.UserinfoEndpoint}, {"endSessionEndpoint", p.EndSessionEndpoint}} {
		if e.v != "" {
			if _, ok := httpURL(e.v); !ok {
				return nil, fmt.Errorf("oidc.%s %s: want an http(s) URL", e.n, redactURL(e.v))
			}
		}
	}
	for k := range p.AuthParams {
		switch k {
		case "", "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method":
			return nil, fmt.Errorf("oidc.authParams: %q is set by the gateway", k)
		}
	}
	for h := range p.ClaimHeaders {
		if h == "" || strings.ContainsAny(h, " :\r\n") {
			return nil, fmt.Errorf("oidc.claimHeaders: bad header name %q", h)
		}
		o.own = append(o.own, h)
	}
	for _, h := range []string{p.AccessTokenHeader, p.IDTokenHeader} {
		if h != "" {
			if strings.ContainsAny(h, " :\r\n") || strings.EqualFold(h, "host") {
				return nil, fmt.Errorf("oidc: bad header name %q", h)
			}
			o.own = append(o.own, h)
		}
	}
	if p.AccessTokenScheme != "" && p.AccessTokenHeader == "" {
		return nil, errors.New("oidc.accessTokenScheme needs accessTokenHeader")
	}
	if len(p.SessionClaims) > 0 {
		o.keepClaims = map[string]bool{}
		for _, c := range p.SessionClaims {
			o.keepClaims[c] = true
		}
	}
	o.prov = sharedOIDCProvider(p)
	return o, nil
}

// ---- provider: discovery and token endpoint ----

type oidcEndpoints struct{ issuer, authz, token, jwks, userinfo, endSession string }

type oidcProvider struct {
	issuer string
	over   oidcEndpoints
	client *http.Client

	mu          sync.Mutex
	ep          *oidcEndpoints
	fetchedAt   time.Time
	lastAttempt time.Time
	lastErr     string
	fetches     int
}

var (
	oidcMu       sync.Mutex
	oidcRegistry = map[string]*oidcProvider{}
)

func sharedOIDCProvider(p *OIDCPolicy) *oidcProvider {
	over := oidcEndpoints{p.Issuer, p.AuthorizationEndpoint, p.TokenEndpoint, p.JWKSURI, p.UserinfoEndpoint, p.EndSessionEndpoint}
	key := strings.Join([]string{over.issuer, over.authz, over.token, over.jwks, over.userinfo, over.endSession}, "\x00")
	oidcMu.Lock()
	defer oidcMu.Unlock()
	if pr := oidcRegistry[key]; pr != nil {
		return pr
	}
	pr := &oidcProvider{issuer: p.Issuer, over: over, client: &http.Client{Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	oidcRegistry[key] = pr
	return pr
}

type errOIDC struct {
	msg       string
	temporary bool
}

func (e *errOIDC) Error() string { return e.msg }

func (pr *oidcProvider) fetchJSON(method, rawURL string, body io.Reader, hdr map[string]string, out any) (int, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return 0, errors.New("bad URL")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := pr.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, fmt.Errorf("%s: %w", redactURL(rawURL), err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, oidcMaxBody+1))
	if err != nil || len(b) > oidcMaxBody {
		return resp.StatusCode, fmt.Errorf("%s: unreadable or oversized body", redactURL(rawURL))
	}
	if out != nil && len(b) > 0 {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		if err := dec.Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s: the response is not JSON", redactURL(rawURL))
		}
	}
	return resp.StatusCode, nil
}

// endpoints returns the provider's endpoints, discovering them at most once
// an hour and retrying a failed discovery at most every 10 seconds.
func (pr *oidcProvider) endpoints(now time.Time) (*oidcEndpoints, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if pr.ep != nil && now.Sub(pr.fetchedAt) < oidcDiscoverTTL {
		return pr.ep, nil
	}
	if !pr.lastAttempt.IsZero() && now.Sub(pr.lastAttempt) < oidcRetryAfter && now.After(pr.lastAttempt) {
		if pr.ep != nil {
			return pr.ep, nil
		}
		return nil, &errOIDC{"identity provider discovery failed: " + pr.lastErr, true}
	}
	pr.lastAttempt = now
	if o := pr.over; o.authz != "" && o.token != "" && o.jwks != "" {
		e := o
		pr.ep, pr.fetchedAt, pr.lastErr = &e, now, ""
		return pr.ep, nil
	}
	var doc struct {
		Issuer     string   `json:"issuer"`
		Authz      string   `json:"authorization_endpoint"`
		Token      string   `json:"token_endpoint"`
		JWKS       string   `json:"jwks_uri"`
		Userinfo   string   `json:"userinfo_endpoint"`
		EndSession string   `json:"end_session_endpoint"`
		PKCE       []string `json:"code_challenge_methods_supported"`
	}
	pr.fetches++
	st, err := pr.fetchJSON(http.MethodGet, strings.TrimSuffix(pr.issuer, "/")+"/.well-known/openid-configuration", nil, nil, &doc)
	fail := func(format string, a ...any) (*oidcEndpoints, error) {
		pr.lastErr = fmt.Sprintf(format, a...)
		if pr.ep != nil { // stale on error
			return pr.ep, nil
		}
		return nil, &errOIDC{"identity provider discovery failed: " + pr.lastErr, true}
	}
	switch {
	case err != nil:
		return fail("%v", err)
	case st != http.StatusOK:
		return fail("status %d", st)
	case doc.Issuer != pr.issuer:
		return fail("the discovery document's issuer %q is not the configured issuer", clip(doc.Issuer, 80))
	case len(doc.PKCE) > 0 && !containsStr(doc.PKCE, "S256"):
		return fail("the provider does not support PKCE S256")
	}
	e := &oidcEndpoints{issuer: doc.Issuer, authz: doc.Authz, token: doc.Token, jwks: doc.JWKS, userinfo: doc.Userinfo, endSession: doc.EndSession}
	for _, ov := range []struct {
		dst *string
		v   string
	}{{&e.authz, pr.over.authz}, {&e.token, pr.over.token}, {&e.jwks, pr.over.jwks}, {&e.userinfo, pr.over.userinfo}, {&e.endSession, pr.over.endSession}} {
		if ov.v != "" {
			*ov.dst = ov.v
		}
	}
	for n, v := range map[string]string{"authorization_endpoint": e.authz, "token_endpoint": e.token, "jwks_uri": e.jwks} {
		if _, ok := httpURL(v); !ok {
			return fail("the discovery document has no usable %s", n)
		}
	}
	for _, v := range []string{e.userinfo, e.endSession} {
		if v != "" {
			if _, ok := httpURL(v); !ok {
				return fail("the discovery document has an unusable endpoint URL")
			}
		}
	}
	pr.ep, pr.fetchedAt, pr.lastErr = e, now, ""
	return e, nil
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- secrets and the sealed cookie ----

func (o *compiledOIDC) keyStrings(sec *authSecrets) []string {
	if sec == nil {
		return nil
	}
	var out []string
	for _, k := range sec.cookieKeys {
		if k != nil {
			if v := k.get(); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func deriveKey(label, secret string) []byte {
	h := sha256.Sum256([]byte("setura/oidc/" + label + "\x00" + secret))
	return h[:]
}

func compress(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestSpeed)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

func decompress(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, 256<<10+1))
	if err != nil || len(out) > 256<<10 {
		return nil, errors.New("bad session payload")
	}
	return out, nil
}

// seal protects plain with the first key. name binds the value to its cookie.
func (o *compiledOIDC) seal(keys []string, name string, plain []byte) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("no cookie key")
	}
	z := compress(plain)
	if o.signed {
		mac := hmac.New(sha256.New, deriveKey("mac", keys[0]))
		mac.Write([]byte(name + "\x00"))
		mac.Write(z)
		return "s1." + base64.RawURLEncoding.EncodeToString(z) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
	}
	blk, err := aes.NewCipher(deriveKey("enc", keys[0]))
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return "e1." + base64.RawURLEncoding.EncodeToString(g.Seal(nonce, nonce, z, []byte(name))), nil
}

// open reverses seal with any key; idx is the position of the key that worked.
func (o *compiledOIDC) open(keys []string, name, v string) (plain []byte, idx int, err error) {
	bad := errors.New("session cookie is not valid")
	if o.signed {
		parts := strings.Split(v, ".")
		if len(parts) != 3 || parts[0] != "s1" {
			return nil, 0, bad
		}
		z, e1 := base64.RawURLEncoding.DecodeString(parts[1])
		sig, e2 := base64.RawURLEncoding.DecodeString(parts[2])
		if e1 != nil || e2 != nil {
			return nil, 0, bad
		}
		for i, k := range keys {
			mac := hmac.New(sha256.New, deriveKey("mac", k))
			mac.Write([]byte(name + "\x00"))
			mac.Write(z)
			if hmac.Equal(mac.Sum(nil), sig) {
				p, err := decompress(z)
				return p, i, err
			}
		}
		return nil, 0, bad
	}
	if !strings.HasPrefix(v, "e1.") {
		return nil, 0, bad
	}
	raw, err := base64.RawURLEncoding.DecodeString(v[3:])
	if err != nil {
		return nil, 0, bad
	}
	for i, k := range keys {
		blk, err := aes.NewCipher(deriveKey("enc", k))
		if err != nil {
			continue
		}
		g, err := cipher.NewGCM(blk)
		if err != nil || len(raw) < g.NonceSize()+g.Overhead() {
			continue
		}
		z, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte(name))
		if err == nil {
			p, err := decompress(z)
			return p, i, err
		}
	}
	return nil, 0, bad
}

func chunkName(name string, n int) string {
	if n == 0 {
		return name
	}
	return name + "_" + strconv.Itoa(n)
}

// readCookie joins the chunks of a cookie that was too long for one.
func (o *compiledOIDC) readCookie(r *http.Request, name string) string {
	var sb strings.Builder
	for n := 0; n < oidcMaxChunks; n++ {
		c, err := r.Cookie(chunkName(name, n))
		if err != nil {
			break
		}
		sb.WriteString(c.Value)
	}
	return sb.String()
}

func (o *compiledOIDC) cookieAttrs(c *http.Cookie, https bool) {
	c.HttpOnly = true
	c.Secure = o.secure
	c.SameSite = o.sameSite
	c.Path = "/"
	if ck := o.p.Cookie; ck != nil {
		c.Domain = ck.Domain
		if ck.Path != "" {
			c.Path = ck.Path
		}
	}
}

// setCookies returns the cookies that store value (expiring leftover chunks
// the request carried).
func (o *compiledOIDC) setCookies(r *http.Request, name, value string, exp time.Time, https bool) []*http.Cookie {
	var out []*http.Cookie
	n := 0
	for len(value) > 0 || n == 0 {
		part := value
		if len(part) > oidcChunkSize {
			part = part[:oidcChunkSize]
		}
		value = value[len(part):]
		c := &http.Cookie{Name: chunkName(name, n), Value: part, Expires: exp}
		o.cookieAttrs(c, https)
		out = append(out, c)
		n++
	}
	for ; n < oidcMaxChunks; n++ {
		if _, err := r.Cookie(chunkName(name, n)); err == nil {
			out = append(out, o.expired(chunkName(name, n), https))
		}
	}
	return out
}

func (o *compiledOIDC) expired(name string, https bool) *http.Cookie {
	c := &http.Cookie{Name: name, Value: "", MaxAge: -1, Expires: time.Unix(1, 0)}
	o.cookieAttrs(c, https)
	return c
}

func (o *compiledOIDC) clearSession(r *http.Request, https bool) []*http.Cookie {
	var out []*http.Cookie
	for n := 0; n < oidcMaxChunks; n++ {
		if _, err := r.Cookie(chunkName(o.name, n)); err == nil || n == 0 {
			out = append(out, o.expired(chunkName(o.name, n), https))
		}
	}
	return out
}

func (o *compiledOIDC) txName(state string) string {
	return o.name + "_tx_" + state[:10]
}

// ---- session ----

type oidcSession struct {
	Sub    string         `json:"sub"`
	Claims map[string]any `json:"c"`
	AT     string         `json:"at,omitempty"`
	RT     string         `json:"rt,omitempty"`
	IDT    string         `json:"idt,omitempty"`
	ATExp  int64          `json:"ate,omitempty"`
	Exp    int64          `json:"exp"`
	Iat    int64          `json:"iat"`
}

func decodeSession(b []byte) (*oidcSession, error) {
	var s oidcSession
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&s); err != nil || s.Sub == "" || s.Claims == nil {
		return nil, errors.New("bad session")
	}
	return &s, nil
}

func (o *compiledOIDC) storeSession(r *http.Request, s *oidcSession, keys []string, https bool) ([]*http.Cookie, error) {
	b, _ := json.Marshal(s)
	v, err := o.seal(keys, o.name, b)
	if err != nil {
		return nil, err
	}
	if len(v) > oidcMaxChunks*oidcChunkSize {
		return nil, errors.New("the session is too large for a cookie; set oidc.sessionClaims to keep fewer claims")
	}
	return o.setCookies(r, o.name, v, time.Unix(s.Exp, 0), https), nil
}

type tokenResponse struct {
	AccessToken  string      `json:"access_token"`
	TokenType    string      `json:"token_type"`
	ExpiresIn    json.Number `json:"expires_in"`
	RefreshToken string      `json:"refresh_token"`
	IDToken      string      `json:"id_token"`
	Error        string      `json:"error"`
}

var errCodeRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,40}$`)

func safeCode(s string) string {
	if errCodeRE.MatchString(s) {
		return s
	}
	return "unknown_error"
}

// tokenCall posts a token request.
func (o *compiledOIDC) tokenCall(ep *oidcEndpoints, form url.Values, sec *authSecrets) (*tokenResponse, *errOIDC) {
	form.Set("client_id", o.p.ClientID)
	hdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if cs := sec.client(); cs != "" {
		if o.p.TokenAuthMethod == "client_secret_post" {
			form.Set("client_secret", cs)
		} else {
			hdr["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(o.p.ClientID)+":"+url.QueryEscape(cs)))
		}
	}
	var tr tokenResponse
	st, err := o.prov.fetchJSON(http.MethodPost, ep.token, strings.NewReader(form.Encode()), hdr, &tr)
	switch {
	case err != nil:
		return nil, &errOIDC{"token endpoint: " + err.Error(), true}
	case st >= 500:
		return nil, &errOIDC{fmt.Sprintf("token endpoint answered %d", st), true}
	case st != http.StatusOK:
		return nil, &errOIDC{"token endpoint refused the request: " + safeCode(tr.Error), false}
	case tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "bearer") && tr.TokenType != "":
		return nil, &errOIDC{"token endpoint returned no bearer access token", false}
	}
	return &tr, nil
}

func (o *compiledOIDC) verifier(ep *oidcEndpoints) (*jwtVerifier, error) {
	o.vmu.Lock()
	defer o.vmu.Unlock()
	if o.v != nil && o.vu == ep.jwks {
		return o.v, nil
	}
	aud := []string{o.p.ClientID}
	v, err := compileJWT(&JWTPolicy{Issuer: o.p.Issuer, Audience: aud, JWKSURI: ep.jwks, ClockSkew: o.skew.String()})
	if err != nil {
		return nil, err
	}
	o.v, o.vu = v, ep.jwks
	return v, nil
}

// checkIDToken validates an ID token: the JWT checks plus azp and nonce.
func (o *compiledOIDC) checkIDToken(ep *oidcEndpoints, idt, nonce string, now time.Time) (jwtClaims, error) {
	v, err := o.verifier(ep)
	if err != nil {
		return nil, err
	}
	claims, je := v.verify(idt, now, false)
	if je != nil {
		return nil, fmt.Errorf("ID token: %s", je.desc)
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil, errors.New("ID token: no sub claim")
	}
	if azp, ok := claims["azp"].(string); ok && azp != o.p.ClientID {
		return nil, errors.New("ID token: authorized party is not this client")
	}
	if aud, ok := claims["aud"].([]any); ok && len(aud) > 1 {
		if azp, _ := claims["azp"].(string); azp != o.p.ClientID {
			return nil, errors.New("ID token: several audiences and no matching azp")
		}
	}
	if nonce != "" {
		if n, _ := claims["nonce"].(string); subtle.ConstantTimeCompare([]byte(n), []byte(nonce)) != 1 {
			return nil, errors.New("ID token: nonce does not match")
		}
	}
	return claims, nil
}

func (o *compiledOIDC) buildSession(tr *tokenResponse, claims jwtClaims, now time.Time, prev *oidcSession) *oidcSession {
	s := &oidcSession{Claims: map[string]any{}, Iat: now.Unix(), Exp: now.Add(o.ttl).Unix()}
	if prev != nil {
		s.Iat, s.Exp = prev.Iat, prev.Exp
	}
	for k, v := range claims {
		if o.keepClaims == nil || o.keepClaims[k] || k == "sub" || k == "iss" || k == "exp" {
			s.Claims[k] = v
		}
	}
	s.Sub, _ = claims["sub"].(string)
	s.AT, s.IDT = tr.AccessToken, tr.IDToken
	if !o.p.DisableRefresh {
		s.RT = tr.RefreshToken
	}
	if n, err := tr.ExpiresIn.Int64(); err == nil && n > 0 {
		s.ATExp = now.Add(time.Duration(n) * time.Second).Unix()
	} else if exp, ok, _ := numericDate(claims, "exp"); ok {
		s.ATExp = exp.Unix()
	}
	return s
}

// ---- refresh ----

type refreshCall struct {
	done chan struct{}
	sess *oidcSession
	err  *errOIDC
}

type refreshDone struct {
	sess *oidcSession
	at   time.Time
}

func (o *compiledOIDC) refresh(sess *oidcSession, now time.Time, sec *authSecrets) (*oidcSession, *errOIDC) {
	h := sha256.Sum256([]byte(sess.RT))
	key := hex.EncodeToString(h[:8])
	o.rmu.Lock()
	if d, ok := o.recent[key]; ok && absDur(now.Sub(d.at)) < 15*time.Second {
		o.rmu.Unlock()
		return d.sess, nil
	}
	if c, ok := o.inflight[key]; ok {
		o.rmu.Unlock()
		<-c.done
		return c.sess, c.err
	}
	c := &refreshCall{done: make(chan struct{})}
	if o.inflight == nil {
		o.inflight, o.recent = map[string]*refreshCall{}, map[string]refreshDone{}
	}
	o.inflight[key] = c
	o.rmu.Unlock()

	c.sess, c.err = o.doRefresh(sess, now, sec)

	o.rmu.Lock()
	delete(o.inflight, key)
	if c.err == nil {
		for k, d := range o.recent {
			if absDur(now.Sub(d.at)) >= 15*time.Second {
				delete(o.recent, k)
			}
		}
		if len(o.recent) < 1024 {
			o.recent[key] = refreshDone{c.sess, now}
		}
	}
	o.rmu.Unlock()
	close(c.done)
	return c.sess, c.err
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func (o *compiledOIDC) doRefresh(sess *oidcSession, now time.Time, sec *authSecrets) (*oidcSession, *errOIDC) {
	ep, err := o.prov.endpoints(now)
	if err != nil {
		return nil, &errOIDC{err.Error(), true}
	}
	tr, e := o.tokenCall(ep, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {sess.RT}}, sec)
	if e != nil {
		return nil, e
	}
	claims := jwtClaims(sess.Claims)
	if tr.IDToken != "" {
		c, err := o.checkIDToken(ep, tr.IDToken, "", now)
		if err != nil {
			return nil, &errOIDC{err.Error(), false}
		}
		if sub, _ := c["sub"].(string); sub != sess.Sub {
			return nil, &errOIDC{"the refreshed ID token is for another subject", false}
		}
		claims = c
	} else {
		tr.IDToken = sess.IDT
	}
	ns := o.buildSession(tr, claims, now, sess)
	if ns.RT == "" && !o.p.DisableRefresh {
		ns.RT = sess.RT
	}
	return ns, nil
}

// ---- evaluation (no side effects but the refresh round trip) ----

// oidcLogin is the evaluation of the session cookie.
type oidcOutcome struct {
	sess     *oidcSession
	cookies  []*http.Cookie
	reason   string
	login    bool // no valid session: log in (or 401)
	unknown  string
	status   int // 503 when the provider is unreachable
	event    string
	refreshE string
}

func (o *compiledOIDC) session(in authInput, sec *authSecrets) oidcOutcome {
	r := in.r
	raw := o.readCookie(r, o.name)
	if raw == "" {
		return oidcOutcome{login: true, reason: "oidc: no session cookie"}
	}
	keys := o.keyStrings(sec)
	if len(keys) == 0 {
		if in.offline {
			return oidcOutcome{unknown: "oidc: the session cookie cannot be opened without the cookie keys (they are read from env, file or Secret on a running gateway)"}
		}
		return oidcOutcome{status: http.StatusInternalServerError, reason: "oidc: the cookie keys are not available"}
	}
	plain, idx, err := o.open(keys, o.name, raw)
	if err != nil {
		return oidcOutcome{login: true, reason: "oidc: session cookie is not valid", event: "session_invalid", cookies: o.clearSession(r, in.https)}
	}
	sess, err := decodeSession(plain)
	if err != nil {
		return oidcOutcome{login: true, reason: "oidc: session cookie is not valid", event: "session_invalid", cookies: o.clearSession(r, in.https)}
	}
	if !in.now.Before(time.Unix(sess.Exp, 0)) {
		return oidcOutcome{login: true, reason: "oidc: the session has expired", event: "session_invalid", cookies: o.clearSession(r, in.https)}
	}
	expired := sess.ATExp > 0 && !in.now.Before(time.Unix(sess.ATExp, 0).Add(-oidcRefreshLead))
	var out oidcOutcome
	switch {
	case expired && sess.RT != "" && !o.p.DisableRefresh:
		if in.offline {
			return oidcOutcome{unknown: "oidc: the tokens in the session have expired and are refreshed against the provider, which an offline view does not do"}
		}
		ns, e := o.refresh(sess, in.now, sec)
		if e != nil {
			if e.temporary {
				return oidcOutcome{status: http.StatusServiceUnavailable, reason: "oidc: the identity provider is not reachable to refresh the session", event: "refresh_failed"}
			}
			return oidcOutcome{login: true, reason: "oidc: the session could not be refreshed (" + clip(e.msg, 80) + ")", event: "refresh_failed", cookies: o.clearSession(r, in.https)}
		}
		cs, err := o.storeSession(r, ns, keys, in.https)
		if err != nil {
			return oidcOutcome{status: http.StatusInternalServerError, reason: "oidc: " + err.Error()}
		}
		sess, out.cookies, out.event = ns, cs, "refresh_succeeded"
	case expired && o.p.AccessTokenHeader != "":
		return oidcOutcome{login: true, reason: "oidc: the access token has expired and the session has no refresh token", event: "session_invalid", cookies: o.clearSession(r, in.https)}
	case idx != 0: // sealed with an older key: reissue with the first one
		if cs, err := o.storeSession(r, sess, keys, in.https); err == nil {
			out.cookies = cs
		}
	}
	out.sess = sess
	return out
}

// denySilently says whether an unauthenticated request gets 401 instead of
// a redirect to the provider.
func (o *compiledOIDC) denySilently(r *http.Request) bool {
	switch o.silent {
	case "always":
		return false
	case "never":
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") || r.Header.Get("Authorization") != "" ||
		(r.Method != http.MethodGet && r.Method != http.MethodHead) ||
		!strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		return true
	}
	m := r.Header.Get("Sec-Fetch-Mode")
	return m != "" && m != "navigate"
}

// forwarded returns the headers an authenticated session adds upstream.
func (o *compiledOIDC) forwarded(sess *oidcSession) map[string]string {
	h := map[string]string{}
	for _, name := range sortedKeys(o.p.ClaimHeaders) {
		if v, ok := claimAt(sess.Claims, o.p.ClaimHeaders[name]); ok {
			if s := claimHeaderValue(v); s != "" {
				h[name] = s
			}
		}
	}
	if o.p.AccessTokenHeader != "" && sess.AT != "" {
		v := sess.AT
		if o.p.AccessTokenScheme != "" {
			v = o.p.AccessTokenScheme + " " + v
		}
		h[o.p.AccessTokenHeader] = cleanHeaderValue(v)
	}
	if o.p.IDTokenHeader != "" && sess.IDT != "" {
		h[o.p.IDTokenHeader] = cleanHeaderValue(sess.IDT)
	}
	return h
}

// stripCookies removes the gateway's cookies from the request sent upstream.
func (o *compiledOIDC) stripCookies(r *http.Request) {
	if o.p.ForwardCookies {
		return
	}
	cs := r.Cookies()
	if len(cs) == 0 {
		return
	}
	r.Header.Del("Cookie")
	for _, c := range cs {
		if c.Name == o.name || strings.HasPrefix(c.Name, o.name+"_") {
			continue
		}
		r.AddCookie(c)
	}
}

// ---- the flow: login, callback, logout ----

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// redirectURI is the absolute callback URL.
func (o *compiledOIDC) redirectURI(r *http.Request, https bool) string {
	if o.redirect.Scheme != "" {
		return o.redirect.String()
	}
	return o.absolute(r, https, o.redirect.Path)
}

func (o *compiledOIDC) absolute(r *http.Request, https bool, path string) string {
	scheme := "http"
	if https {
		scheme = "https"
	}
	return scheme + "://" + r.Host + path
}

// ownsPath reports whether a request is for the callback or the logout path
// of this policy.
func (o *compiledOIDC) ownsHost(r *http.Request) bool {
	return o.redirect.Scheme == "" || strings.EqualFold(o.redirect.Host, r.Host)
}

func safeReturn(r *http.Request, cb string) string {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "/"
	}
	u := r.URL.RequestURI()
	if !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") || strings.ContainsAny(u, "\\\r\n") || len(u) > 2000 || r.URL.Path == cb {
		return "/"
	}
	return u
}

type oidcTx struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Return   string `json:"r"`
	Exp      int64  `json:"e"`
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func oidcFail(w http.ResponseWriter, code int, msg string) {
	noStore(w)
	jsonError(w, code, "login_failed", msg)
}

// jsonError answers with a small JSON document.
func jsonError(w http.ResponseWriter, code int, kind, msg string, extra ...string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	m := map[string]string{"error": kind, "message": msg}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	b, _ := json.Marshal(m)
	w.Write(append(b, '\n'))
}

// startLogin redirects the browser to the provider.
func (o *compiledOIDC) startLogin(w http.ResponseWriter, r *http.Request, now time.Time, https bool, sec *authSecrets, ev func(string)) {
	keys := o.keyStrings(sec)
	if len(keys) == 0 {
		jsonError(w, http.StatusInternalServerError, "login_unavailable", "the login is not configured completely")
		return
	}
	ep, err := o.prov.endpoints(now)
	if err != nil {
		noStore(w)
		jsonError(w, http.StatusServiceUnavailable, "login_unavailable", "the identity provider is not reachable")
		return
	}
	tx := oidcTx{State: randToken(24), Nonce: randToken(16), Verifier: randToken(32), Return: safeReturn(r, o.cbPath), Exp: now.Add(oidcTxTTL).Unix()}
	b, _ := json.Marshal(tx)
	name := o.txName(tx.State)
	v, err := o.seal(keys, name, b)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "login_unavailable", "the login state could not be protected")
		return
	}
	c := &http.Cookie{Name: name, Value: v, Expires: now.Add(oidcTxTTL)}
	o.cookieAttrs(c, https)
	c.SameSite, c.Path = http.SameSiteLaxMode, o.cbPath // the callback is a cross-site navigation
	http.SetCookie(w, c)
	ch := sha256.Sum256([]byte(tx.Verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {o.p.ClientID}, "redirect_uri": {o.redirectURI(r, https)},
		"scope": {strings.Join(o.scopes, " ")}, "state": {tx.State}, "nonce": {tx.Nonce},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(ch[:])}, "code_challenge_method": {"S256"}}
	for k, v := range o.p.AuthParams {
		q.Set(k, v)
	}
	loc := ep.authz
	if strings.Contains(loc, "?") {
		loc += "&"
	} else {
		loc += "?"
	}
	noStore(w)
	ev("login_started")
	http.Redirect(w, r, loc+q.Encode(), http.StatusFound)
}

// callback finishes the login.
func (o *compiledOIDC) callback(w http.ResponseWriter, r *http.Request, now time.Time, https bool, sec *authSecrets, ev func(string)) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the login callback only accepts GET")
		return
	}
	fail := func(code int, msg string) { ev("login_failed"); oidcFail(w, code, msg) }
	q := r.URL.Query()
	state := q.Get("state")
	if len(state) < 10 || len(state) > 128 || strings.ContainsAny(state, " \"';") {
		fail(http.StatusBadRequest, "the login response has no valid state")
		return
	}
	txName := o.txName(state)
	for _, c := range o.expiredTx(txName, https) {
		http.SetCookie(w, c)
	}
	keys := o.keyStrings(sec)
	if len(keys) == 0 {
		fail(http.StatusInternalServerError, "the login is not configured completely")
		return
	}
	cv, cerr := r.Cookie(txName)
	if cerr != nil {
		fail(http.StatusBadRequest, "the login was not started here or took too long; try again")
		return
	}
	plain, _, err := o.open(keys, txName, cv.Value)
	var tx oidcTx
	if err != nil || json.Unmarshal(plain, &tx) != nil || subtle.ConstantTimeCompare([]byte(tx.State), []byte(state)) != 1 || now.Unix() >= tx.Exp {
		fail(http.StatusBadRequest, "the login state is not valid or has expired; try again")
		return
	}
	if e := q.Get("error"); e != "" {
		fail(http.StatusUnauthorized, "the identity provider refused the login: "+safeCode(e))
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		fail(http.StatusBadRequest, "the login response has no code")
		return
	}
	ep, err := o.prov.endpoints(now)
	if err != nil {
		fail(http.StatusServiceUnavailable, "the identity provider is not reachable")
		return
	}
	tr, e := o.tokenCall(ep, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {o.redirectURI(r, https)}, "code_verifier": {tx.Verifier}}, sec)
	if e != nil {
		code := http.StatusUnauthorized
		if e.temporary {
			code = http.StatusServiceUnavailable
		}
		fail(code, "the code could not be exchanged for tokens")
		return
	}
	if tr.IDToken == "" {
		fail(http.StatusUnauthorized, "the provider returned no ID token (is the openid scope allowed for this client?)")
		return
	}
	claims, err := o.checkIDToken(ep, tr.IDToken, tx.Nonce, now)
	if err != nil {
		fail(http.StatusUnauthorized, err.Error())
		return
	}
	if o.p.Userinfo && ep.userinfo != "" {
		var ui map[string]any
		if st, err := o.prov.fetchJSON(http.MethodGet, ep.userinfo, nil, map[string]string{"Authorization": "Bearer " + tr.AccessToken}, &ui); err != nil || st != http.StatusOK {
			fail(http.StatusUnauthorized, "the userinfo endpoint refused the access token")
			return
		}
		if sub, _ := ui["sub"].(string); sub != claims["sub"] {
			fail(http.StatusUnauthorized, "the userinfo subject is not the ID token's")
			return
		}
		for k, v := range ui {
			if _, have := claims[k]; !have {
				claims[k] = v
			}
		}
	}
	sess := o.buildSession(tr, claims, now, nil)
	cs, err := o.storeSession(r, sess, keys, https)
	if err != nil {
		fail(http.StatusInternalServerError, err.Error())
		return
	}
	for _, c := range cs {
		http.SetCookie(w, c)
	}
	ev("login_succeeded")
	noStore(w)
	http.Redirect(w, r, tx.Return, http.StatusFound)
}

func (o *compiledOIDC) expiredTx(name string, https bool) []*http.Cookie {
	c := o.expired(name, https)
	c.Path = o.cbPath
	c.SameSite = http.SameSiteLaxMode
	return []*http.Cookie{c}
}

// logout clears the session and continues at the provider's end-session endpoint.
func (o *compiledOIDC) logout(w http.ResponseWriter, r *http.Request, now time.Time, https bool, sec *authSecrets, csrf *compiledCSRF, ev func(string)) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, POST")
		jsonError(w, http.StatusMethodNotAllowed, "method_not_allowed", "logout accepts GET and POST")
		return
	}
	if why := csrf.check(r, https); why != "" {
		jsonError(w, http.StatusForbidden, "forbidden", "logout refused: "+why)
		return
	}
	hint := ""
	if keys := o.keyStrings(sec); len(keys) > 0 {
		if raw := o.readCookie(r, o.name); raw != "" {
			if plain, _, err := o.open(keys, o.name, raw); err == nil {
				if s, err := decodeSession(plain); err == nil {
					hint = s.IDT
				}
			}
		}
	}
	for _, c := range o.clearSession(r, https) {
		http.SetCookie(w, c)
	}
	ev("logout")
	noStore(w)
	post := o.p.PostLogoutRedirectURL
	if post != "" && strings.HasPrefix(post, "/") {
		post = o.absolute(r, https, post)
	}
	if ep, err := o.prov.endpoints(now); err == nil && ep.endSession != "" {
		q := url.Values{"client_id": {o.p.ClientID}}
		if hint != "" {
			q.Set("id_token_hint", hint)
		}
		if post != "" {
			q.Set("post_logout_redirect_uri", post)
		}
		sep := "?"
		if strings.Contains(ep.endSession, "?") {
			sep = "&"
		}
		http.Redirect(w, r, ep.endSession+sep+q.Encode(), http.StatusFound)
		return
	}
	if post == "" {
		post = "/"
	}
	http.Redirect(w, r, post, http.StatusFound)
}
