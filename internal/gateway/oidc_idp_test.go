package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClock is the injectable, deterministic clock of the OIDC tests: the
// gateway (Options.AuthClock) and the fake provider read the same one.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: t0} }

func (c *testClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

const (
	idpRealm     = "/realms/haven"
	idpOIDC      = idpRealm + "/protocol/openid-connect"
	idpClientID  = "haven-app"
	secretClient = "cs-SENTINEL-client-secret-7c1e"
	secretInject = "inj-SENTINEL-upstream-token-55aa"
	secretKeyA   = "ck-SENTINEL-cookie-key-A-0123456789abcdef"
	secretKeyB   = "ck-SENTINEL-cookie-key-B-0123456789abcdef"
)

type idpCode struct {
	nonce, challenge, redirect, scope string
	used                              bool
}

// fakeIdP is a Keycloak-shaped OpenID provider on 127.0.0.1:0: discovery,
// authorize, token, jwks, userinfo and end_session.
type fakeIdP struct {
	*httptest.Server
	t      *testing.T
	key    *jwtKey
	clock  *testClock
	issuer string

	mu            sync.Mutex
	codes         map[string]idpCode
	refreshTokens map[string]bool // value: already used
	n             int
	discoveries   int
	tokenCalls    int
	refreshCalls  int
	jwksCalls     int
	authzQuery    url.Values
	tokenForms    []url.Values
	logoutQuery   url.Values

	// knobs
	postAuth      bool          // expect client_secret_post instead of Basic
	revokeRefresh bool          // a refresh token works once (rotation)
	tokenStatus   int           // when set, the token endpoint answers this status
	badNonce      bool          // ID token carries another nonce
	idIssuer      string        // overrides iss in the ID token
	idAud         string        // overrides aud in the ID token
	atTTL         time.Duration // lifetime of tokens (default 5m)
	roles         []string
	noRefresh     bool
	discIssuer    string // issuer the discovery document claims
	noEndSession  bool
}

func newFakeIdP(t *testing.T, clock *testClock) *fakeIdP {
	t.Helper()
	p := &fakeIdP{t: t, key: newRSAKey(t, "kc-1"), clock: clock, codes: map[string]idpCode{}, refreshTokens: map[string]bool{},
		atTTL: 5 * time.Minute, roles: []string{"user"}}
	mux := http.NewServeMux()
	mux.HandleFunc(idpRealm+"/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc(idpOIDC+"/auth", p.authorize)
	mux.HandleFunc(idpOIDC+"/token", p.token)
	mux.HandleFunc(idpOIDC+"/certs", p.certs)
	mux.HandleFunc(idpOIDC+"/userinfo", p.userinfo)
	mux.HandleFunc(idpOIDC+"/logout", p.logout)
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	p.issuer = p.URL + idpRealm
	return p
}

func (p *fakeIdP) stat(f func()) { p.mu.Lock(); f(); p.mu.Unlock() }
func (p *fakeIdP) get(f func() int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return f()
}

func (p *fakeIdP) discovery(w http.ResponseWriter, r *http.Request) {
	p.stat(func() { p.discoveries++ })
	iss := p.issuer
	if p.discIssuer != "" {
		iss = p.discIssuer
	}
	doc := m{"issuer": iss, "authorization_endpoint": p.URL + idpOIDC + "/auth", "token_endpoint": p.URL + idpOIDC + "/token",
		"jwks_uri": p.URL + idpOIDC + "/certs", "userinfo_endpoint": p.URL + idpOIDC + "/userinfo",
		"introspection_endpoint": p.URL + idpOIDC + "/token/introspect", "grant_types_supported": l{"authorization_code", "refresh_token"},
		"response_types_supported": l{"code", "none", "id_token", "token"}, "subject_types_supported": l{"public", "pairwise"},
		"id_token_signing_alg_values_supported": l{"RS256", "ES256"}, "code_challenge_methods_supported": l{"plain", "S256"},
		"token_endpoint_auth_methods_supported": l{"client_secret_basic", "client_secret_post"}, "claims_supported": l{"sub", "iss", "preferred_username"}}
	if !p.noEndSession {
		doc["end_session_endpoint"] = p.URL + idpOIDC + "/logout"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (p *fakeIdP) certs(w http.ResponseWriter, r *http.Request) {
	p.stat(func() { p.jwksCalls++ })
	w.Header().Set("Content-Type", "application/json")
	w.Write(jwksDoc(p.key))
}

func (p *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.stat(func() { p.authzQuery = q })
	if q.Get("client_id") != idpClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("state") == "" {
		http.Error(w, "invalid_request", 400)
		return
	}
	p.mu.Lock()
	p.n++
	code := "code-" + strings.Repeat("x", 3) + string(rune('a'+p.n))
	p.codes[code] = idpCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), scope: q.Get("scope")}
	p.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	bq.Set("session_state", "kc-session")
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *fakeIdP) tokenErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(m{"error": code, "error_description": "Secret detail " + secretClient})
}

func (p *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	form := r.PostForm
	p.stat(func() { p.tokenCalls++; p.tokenForms = append(p.tokenForms, form) })
	if p.tokenStatus != 0 {
		p.tokenErr(w, p.tokenStatus, "server_error")
		return
	}
	user, pass, basic := r.BasicAuth()
	if p.postAuth {
		user, pass = form.Get("client_id"), form.Get("client_secret")
	} else if !basic {
		p.tokenErr(w, 401, "invalid_client")
		return
	}
	if user != idpClientID || pass != secretClient {
		p.tokenErr(w, 401, "invalid_client")
		return
	}
	now := p.clock.Now()
	nonce := ""
	switch form.Get("grant_type") {
	case "authorization_code":
		p.mu.Lock()
		c, ok := p.codes[form.Get("code")]
		if ok {
			p.codes[form.Get("code")] = idpCode{used: true}
		}
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(form.Get("code_verifier")))
		if !ok || c.used || c.redirect != form.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
			p.tokenErr(w, 400, "invalid_grant")
			return
		}
		nonce = c.nonce
	case "refresh_token":
		p.stat(func() { p.refreshCalls++ })
		rt := form.Get("refresh_token")
		p.mu.Lock()
		used, ok := p.refreshTokens[rt]
		if ok && p.revokeRefresh {
			p.refreshTokens[rt] = true
		}
		p.mu.Unlock()
		if !ok || (used && p.revokeRefresh) {
			p.tokenErr(w, 400, "invalid_grant")
			return
		}
	default:
		p.tokenErr(w, 400, "unsupported_grant_type")
		return
	}
	if p.badNonce {
		nonce = "another-nonce"
	}
	exp := now.Add(p.atTTL)
	idClaims := m{"iss": p.issuer, "sub": "user-1", "aud": idpClientID, "azp": idpClientID, "exp": exp.Unix(), "iat": now.Unix(),
		"typ": "ID", "preferred_username": "alice", "email": "alice@haven.test", "name": "Alice Doe", "sid": "kc-session",
		"realm_access": m{"roles": p.roles}, "resource_access": m{idpClientID: m{"roles": l{"editor"}}}}
	if form.Get("grant_type") == "authorization_code" {
		idClaims["nonce"] = nonce
	}
	if p.idIssuer != "" {
		idClaims["iss"] = p.idIssuer
	}
	if p.idAud != "" {
		idClaims["aud"] = p.idAud
	}
	at := p.key.sign(p.t, map[string]any{"typ": "JWT"}, m{"iss": p.issuer, "sub": "user-1", "aud": "account", "azp": idpClientID,
		"exp": exp.Unix(), "iat": now.Unix(), "scope": "openid profile email", "jti": randToken(6)})
	resp := m{"access_token": at, "token_type": "Bearer", "expires_in": int(p.atTTL.Seconds()),
		"id_token": p.key.sign(p.t, map[string]any{"typ": "JWT"}, idClaims), "scope": "openid profile email"}
	if !p.noRefresh {
		p.mu.Lock()
		p.n++
		rt := "rt-" + randToken(8)
		p.refreshTokens[rt] = false
		p.mu.Unlock()
		resp["refresh_token"] = rt
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (p *fakeIdP) userinfo(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ey") {
		w.WriteHeader(401)
		return
	}
	json.NewEncoder(w).Encode(m{"sub": "user-1", "preferred_username": "alice", "department": "platform", "email": "ignored@x"})
}

func (p *fakeIdP) logout(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.stat(func() { p.logoutQuery = q })
	if back := q.Get("post_logout_redirect_uri"); back != "" {
		http.Redirect(w, r, back, http.StatusFound)
		return
	}
	w.WriteHeader(200)
}

// ---- browser ----

// browser keeps cookies by hand (the gateway test listener is plain http, and
// the session cookie is Secure) and never follows redirects.
type browser struct {
	t       *testing.T
	s       *Server
	cookies map[string]string
	idp     *http.Client
}

func newBrowser(t *testing.T, s *Server) *browser {
	return &browser{t: t, s: s, cookies: map[string]string{}, idp: &http.Client{Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) cookieHeader() string {
	var parts []string
	for _, k := range sortedKeys(b.cookies) {
		parts = append(parts, k+"="+b.cookies[k])
	}
	return strings.Join(parts, "; ")
}

func (b *browser) store(h http.Header) []*http.Cookie {
	cs := (&http.Response{Header: h}).Cookies()
	for _, c := range cs {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return cs
}

func (b *browser) do(method, target string, hdr ...string) reply {
	b.t.Helper()
	if len(b.cookies) > 0 {
		hdr = append(hdr, "Cookie", b.cookieHeader())
	}
	r := req(b.t, client(b.s.Addr(8080), nil), "http", method, "a.test", target, "", hdr...)
	b.store(r.Header)
	return r
}

var htmlAccept = []string{"Accept", "text/html,application/xhtml+xml"}

// follow performs a GET on an absolute URL (the provider) and returns the response.
func (b *browser) follow(rawURL string) reply {
	b.t.Helper()
	resp, err := b.idp.Get(rawURL)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return reply{Status: resp.StatusCode, Header: resp.Header, Body: string(body)}
}

// login walks the whole flow starting at target and returns the reply of the
// final request for target.
func (b *browser) login(target string) reply {
	b.t.Helper()
	r := b.do("GET", target, htmlAccept...)
	if r.Status != 302 {
		b.t.Fatalf("first request: %d %s", r.Status, r.Body)
	}
	idp := b.follow(r.Header.Get("Location"))
	if idp.Status != 302 {
		b.t.Fatalf("authorize: %d %s", idp.Status, idp.Body)
	}
	back, _ := url.Parse(idp.Header.Get("Location"))
	cb := b.do("GET", back.RequestURI())
	if cb.Status != 302 {
		b.t.Fatalf("callback: %d %s", cb.Status, cb.Body)
	}
	if loc := cb.Header.Get("Location"); loc != target {
		b.t.Fatalf("callback sent the browser to %q, want %q", loc, target)
	}
	return b.do("GET", target, htmlAccept...)
}
