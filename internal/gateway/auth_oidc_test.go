package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func oidcEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TEST_OIDC_CLIENT_SECRET", secretClient)
	t.Setenv("TEST_OIDC_KEY_A", secretKeyA)
	t.Setenv("TEST_OIDC_KEY_B", secretKeyB)
}

func oidcPolicyM(idp *fakeIdP, extra m) m {
	o := m{"issuer": idp.issuer, "clientId": idpClientID, "clientSecret": m{"env": "TEST_OIDC_CLIENT_SECRET"},
		"redirectUrl": "http://a.test/oauth2/callback", "cookieKeys": l{m{"env": "TEST_OIDC_KEY_A"}},
		"claimHeaders":      m{"X-User": "preferred_username", "X-Email": "email", "X-Roles": "realm_access.roles"},
		"accessTokenHeader": "Authorization", "accessTokenScheme": "Bearer"}
	for k, v := range extra {
		o[k] = v
	}
	return o
}

// oidcServer starts a gateway whose only route a.test carries an OIDC policy.
func oidcServer(t *testing.T, idp *fakeIdP, clock *testClock, oidc, policy m) (*Server, *upstream, *syncBuf) {
	t.Helper()
	oidcEnv(t)
	p := m{"oidc": oidcPolicyM(idp, oidc)}
	for k, v := range policy {
		p[k] = v
	}
	var log syncBuf
	s, up := authServer(t, p, func(o *Options) {
		o.AuthClock = clock.Now
		o.AccessLog = &log
	})
	return s, up, &log
}

func TestOIDCLoginFlow(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, up, _ := oidcServer(t, idp, clock, nil, nil)
	b := newBrowser(t, s)

	// A browser without a session is redirected to the authorization endpoint.
	r := b.do("GET", "/app?tab=2", htmlAccept...)
	if r.Status != 302 || len(up.seen()) != 0 {
		t.Fatalf("anonymous browser: %d", r.Status)
	}
	loc, _ := url.Parse(r.Header.Get("Location"))
	if loc.Path != idpOIDC+"/auth" || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("redirect %s, cache-control %q", loc, r.Header.Get("Cache-Control"))
	}
	q := loc.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != idpClientID || q.Get("redirect_uri") != "http://a.test/oauth2/callback" ||
		q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || len(q.Get("state")) < 20 || q.Get("nonce") == "" ||
		q.Get("scope") != "openid profile email" {
		t.Fatalf("authorization request: %v", q)
	}
	var tx *http.Cookie
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if strings.HasPrefix(c.Name, "setura_session_tx_") {
			tx = c
		}
	}
	if tx == nil || !tx.HttpOnly || tx.Path != "/oauth2/callback" || tx.SameSite != http.SameSiteLaxMode {
		t.Fatalf("login state cookie: %+v", tx)
	}
	if strings.Contains(tx.Value, q.Get("state")) || strings.Contains(tx.Value, q.Get("nonce")) {
		t.Error("the login state cookie is not encrypted")
	}

	// Authorize at the provider, come back to the callback, land on the original URL with a session.
	idpR := b.follow(loc.String())
	back, _ := url.Parse(idpR.Header.Get("Location"))
	cb := b.do("GET", back.RequestURI())
	if cb.Status != 302 || cb.Header.Get("Location") != "/app?tab=2" {
		t.Fatalf("callback: %d %v", cb.Status, cb.Header)
	}
	var sess *http.Cookie
	for _, c := range (&http.Response{Header: cb.Header}).Cookies() {
		if c.Name == "setura_session" {
			sess = c
		}
	}
	if sess == nil || !sess.HttpOnly || !sess.Secure || sess.SameSite != http.SameSiteLaxMode || sess.Path != "/" {
		t.Fatalf("session cookie: %+v", sess)
	}
	if strings.Contains(sess.Value, "alice") || strings.Contains(sess.Value, "ey") && strings.Count(sess.Value, ".") > 2 {
		t.Error("the session cookie is readable")
	}
	if _, left := b.cookies["setura_session_tx_"+q.Get("state")[:10]]; left {
		t.Error("the login state cookie is not cleared")
	}
	// PKCE: the provider saw the verifier of the challenge (checked in its token handler), with Basic client auth.
	if idp.tokenCalls != 1 || idp.discoveries != 1 {
		t.Errorf("token calls %d, discoveries %d", idp.tokenCalls, idp.discoveries)
	}

	// With the session the request is proxied; claims and the access token go upstream, the cookie does not.
	r = b.do("GET", "/app?tab=2", append(htmlAccept, "X-User", "root", "X-Roles", "admin", "Authorization", "Bearer forged")...)
	if r.Status != 200 {
		t.Fatalf("with session: %d %s", r.Status, r.Body)
	}
	h := r.Echo.Headers
	if h["x-user"] != "alice" || h["x-email"] != "alice@haven.test" || h["x-roles"] != "user" {
		t.Errorf("claim headers: %v", h)
	}
	if !strings.HasPrefix(h["authorization"], "Bearer ey") || strings.Contains(h["authorization"], "forged") {
		t.Errorf("access token header: %q", h["authorization"])
	}
	if h["x-setura-auth-method"] != "oidc" || h["x-setura-auth-subject"] != "user-1" {
		t.Errorf("identity headers: %v", h)
	}
	if strings.Contains(h["cookie"], "setura_session") {
		t.Errorf("the session cookie reached the backend: %q", h["cookie"])
	}
	if idp.tokenCalls != 1 {
		t.Errorf("a valid session must not call the provider: %d", idp.tokenCalls)
	}
	// Other cookies of the browser pass through.
	b.cookies["theme"] = "dark"
	r = b.do("GET", "/")
	delete(b.cookies, "theme")
	if r.Echo.Headers["cookie"] != "theme=dark" {
		t.Errorf("other cookies: %q", r.Echo.Headers["cookie"])
	}
	// A tampered cookie is not a session.
	b.cookies["setura_session"] = b.cookies["setura_session"][:len(b.cookies["setura_session"])-3] + "AAA"
	if r = b.do("GET", "/", htmlAccept...); r.Status != 302 {
		t.Errorf("tampered cookie: %d", r.Status)
	}
	if _, kept := b.cookies["setura_session"]; kept {
		t.Error("an invalid session cookie should be cleared")
	}
	mt := metricsOf(s)
	for _, want := range []string{`setura_gateway_oidc_events_total{route="t/r",event="login_started"} 2`, `event="login_succeeded"} 1`, `event="session_invalid"} 1`} {
		if !strings.Contains(mt, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestOIDCCallbackRejections(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, up, _ := oidcServer(t, idp, clock, nil, nil)
	start := func(b *browser) (state string, authURL string) {
		r := b.do("GET", "/x", htmlAccept...)
		u, _ := url.Parse(r.Header.Get("Location"))
		return u.Query().Get("state"), u.String()
	}
	finish := func(b *browser, authURL string) reply {
		idpR := b.follow(authURL)
		back, _ := url.Parse(idpR.Header.Get("Location"))
		return b.do("GET", back.RequestURI())
	}
	deny := func(name string, r reply, status int) {
		t.Helper()
		if r.Status != status || len(b2s(r.Header["Set-Cookie"], "setura_session=")) > 0 && !strings.Contains(strings.Join(r.Header["Set-Cookie"], ";"), "Max-Age=0") {
			t.Errorf("%s: %d %s %v", name, r.Status, r.Body, r.Header["Set-Cookie"])
		}
		if strings.Contains(r.Body, secretClient) || strings.Contains(r.Body, "Secret detail") {
			t.Errorf("%s: the provider's error text reached the client: %s", name, r.Body)
		}
		var j map[string]string
		if json.Unmarshal([]byte(r.Body), &j) != nil || j["error"] == "" {
			t.Errorf("%s: body is not the JSON error: %q", name, r.Body)
		}
	}

	// No login in progress: a callback with an unknown state.
	b := newBrowser(t, s)
	deny("no state cookie", b.do("GET", "/oauth2/callback?code=abc&state=0123456789abcdefghij"), 400)
	deny("no state", b.do("GET", "/oauth2/callback?code=abc"), 400)

	// A state cookie from one login cannot finish another browser's login.
	b1, b2 := newBrowser(t, s), newBrowser(t, s)
	_, u1 := start(b1)
	st2, _ := start(b2)
	idpR := b1.follow(u1)
	back, _ := url.Parse(idpR.Header.Get("Location"))
	bq := back.Query()
	bq.Set("state", st2)
	deny("state of another login", b1.do("GET", back.Path+"?"+bq.Encode()), 400)

	// Replay: the code can be used once.
	b3 := newBrowser(t, s)
	_, u3 := start(b3)
	idpR = b3.follow(u3)
	back, _ = url.Parse(idpR.Header.Get("Location"))
	saved := map[string]string{}
	for k, v := range b3.cookies {
		saved[k] = v
	}
	if r := b3.do("GET", back.RequestURI()); r.Status != 302 {
		t.Fatalf("first use: %d", r.Status)
	}
	b3.cookies = saved
	deny("replayed code", b3.do("GET", back.RequestURI()), 401)

	// The provider's error response.
	b4 := newBrowser(t, s)
	st, _ := start(b4)
	deny("provider error", b4.do("GET", "/oauth2/callback?error=access_denied&state="+st+"&error_description=nope"), 401)

	// A login that took too long.
	b5 := newBrowser(t, s)
	_, u5 := start(b5)
	clock.Advance(11 * time.Minute)
	deny("expired login", finish(b5, u5), 400)

	// POST is not a callback.
	if r := newBrowser(t, s).do("POST", "/oauth2/callback"); r.Status != 405 {
		t.Errorf("POST callback: %d", r.Status)
	}

	// The ID token is checked: nonce, issuer, audience.
	for _, c := range []struct {
		name string
		set  func()
		undo func()
	}{
		{"nonce", func() { idp.badNonce = true }, func() { idp.badNonce = false }},
		{"issuer", func() { idp.idIssuer = "https://evil.test/realms/haven" }, func() { idp.idIssuer = "" }},
		{"audience", func() { idp.idAud = "other-client" }, func() { idp.idAud = "" }},
	} {
		c.set()
		bb := newBrowser(t, s)
		_, uu := start(bb)
		deny("ID token "+c.name, finish(bb, uu), 401)
		c.undo()
	}
	// Provider failure while exchanging the code: 503, not a session.
	idp.tokenStatus = 503
	bb := newBrowser(t, s)
	_, uu := start(bb)
	deny("token endpoint down", finish(bb, uu), 503)
	idp.tokenStatus = 0
	if len(up.seen()) != 0 {
		t.Error("a failed login reached the backend")
	}
	mt := metricsOf(s)
	if !strings.Contains(mt, `event="login_failed"}`) {
		t.Error("login_failed is not counted")
	}
	if strings.Count(mt, "setura_gateway_oidc_events_total{") > 8 {
		t.Errorf("the event label must stay a small fixed set:\n%s", mt)
	}
}

func b2s(v []string, prefix string) []string {
	var out []string
	for _, s := range v {
		if strings.HasPrefix(s, prefix) {
			out = append(out, s)
		}
	}
	return out
}

func TestOIDCSilentDenyAndRedirectModes(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, nil, nil)
	b := newBrowser(t, s)
	for _, c := range []struct {
		name   string
		method string
		hdr    []string
		want   int
	}{
		{"navigation", "GET", htmlAccept, 302},
		{"xhr", "GET", append([]string{"X-Requested-With", "XMLHttpRequest"}, htmlAccept...), 401},
		{"json api", "GET", []string{"Accept", "application/json"}, 401},
		{"curl", "GET", []string{"Accept", "*/*"}, 401},
		{"no accept", "GET", nil, 401},
		{"fetch", "GET", append([]string{"Sec-Fetch-Mode", "cors"}, htmlAccept...), 401},
		{"form post", "POST", htmlAccept, 401},
		{"bad bearer", "GET", append([]string{"Authorization", "Bearer x"}, htmlAccept...), 401},
	} {
		r := b.do(c.method, "/data", c.hdr...)
		if r.Status != c.want {
			t.Errorf("%s: %d, want %d", c.name, r.Status, c.want)
		}
		if c.want == 401 {
			var j map[string]string
			if json.Unmarshal([]byte(r.Body), &j) != nil || j["code"] != "login_required" || r.Header.Get("Location") != "" {
				t.Errorf("%s: 401 body %q location %q", c.name, r.Body, r.Header.Get("Location"))
			}
		}
	}
	for mode, want := range map[string]int{"always": 302, "never": 401} {
		s2, _, _ := oidcServer(t, idp, clock, m{"denyRedirect": mode}, nil)
		b2 := newBrowser(t, s2)
		if r := b2.do("GET", "/", "X-Requested-With", "XMLHttpRequest"); r.Status != want {
			t.Errorf("denyRedirect %s xhr: %d, want %d", mode, r.Status, want)
		}
		wantNav := 302
		if mode == "never" {
			wantNav = 401
		}
		if r := b2.do("GET", "/", htmlAccept...); r.Status != wantNav {
			t.Errorf("denyRedirect %s navigation: %d, want %d", mode, r.Status, wantNav)
		}
	}
}

func TestOIDCRefreshAndExpiry(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, m{"sessionTtl": "1h"}, nil)
	b := newBrowser(t, s)
	if r := b.login("/app"); r.Status != 200 {
		t.Fatalf("login: %d", r.Status)
	}
	first := b.cookies["setura_session"]
	at1 := b.do("GET", "/app").Echo.Headers["authorization"]

	// Access token still fresh: no refresh.
	clock.Advance(2 * time.Minute)
	b.do("GET", "/app")
	if idp.refreshCalls != 0 {
		t.Fatalf("refreshed too early: %d", idp.refreshCalls)
	}
	// Past its expiry the session is refreshed and the cookie replaced.
	clock.Advance(4 * time.Minute)
	r := b.do("GET", "/app")
	if r.Status != 200 || idp.refreshCalls != 1 {
		t.Fatalf("refresh: %d, calls %d", r.Status, idp.refreshCalls)
	}
	if b.cookies["setura_session"] == first || r.Echo.Headers["authorization"] == at1 || r.Echo.Headers["x-user"] != "alice" {
		t.Errorf("refresh did not renew the session: %v", r.Echo.Headers)
	}
	b.do("GET", "/app")
	if idp.refreshCalls != 1 {
		t.Errorf("refreshed again: %d", idp.refreshCalls)
	}
	// The refresh was a refresh_token grant with the client credentials.
	last := idp.tokenForms[len(idp.tokenForms)-1]
	if last.Get("grant_type") != "refresh_token" || last.Get("client_id") != idpClientID || last.Get("refresh_token") == "" {
		t.Errorf("refresh request: %v", last)
	}
	// The absolute session lifetime ends the session whatever the tokens say.
	clock.Advance(time.Hour)
	if r = b.do("GET", "/app", htmlAccept...); r.Status != 302 {
		t.Errorf("expired session: %d", r.Status)
	}
	if !strings.Contains(metricsOf(s), `event="refresh_succeeded"} 1`) {
		t.Error("refresh_succeeded is not counted")
	}
}

func TestOIDCRefreshFailureModes(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, nil, nil)
	b := newBrowser(t, s)
	b.login("/")
	clock.Advance(6 * time.Minute)
	// The provider is down: a temporary failure keeps the user's cookie and answers 503.
	idp.tokenStatus = 503
	r := b.do("GET", "/", htmlAccept...)
	if r.Status != 503 || b.cookies["setura_session"] == "" {
		t.Fatalf("provider down: %d (cookie kept: %v)", r.Status, b.cookies["setura_session"] != "")
	}
	// The provider refuses the refresh token: back to login.
	idp.tokenStatus = 0
	idp.stat(func() {
		for k := range idp.refreshTokens {
			delete(idp.refreshTokens, k)
		}
	})
	r = b.do("GET", "/", htmlAccept...)
	if r.Status != 302 || b.cookies["setura_session"] != "" {
		t.Fatalf("revoked refresh token: %d", r.Status)
	}
	if !strings.Contains(metricsOf(s), `event="refresh_failed"} 2`) {
		t.Errorf("refresh_failed is not counted:\n%s", metricsOf(s))
	}
}

// Many requests of one browser arrive with the same expired tokens: the
// refresh token (single use here) is redeemed once.
func TestOIDCConcurrentRefreshIsSingleFlight(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	idp.revokeRefresh = true
	s, _, _ := oidcServer(t, idp, clock, nil, nil)
	b := newBrowser(t, s)
	b.login("/")
	clock.Advance(6 * time.Minute)
	cookie := b.cookieHeader()
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rq, _ := http.NewRequest("GET", "http://a.test/", nil)
			rq.Header.Set("Cookie", cookie)
			resp, err := client(s.Addr(8080), nil).Do(rq)
			if err != nil {
				return
			}
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	wg.Wait()
	for i, c := range codes {
		if c != 200 {
			t.Errorf("request %d: %d", i, c)
		}
	}
	if idp.refreshCalls != 1 {
		t.Errorf("refresh token redeemed %d times", idp.refreshCalls)
	}
}

func TestOIDCLogoutEndSession(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, m{"postLogoutRedirectUrl": "http://a.test/bye"}, m{"csrf": m{}})
	b := newBrowser(t, s)
	b.login("/")
	// A cross-site POST cannot log the user out.
	if r := b.do("POST", "/oauth2/logout", "Origin", "https://evil.test"); r.Status != 403 || b.cookies["setura_session"] == "" {
		t.Errorf("cross-site logout: %d", r.Status)
	}
	r := b.do("GET", "/oauth2/logout")
	if r.Status != 302 {
		t.Fatalf("logout: %d %s", r.Status, r.Body)
	}
	u, _ := url.Parse(r.Header.Get("Location"))
	q := u.Query()
	if u.Path != idpOIDC+"/logout" || q.Get("client_id") != idpClientID || q.Get("post_logout_redirect_uri") != "http://a.test/bye" || strings.Count(q.Get("id_token_hint"), ".") != 2 {
		t.Errorf("end_session redirect: %s", u)
	}
	if _, kept := b.cookies["setura_session"]; kept {
		t.Error("the session cookie survived the logout")
	}
	if b.follow(u.String()).Header.Get("Location") != "http://a.test/bye" {
		t.Error("the provider did not send the browser back")
	}
	if r = b.do("GET", "/", htmlAccept...); r.Status != 302 || !strings.Contains(r.Header.Get("Location"), idpOIDC+"/auth") {
		t.Errorf("after logout: %d", r.Status)
	}
	// A provider without an end_session_endpoint: logout still clears the cookie and goes to the post-logout URL.
	idp2 := newFakeIdP(t, clock)
	idp2.noEndSession = true
	s2, _, _ := oidcServer(t, idp2, clock, nil, nil)
	b2 := newBrowser(t, s2)
	b2.login("/")
	if r = b2.do("GET", "/oauth2/logout"); r.Status != 302 || r.Header.Get("Location") != "/" || b2.cookies["setura_session"] != "" {
		t.Errorf("logout without end_session: %d %q", r.Status, r.Header.Get("Location"))
	}
}

func TestOIDCCookieAttributesNamesAndMode(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, m{"cookieMode": "signed",
		"cookie": m{"name": "haven_sid", "domain": "a.test", "path": "/", "sameSite": "Strict", "secure": false}}, nil)
	b := newBrowser(t, s)
	r := b.do("GET", "/", htmlAccept...)
	idpR := b.follow(r.Header.Get("Location"))
	back, _ := url.Parse(idpR.Header.Get("Location"))
	cb := b.do("GET", back.RequestURI())
	var c *http.Cookie
	for _, k := range (&http.Response{Header: cb.Header}).Cookies() {
		if k.Name == "haven_sid" {
			c = k
		}
	}
	if c == nil || c.Domain != "a.test" || c.Secure || c.SameSite != http.SameSiteStrictMode || !c.HttpOnly || !strings.HasPrefix(c.Value, "s1.") {
		t.Fatalf("cookie: %+v", c)
	}
	// The transaction cookie stays Lax even when the session cookie is Strict: the callback is a cross-site navigation.
	for _, k := range (&http.Response{Header: r.Header}).Cookies() {
		if strings.HasPrefix(k.Name, "haven_sid_tx_") && k.SameSite != http.SameSiteLaxMode {
			t.Errorf("tx cookie SameSite %v", k.SameSite)
		}
	}
	if r = b.do("GET", "/"); r.Status != 200 || r.Echo.Headers["x-user"] != "alice" {
		t.Errorf("signed session: %d", r.Status)
	}
}

func TestOIDCKeyRotationSealAndOpen(t *testing.T) {
	o := &compiledOIDC{name: "sid"}
	a, b := secretKeyA, secretKeyB
	v, err := o.seal([]string{a}, "sid", []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	// Rotation: the new key first, the old one still opens.
	plain, idx, err := o.open([]string{b, a}, "sid", v)
	if err != nil || string(plain) != `{"x":1}` || idx != 1 {
		t.Fatalf("open with rotated keys: %q %d %v", plain, idx, err)
	}
	if _, _, err := o.open([]string{b}, "sid", v); err == nil {
		t.Error("a removed key still opens the cookie")
	}
	if _, _, err := o.open([]string{a}, "other", v); err == nil {
		t.Error("a cookie moved to another name still opens")
	}
	if _, _, err := o.open([]string{a}, "sid", v[:len(v)-2]+"AA"); err == nil {
		t.Error("tampered cookie opens")
	}
	o.signed = true
	sv, _ := o.seal([]string{a}, "sid", []byte("hello"))
	if p, i, err := o.open([]string{b, a}, "sid", sv); err != nil || string(p) != "hello" || i != 1 {
		t.Errorf("signed mode: %q %d %v", p, i, err)
	}
	if _, _, err := o.open([]string{a}, "sid", v); err == nil {
		t.Error("an encrypted cookie opens in signed mode")
	}
	if _, _, err := o.open([]string{b}, "sid", sv); err == nil {
		t.Error("signed cookie verified with the wrong key")
	}
}

// End to end: a session made with the old key keeps working after the keys are
// rotated, and the cookie is reissued under the new key.
func TestOIDCKeyRotationEndToEnd(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, nil, nil)
	b := newBrowser(t, s)
	b.login("/")
	old := b.cookies["setura_session"]
	s2, _, _ := oidcServer(t, idp, clock, m{"cookieKeys": l{m{"env": "TEST_OIDC_KEY_B"}, m{"env": "TEST_OIDC_KEY_A"}}}, nil)
	b2 := &browser{t: t, s: s2, cookies: map[string]string{"setura_session": old}}
	r := b2.do("GET", "/")
	if r.Status != 200 {
		t.Fatalf("old session after rotation: %d", r.Status)
	}
	if b2.cookies["setura_session"] == old {
		t.Error("the cookie was not reissued under the new key")
	}
	s3, _, _ := oidcServer(t, idp, clock, m{"cookieKeys": l{m{"env": "TEST_OIDC_KEY_B"}}}, nil)
	b3 := &browser{t: t, s: s3, cookies: map[string]string{"setura_session": b2.cookies["setura_session"]}}
	if r := b3.do("GET", "/"); r.Status != 200 {
		t.Errorf("reissued session with only the new key: %d", r.Status)
	}
	b4 := &browser{t: t, s: s3, cookies: map[string]string{"setura_session": old}}
	if r := b4.do("GET", "/", htmlAccept...); r.Status != 302 {
		t.Errorf("old session after the old key is removed: %d", r.Status)
	}
}

func TestOIDCLargeSessionIsChunked(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	idp.roles = nil
	for i := 0; i < 120; i++ {
		idp.roles = append(idp.roles, "group-"+randToken(24))
	}
	s, _, _ := oidcServer(t, idp, clock, nil, nil)
	b := newBrowser(t, s)
	r := b.login("/")
	if r.Status != 200 {
		t.Fatalf("login with a large token: %d %s", r.Status, r.Body)
	}
	if _, ok := b.cookies["setura_session_1"]; !ok {
		t.Fatalf("the session was not split into chunks: %v", sortedKeys(b.cookies))
	}
	for k, v := range b.cookies {
		if len(v) > oidcChunkSize {
			t.Errorf("cookie %s is %d bytes", k, len(v))
		}
	}
	if len(strings.Split(r.Echo.Headers["x-roles"], ",")) != 120 {
		t.Errorf("roles after chunking: %d", len(strings.Split(r.Echo.Headers["x-roles"], ",")))
	}
	// sessionClaims keeps the session small: one cookie, the claims in the list only.
	s2, _, _ := oidcServer(t, idp, clock, m{"sessionClaims": l{"preferred_username", "email"}}, nil)
	b2 := newBrowser(t, s2)
	r = b2.login("/")
	size := func(b *browser) (n int) {
		for _, v := range b.cookies {
			n += len(v)
		}
		return n
	}
	if size(b2) >= size(b) || r.Echo.Headers["x-user"] != "alice" || r.Echo.Headers["x-roles"] != "" {
		t.Errorf("sessionClaims: %d bytes against %d, %v", size(b2), size(b), r.Echo.Headers)
	}
}

func TestOIDCKeycloakVariantsAndUserinfo(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	idp.postAuth = true
	s, _, _ := oidcServer(t, idp, clock, m{"tokenAuthMethod": "client_secret_post", "userinfo": true,
		"claimHeaders": m{"X-Dept": "department", "X-Client-Role": "resource_access.haven-app.roles", "X-Email": "email"},
		"authParams":   m{"kc_idp_hint": "corp-saml", "prompt": "login"}, "scopes": l{"profile", "roles"}}, nil)
	b := newBrowser(t, s)
	r := b.do("GET", "/", htmlAccept...)
	loc, _ := url.Parse(r.Header.Get("Location"))
	if q := loc.Query(); q.Get("kc_idp_hint") != "corp-saml" || q.Get("prompt") != "login" || q.Get("scope") != "openid profile roles" {
		t.Errorf("authorization params: %v", q)
	}
	r = b.login("/")
	h := r.Echo.Headers
	if r.Status != 200 || h["x-dept"] != "platform" || h["x-client-role"] != "editor" || h["x-email"] != "alice@haven.test" {
		t.Errorf("claims: %d %v", r.Status, h)
	}
	last := idp.tokenForms[0]
	if last.Get("client_secret") != secretClient {
		t.Error("client_secret_post: the secret was not posted")
	}
	// A discovery document that names another issuer is refused (mix-up defence).
	idp3 := newFakeIdP(t, clock)
	idp3.discIssuer = "https://other.test/realms/haven"
	s3, _, _ := oidcServer(t, idp3, clock, nil, nil)
	if r := newBrowser(t, s3).do("GET", "/", htmlAccept...); r.Status != 503 {
		t.Errorf("issuer mismatch in discovery: %d", r.Status)
	}
}

// With every endpoint given, discovery is not used at all.
func TestOIDCEndpointOverridesSkipDiscovery(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, m{"authorizationEndpoint": idp.URL + idpOIDC + "/auth", "tokenEndpoint": idp.URL + idpOIDC + "/token",
		"jwksUri": idp.URL + idpOIDC + "/certs"}, nil)
	b := newBrowser(t, s)
	if r := b.login("/"); r.Status != 200 {
		t.Fatalf("login: %d", r.Status)
	}
	if idp.discoveries != 0 {
		t.Errorf("discovery used: %d", idp.discoveries)
	}
}

// Secrets come from env, file or Secret, rotate with the file, and never leak.
func TestOIDCSecretsNeverLeak(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	oidcEnv(t)
	t.Setenv("TEST_INJECT", secretInject)
	s, up, log := oidcServer(t, idp, clock, nil, m{"inject": l{m{"header": "X-Svc-Token", "secret": m{"env": "TEST_INJECT"}}}})
	b := newBrowser(t, s)
	b.login("/")
	b.do("GET", "/x") // the backend echoes the injected header into its own response: not the gateway's to hide
	var all bytes.Buffer
	for _, r := range []reply{b.do("GET", "/oauth2/callback?error=x&state=0123456789abcdef"), b.do("GET", "/oauth2/callback?state=0123456789abcdef&code=1"), newBrowser(t, s).do("GET", "/", htmlAccept...)} {
		all.WriteString(r.Body)
		for k, v := range r.Header {
			all.WriteString(k + strings.Join(v, ","))
		}
	}
	s.FlushAccessLog()
	all.WriteString(log.String())
	all.WriteString(metricsOf(s))
	cfg, _ := json.Marshal(s.Table().Cfg.Routes[0].Rules[0].Auth)
	all.Write(cfg)
	tr := explainAuthFor(t, s, "127.0.0.1", "Cookie", b.cookieHeader())
	tj, _ := json.Marshal(tr)
	all.Write(tj)
	for _, secret := range []string{secretClient, secretKeyA, secretInject} {
		if strings.Contains(all.String(), secret) {
			t.Errorf("secret %q leaked", secret)
		}
	}
	// The injected credential does reach the backend, the session cookie does not.
	seen := up.seen()
	if got := seen[len(seen)-1].Headers["x-svc-token"]; got != secretInject {
		t.Errorf("injected value %q", got)
	}
	if strings.Contains(string(tj), "setura_session=") {
		t.Error("the echoed request shows the session cookie")
	}
	if !strings.Contains(string(cfg), `"TEST_OIDC_CLIENT_SECRET"`) {
		t.Errorf("the dump should name the source of the secret: %s", cfg)
	}
}

func TestOIDCSecretSourcesAndInvalidPolicy(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	dir := t.TempDir()
	keyFile := dir + "/cookie.key"
	writeFile(t, keyFile, []byte(secretKeyA+"\n"))
	t.Setenv("TEST_OIDC_CLIENT_SECRET", secretClient)
	s, _ := authServer(t, m{"oidc": oidcPolicyM(idp, m{"cookieKeys": l{m{"file": keyFile}}})}, func(o *Options) { o.AuthClock = clock.Now })
	if r := newBrowser(t, s).login("/"); r.Status != 200 {
		t.Fatalf("cookie key from a file: %d", r.Status)
	}
	// A missing secret makes the route invalid, never an unprotected or half-protected one.
	t.Setenv("TEST_OIDC_CLIENT_SECRET", "")
	s, up := authServer(t, m{"oidc": oidcPolicyM(idp, m{"cookieKeys": l{m{"file": keyFile}}})}, func(o *Options) { o.AuthClock = clock.Now })
	if r := get(t, s, "a.test", "/"); r.Status == 200 || len(up.seen()) != 0 {
		t.Errorf("route with a missing client secret served: %d", r.Status)
	}
	msg := ""
	for _, c := range s.Status().Routes["t/r"].Parents[0].Conditions {
		msg += c.Message
	}
	if !strings.Contains(msg, "oidc.clientSecret") || strings.Contains(msg, secretClient) {
		t.Errorf("status message: %q", msg)
	}
	// A short cookie key is refused.
	t.Setenv("TEST_OIDC_CLIENT_SECRET", secretClient)
	t.Setenv("TEST_OIDC_KEY_A", "too-short")
	s, _ = authServer(t, m{"oidc": oidcPolicyM(idp, nil)}, nil)
	if r := get(t, s, "a.test", "/"); r.Status == 200 || r.Status == 302 {
		t.Errorf("short cookie key: %d", r.Status)
	}
	// A secret written into the route is a validation error.
	for name, o := range map[string]m{
		"no redirect":     {"redirectUrl": ""},
		"no keys":         {"cookieKeys": l{}},
		"two sources":     {"clientSecret": m{"env": "A", "file": "/x"}},
		"bad samesite":    {"cookie": m{"sameSite": "Sometimes"}},
		"none not secure": {"cookie": m{"sameSite": "None", "secure": false}},
		"logout is cb":    {"logoutPath": "/oauth2/callback"},
		"bad deny":        {"denyRedirect": "sometimes"},
		"bad auth param":  {"authParams": m{"state": "x"}},
		"host prefix":     {"cookie": m{"name": "__Host-x", "domain": "a.test"}},
	} {
		raw, _ := json.Marshal(m{"oidc": oidcPolicyM(idp, o)})
		if _, err := ParseAuthBlock(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	raw := []byte(`{"oidc":{"issuer":"https://i","clientId":"c","redirectUrl":"/cb","clientSecret":{"value":"inline"}}}`)
	if _, err := ParseAuthBlock(raw); err == nil {
		t.Error("an inline secret value is accepted")
	}
	// gRPC cannot do a browser login.
	if _, err := ParseAuthBlock([]byte(`{"oidc":{"issuer":"https://i","clientId":"c","redirectUrl":"/cb","cookieKeys":[{"env":"X"}]}}`)); err != nil {
		t.Errorf("a valid policy: %v", err)
	}
}

// An offline "why" shows the decision for a browser with and without a session.
func TestWhyOIDC(t *testing.T) {
	clock := newTestClock()
	idp := newFakeIdP(t, clock)
	s, _, _ := oidcServer(t, idp, clock, nil, nil)
	b := newBrowser(t, s)
	tr := explainAuthFor(t, s, "127.0.0.1", "Accept", "text/html")
	a := tr.Winner.Auth
	if a == nil || a.Decision != "deny" || a.Status != 302 || !strings.Contains(a.Reason, "identity provider") || !strings.Contains(a.Policy, "oidc login with "+idpClientID) {
		t.Fatalf("anonymous: %+v", a)
	}
	tr = explainAuthFor(t, s, "127.0.0.1", "X-Requested-With", "XMLHttpRequest")
	if a := tr.Winner.Auth; a.Decision != "deny" || a.Status != 401 {
		t.Errorf("xhr: %+v", a)
	}
	b.login("/")
	tr = explainAuthFor(t, s, "127.0.0.1", "Cookie", b.cookieHeader())
	a = tr.Winner.Auth
	if a.Decision != "allow" || a.Method != "oidc" || a.Subject != "user-1" {
		t.Fatalf("with session: %+v", a)
	}
	got := tr.Winner.Backends[0].Request.Headers
	if got["X-User"] != "alice" || got["X-Setura-Auth-Method"] != "oidc" {
		t.Errorf("explained upstream headers: %v", got)
	}
	if got["Authorization"] != redacted {
		t.Errorf("the forwarded access token must be redacted: %q", got["Authorization"])
	}
}
