package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

const adminTok = "adm1n-t0ken-VALUE"

func adminGet(t *testing.T, addr, path string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	rq, _ := http.NewRequest("GET", "http://"+addr+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			rq.Host = hdr[i+1]
			continue
		}
		rq.Header.Set(hdr[i], hdr[i+1])
	}
	c := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestAdminRefusesOffLoopbackWithoutToken(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "192.0.2.1:0"} {
		s := New(Options{Admin: addr})
		err := s.startAdmin()
		if err == nil || !strings.Contains(err.Error(), "--admin-token") {
			t.Errorf("%s: %v", addr, err)
		}
		s.Close()
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		s := New(Options{Admin: addr})
		if err := s.startAdmin(); err != nil {
			t.Logf("%s: %v (no IPv6 here?)", addr, err)
		}
		s.Close()
	}
	// With a token, any address is allowed.
	s := New(Options{Admin: "0.0.0.0:0", AdminToken: adminTok})
	if err := s.startAdmin(); err != nil {
		t.Errorf("token + 0.0.0.0: %v", err)
	}
	s.Close()
}

func TestAdminTokenRules(t *testing.T) {
	var diag bytes.Buffer
	s := New(Options{Admin: "127.0.0.1:0", AdminToken: adminTok, AdminOpenReady: true, Diag: &diag})
	t.Cleanup(s.Close)
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	a := s.AdminAddr()
	if code, _, h := adminGet(t, a, "/config"); code != 401 || !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("no token: %d %v", code, h)
	}
	if code, _, _ := adminGet(t, a, "/config", "Authorization", "Bearer wrong"); code != 401 {
		t.Errorf("wrong token: %d", code)
	}
	if code, _, _ := adminGet(t, a, "/config", "Authorization", "Basic "+adminTok); code != 401 {
		t.Errorf("wrong scheme: %d", code)
	}
	if code, _, _ := adminGet(t, a, "/stats", "Authorization", "Bearer "+adminTok); code != 503 && code != 200 {
		t.Errorf("bearer: %d", code)
	}
	if code, _, _ := adminGet(t, a, "/stats", "Cookie", adminCookie+"="+adminTok); code != 503 && code != 200 {
		t.Errorf("cookie: %d", code)
	}
	// /ready stays open with --admin-open-ready, and only /ready.
	if code, _, _ := adminGet(t, a, "/ready"); code != 503 { // not applied yet: the handler ran, so the guard let it in
		t.Errorf("/ready: %d", code)
	}
	if code, _, _ := adminGet(t, a, "/metrics"); code != 401 {
		t.Errorf("/metrics must still need the token: %d", code)
	}
	// ?token= trades the secret for a cookie and a clean URL.
	code, _, h := adminGet(t, a, "/stats?x=1&token="+adminTok)
	if code != http.StatusSeeOther || h.Get("Location") != "/stats?x=1" || !strings.Contains(h.Get("Set-Cookie"), adminCookie+"="+adminTok) || !strings.Contains(h.Get("Set-Cookie"), "HttpOnly") {
		t.Errorf("token exchange: %d %q %q", code, h.Get("Location"), h.Get("Set-Cookie"))
	}
	if code, _, _ := adminGet(t, a, "/stats?token=wrong"); code != 401 {
		t.Errorf("wrong ?token=: %d", code)
	}
	if strings.Contains(diag.String(), adminTok) {
		t.Errorf("the token was written to diagnostics: %s", diag.String())
	}
}

func TestAdminOpenReadyIsOffByDefault(t *testing.T) {
	s := New(Options{Admin: "127.0.0.1:0", AdminToken: adminTok})
	t.Cleanup(s.Close)
	s.startAdmin()
	if code, _, _ := adminGet(t, s.AdminAddr(), "/ready"); code != 401 {
		t.Errorf("/ready without --admin-open-ready: %d", code)
	}
}

func TestAdminWithoutTokenChecksHost(t *testing.T) {
	s := New(Options{Admin: "127.0.0.1:0"})
	t.Cleanup(s.Close)
	s.startAdmin()
	if code, _, _ := adminGet(t, s.AdminAddr(), "/ready"); code != 503 {
		t.Errorf("loopback host: %d", code)
	}
	if code, _, _ := adminGet(t, s.AdminAddr(), "/ready", "Host", "evil.example:19000"); code != 403 {
		t.Errorf("DNS rebinding host: %d", code)
	}
}

func TestRunWithAdminTokenAndWhyDoesNotLeakCredentials(t *testing.T) {
	k := newRSAKey(t, "k")
	be, _ := upstreams(t, "a")
	r := rule("/", ref("a", 1))
	r[authKeyT] = m{"jwt": m{"audience": l{"api"}, "jwks": json.RawMessage(jwksDoc(k))}}
	raw := snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, be)
	path := t.TempDir() + "/cfg.json"
	writeFile(t, path, raw)
	s, cancel, done := startFile(t, path, func(o *Options) {
		o.AdminToken = adminTok
		o.AuthClock = func() time.Time { return t0 }
	})
	_ = cancel
	_ = done
	tok := k.sign(t, nil, claims(nil))
	q := "/why?url=" + "http://a.test:8080/&header=" + "Authorization:%20Bearer%20" + tok + "&client=127.0.0.1"
	if code, _, _ := adminGet(t, s.AdminAddr(), q); code != 401 {
		t.Fatalf("/why without the admin token: %d", code)
	}
	code, body, _ := adminGet(t, s.AdminAddr(), q, "Authorization", "Bearer "+adminTok)
	if code != 200 {
		t.Fatalf("/why: %d %s", code, body)
	}
	if strings.Contains(body, tok) || strings.Contains(body, adminTok) || strings.Contains(body, strings.Split(tok, ".")[1]) {
		t.Errorf("/why echoes a credential:\n%s", body)
	}
	var tr Trace
	if err := json.Unmarshal([]byte(body), &tr); err != nil {
		t.Fatal(err)
	}
	if tr.Winner == nil || tr.Winner.Auth == nil || tr.Winner.Auth.Decision != "allow" || tr.Winner.Auth.Method != "jwt" || tr.Winner.Auth.Subject != "alice" {
		t.Errorf("auth decision: %+v", tr.Winner)
	}
	_ = context.Background
}
