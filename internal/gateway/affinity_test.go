package gateway

import (
	"net/http"
	"testing"
	"time"
)

func TestBackendRequestTimeout(t *testing.T) {
	be, _ := upstreams(t, "a")
	mk := func(bt, rt string) []byte {
		rl := rule("/", ref("a", 1))
		to := m{"backendRequest": bt}
		if rt != "" {
			to["request"] = rt
		}
		rl["timeouts"] = to
		return snap(httpGateway(""), map[string]m{"r": route("", rl)}, be)
	}
	s := startServer(t, mk("100ms", "5s"), nil)
	if r := get(t, s, "x.test", "/slow"); r.Status != http.StatusGatewayTimeout {
		t.Errorf("a backend slower than backendRequest must time out with 504, got %d", r.Status)
	}
	if r := get(t, s, "x.test", "/fast"); r.Status != 200 {
		t.Errorf("a fast backend: %d", r.Status)
	}
	s = startServer(t, mk("2s", "5s"), nil)
	if r := get(t, s, "x.test", "/slow"); r.Status != 200 {
		t.Errorf("a generous backendRequest: %d", r.Status)
	}
	// backendRequest may not exceed request.
	tb := tableOf(t, mk("9s", "1s"), nil)
	if c := cond(BuildStatus(tb, nil, tnow(), nil).Routes["t/r"].Parents[0].Conditions, "Accepted"); c.Status != "False" {
		t.Errorf("backendRequest > request must be refused: %+v", c)
	}
	// Explain reports it.
	tb = tableOf(t, mk("250ms", ""), nil)
	if tr := explain(t, tb, "GET", "http://x.test:8080/"); tr.Winner.BackendTimeout != "250ms" {
		t.Errorf("explain: %+v", tr.Winner)
	}
}

func twoEndpoints(t *testing.T) (map[string]any, map[string]*upstream) {
	u1, u2 := newUpstream(t, "u1"), newUpstream(t, "u2")
	return map[string]any{"svc": m{"endpoints": l{u1.addr(), u2.addr()}}}, map[string]*upstream{"u1": u1, "u2": u2}
}

func sessionRule(sp m) m {
	rl := rule("/", ref("svc", 1))
	rl["sessionPersistence"] = sp
	return route("", rl)
}

func cookieOf(h http.Header, name string) string {
	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func TestSessionPersistenceCookie(t *testing.T) {
	be, _ := twoEndpoints(t)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": sessionRule(m{"sessionName": "sid", "type": "Cookie"})}, be), nil)
	c := client(s.Addr(8080), nil)
	first := req(t, c, "http", "GET", "x.test:8080", "/", "")
	tok := cookieOf(first.Header, "sid")
	if tok == "" {
		t.Fatalf("no session cookie: %v", first.Header)
	}
	want := first.Echo.Name
	for i := 0; i < 12; i++ {
		r := req(t, c, "http", "GET", "x.test:8080", "/", "", "Cookie", "sid="+tok)
		if r.Echo.Name != want {
			t.Fatalf("request %d went to %s, the session is pinned to %s", i, r.Echo.Name, want)
		}
	}
	// Without the cookie, clients still spread over both endpoints.
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		seen[req(t, c, "http", "GET", "x.test:8080", "/", "").Echo.Name] = true
	}
	if len(seen) != 2 {
		t.Errorf("anonymous clients should balance: %v", seen)
	}
	// A forged or foreign token is ignored.
	if r := req(t, c, "http", "GET", "x.test:8080", "/", "", "Cookie", "sid=garbage.sig"); cookieOf(r.Header, "sid") == "" {
		t.Errorf("a bad token starts a new session")
	}
}

func TestSessionPersistenceNeverToEjectedEndpoint(t *testing.T) {
	be, u := twoEndpoints(t)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": sessionRule(m{"sessionName": "sid"})}, be), nil)
	c := client(s.Addr(8080), nil)
	first := req(t, c, "http", "GET", "x.test:8080", "/", "")
	tok, pinned := cookieOf(first.Header, "sid"), first.Echo.Name
	b := s.Table().Backends["t/svc:80"]
	for _, ep := range b.Eps {
		if ep.URL.Host == u[pinned].addr() {
			ep.healthy.Store(false)
		}
	}
	other := ""
	for i := 0; i < 5; i++ {
		r := req(t, c, "http", "GET", "x.test:8080", "/", "", "Cookie", "sid="+tok)
		if r.Echo.Name == pinned {
			t.Fatalf("request %d went to the unhealthy endpoint %s", i, pinned)
		}
		other = r.Echo.Name
		if nt := cookieOf(r.Header, "sid"); nt != "" {
			tok = nt // the gateway re-pins to the healthy endpoint
		}
	}
	for _, ep := range b.Eps {
		ep.healthy.Store(true) // the old endpoint comes back: the new session stays where it is
	}
	for i := 0; i < 6; i++ {
		if r := req(t, c, "http", "GET", "x.test:8080", "/", "", "Cookie", "sid="+tok); r.Echo.Name != other {
			t.Fatalf("session moved back to %s", r.Echo.Name)
		}
	}
}

func TestSessionPersistenceHeaderAndTimeouts(t *testing.T) {
	be, u := twoEndpoints(t)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": sessionRule(m{"sessionName": "X-Session", "type": "Header", "idleTimeout": "1h", "absoluteTimeout": "2h"})}, be), nil)
	c := client(s.Addr(8080), nil)
	first := req(t, c, "http", "GET", "x.test:8080", "/", "")
	tok := first.Header.Get("X-Session")
	if tok == "" {
		t.Fatalf("no session header: %v", first.Header)
	}
	for i := 0; i < 8; i++ {
		if r := req(t, c, "http", "GET", "x.test:8080", "/", "", "X-Session", tok); r.Echo.Name != first.Echo.Name {
			t.Fatalf("header session moved to %s", r.Echo.Name)
		}
	}
	// With an idle timeout every response refreshes the token.
	r := req(t, c, "http", "GET", "x.test:8080", "/", "", "X-Session", tok)
	if r.Header.Get("X-Session") == "" {
		t.Errorf("idleTimeout sessions are refreshed on every response")
	}
	// Expired sessions are not honoured: absolute lifetime and idle time.
	ep := u[first.Echo.Name].addr()
	other := "u1"
	if first.Echo.Name == "u1" {
		other = "u2"
	}
	_ = other
	now := time.Now()
	for name, st := range map[string]sessionToken{
		"absolute": {ref: "svc", ep: ep, issued: now.Add(-3 * time.Hour).Unix(), lastN: now.Unix()},
		"idle":     {ref: "svc", ep: ep, issued: now.Unix(), lastN: now.Add(-2 * time.Hour).Unix()},
	} {
		pol, _ := compileSession(&SessionPersistence{SessionName: "X-Session", Type: "Header", IdleTimeout: "1h", AbsoluteTimeout: "2h"})
		if pol.valid(st, now) {
			t.Errorf("%s: an expired session must not be valid", name)
		}
		if !pol.valid(sessionToken{ref: "svc", ep: ep, issued: now.Unix(), lastN: now.Unix()}, now) {
			t.Errorf("a fresh session must be valid")
		}
	}
}

func TestSessionPolicyValidation(t *testing.T) {
	for _, sp := range []*SessionPersistence{{Type: "Bogus"}, {AbsoluteTimeout: "soon"}, {CookieConfig: &struct {
		LifetimeType string `json:"lifetimeType,omitempty"`
	}{LifetimeType: "Permanent"}}} {
		if _, err := compileSession(sp); err == nil {
			t.Errorf("%+v must be refused", sp)
		}
	}
	c, err := compileSession(&SessionPersistence{Type: "Cookie", AbsoluteTimeout: "1h", CookieConfig: &struct {
		LifetimeType string `json:"lifetimeType,omitempty"`
	}{LifetimeType: "Permanent"}})
	if err != nil || !c.Permanent || c.Name != defaultSessionName {
		t.Errorf("permanent cookie: %+v %v", c, err)
	}
}

func TestSessionPersistencePerBackendRef(t *testing.T) {
	be, _ := twoEndpoints(t)
	r := ref("svc", 1)
	r["setura.zyvor.dev/sessionPersistence"] = m{"sessionName": "refsid"}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", r))}, be), nil)
	c := client(s.Addr(8080), nil)
	first := req(t, c, "http", "GET", "x.test:8080", "/", "")
	tok := cookieOf(first.Header, "refsid")
	if tok == "" {
		t.Fatalf("no backendRef-level cookie: %v", first.Header)
	}
	for i := 0; i < 8; i++ {
		if r := req(t, c, "http", "GET", "x.test:8080", "/", "", "Cookie", "refsid="+tok); r.Echo.Name != first.Echo.Name {
			t.Fatalf("backendRef session moved")
		}
	}
}
