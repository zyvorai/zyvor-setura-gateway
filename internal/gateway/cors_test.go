package gateway

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// snapRes builds a snapshot from fully keyed resources, backends and extra
// top-level sections.
func snapRes(res m, backends map[string]any, top m) []byte {
	b := m{}
	for k, v := range backends {
		b["t/"+k+":80"] = v
	}
	doc := m{"schema": SnapshotSchema, "namespace": "t", "resources": res, "backends": b}
	for k, v := range top {
		doc[k] = v
	}
	return mustJSON(doc)
}

func withFilters(r m, fs ...m) m {
	var out l
	for _, f := range fs {
		out = append(out, f)
	}
	r["filters"] = out
	return r
}

func TestCORSFilter(t *testing.T) {
	be, ups := upstreams(t, "a")
	creds := m{"type": "CORS", "cors": m{"allowOrigins": l{"https://app.example.com", "https://*.dev.example.com"}, "allowCredentials": true,
		"allowMethods": l{"GET", "POST"}, "allowHeaders": l{"X-Token"}, "exposeHeaders": l{"X-Out"}, "maxAge": 600}}
	open := m{"type": "CORS", "cors": m{"allowOrigins": l{"*"}, "allowMethods": l{"*"}, "allowHeaders": l{"*"}}}
	star := m{"type": "CORS", "cors": m{"allowOrigins": l{"*"}, "allowCredentials": true, "allowMethods": l{"*"}, "allowHeaders": l{"*"}}}
	getOnly := rule("/", ref("a", 1))
	getOnly["matches"] = l{m{"path": m{"type": "PathPrefix", "value": "/"}, "method": "GET"}}
	routes := map[string]m{
		"creds": route("creds.test", withFilters(getOnly, creds)),
		"open":  route("open.test", withFilters(rule("/", ref("a", 1)), open)),
		"star":  route("star.test", withFilters(rule("/", ref("a", 1)), star)),
		"none":  route("none.test", rule("/", ref("a", 1))),
	}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	c := client(s.Addr(8080), nil)
	pre := func(host, origin, method string, extra ...string) reply {
		h := append([]string{"Origin", origin, "Access-Control-Request-Method", method}, extra...)
		return req(t, c, "http", "OPTIONS", host+":8080", "/x", "", h...)
	}

	// Preflight from an allowed origin: answered by the gateway, backend untouched.
	r := pre("creds.test", "https://app.example.com", "GET", "Access-Control-Request-Headers", "X-Token")
	if r.Status != 200 || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" ||
		r.Header.Get("Access-Control-Allow-Credentials") != "true" || r.Header.Get("Access-Control-Allow-Methods") != "GET, POST" ||
		r.Header.Get("Access-Control-Allow-Headers") != "X-Token" || r.Header.Get("Access-Control-Max-Age") != "600" {
		t.Fatalf("preflight: %d %v", r.Status, r.Header)
	}
	if !strings.Contains(strings.Join(r.Header.Values("Vary"), ","), "Origin") {
		t.Errorf("preflight must Vary on Origin: %v", r.Header.Values("Vary"))
	}
	if n := len(ups["a"].seen()); n != 0 {
		t.Fatalf("a preflight must not reach the backend, saw %d requests", n)
	}
	// A wildcard-host origin.
	if r = pre("creds.test", "https://x.y.dev.example.com", "GET"); r.Header.Get("Access-Control-Allow-Origin") != "https://x.y.dev.example.com" {
		t.Errorf("wildcard origin: %v", r.Header)
	}
	// Not allowed: answered, but without any CORS grant.
	if r = pre("creds.test", "https://evil.test", "GET"); r.Status != 200 || r.Header.Get("Access-Control-Allow-Origin") != "" || r.Header.Get("Access-Control-Allow-Methods") != "" {
		t.Errorf("denied origin: %d %v", r.Status, r.Header)
	}
	if r = pre("creds.test", "https://dev.example.com", "GET"); r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("*.dev.example.com must not match dev.example.com itself: %v", r.Header)
	}
	// "*" without credentials answers "*"; with credentials it echoes and never sends "*".
	r = pre("open.test", "https://any.test", "PUT", "Access-Control-Request-Headers", "X-A, X-B")
	if r.Header.Get("Access-Control-Allow-Origin") != "*" || r.Header.Get("Access-Control-Allow-Methods") != "*" || r.Header.Get("Access-Control-Allow-Headers") != "*" {
		t.Errorf("open preflight: %v", r.Header)
	}
	r = pre("star.test", "https://any.test", "PUT", "Access-Control-Request-Headers", "X-A, X-B")
	if r.Header.Get("Access-Control-Allow-Origin") != "https://any.test" || r.Header.Get("Access-Control-Allow-Methods") != "PUT" ||
		r.Header.Get("Access-Control-Allow-Headers") != "X-A, X-B" || r.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("credentialed wildcard must echo: %v", r.Header)
	}
	// Default maxAge is 5 seconds.
	if r = pre("open.test", "https://any.test", "GET"); r.Header.Get("Access-Control-Max-Age") != "5" {
		t.Errorf("default max age: %v", r.Header)
	}
	// An OPTIONS request without the preflight headers is an ordinary request.
	r = req(t, c, "http", "OPTIONS", "open.test:8080", "/x", "", "Origin", "https://any.test")
	if r.Echo.Method != "OPTIONS" {
		t.Errorf("a plain OPTIONS must reach the backend: %+v", r)
	}
	// Routes without a CORS filter pass preflights through to the backend.
	before := len(ups["a"].seen())
	pre("none.test", "https://any.test", "GET")
	if len(ups["a"].seen()) != before+1 {
		t.Errorf("a route without CORS forwards the preflight")
	}

	// Actual requests get the response headers.
	r = req(t, c, "http", "GET", "creds.test:8080", "/x", "", "Origin", "https://app.example.com")
	if r.Status != 200 || r.Header.Get("Access-Control-Allow-Origin") != "https://app.example.com" || r.Header.Get("Access-Control-Expose-Headers") != "X-Out" ||
		r.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Errorf("actual request: %d %v", r.Status, r.Header)
	}
	r = req(t, c, "http", "GET", "creds.test:8080", "/x", "", "Origin", "https://evil.test")
	if r.Status != 200 || r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("denied actual request must carry no grant: %v", r.Header)
	}
	r = req(t, c, "http", "GET", "open.test:8080", "/x", "", "Origin", "https://any.test")
	if r.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("open actual request: %v", r.Header)
	}
}

func TestCORSValidation(t *testing.T) {
	for _, bad := range []any{l{"example.com"}, l{"https://a.*.com"}, l{"https://example.com/path"}} {
		f := m{"type": "CORS", "cors": m{"allowOrigins": bad}}
		be, _ := upstreams(t, "a")
		tb := tableOf(t, snap(httpGateway(""), map[string]m{"r": route("", withFilters(rule("/", ref("a", 1)), f))}, be), nil)
		st := BuildStatus(tb, nil, time.Now(), nil)
		if c := cond(st.Routes["t/r"].Parents[0].Conditions, "Accepted"); c.Status != "False" || c.Reason != "UnsupportedValue" {
			t.Errorf("%v: %+v", bad, c)
		}
	}
	// Unknown filter types stay unsupported.
	if err := validFilters([]Filter{{Type: "CORS"}}); err == nil {
		t.Error("a CORS filter without a cors block is invalid")
	}
}

func TestCORSPreflightExplain(t *testing.T) {
	be := fakeBackends("a")
	f := m{"type": "CORS", "cors": m{"allowOrigins": l{"https://app.example.com"}, "allowMethods": l{"GET"}}}
	getOnly := rule("/", ref("a", 1))
	getOnly["matches"] = l{m{"method": "GET"}}
	tb := tableOf(t, snap(httpGateway(""), map[string]m{"r": route("", withFilters(getOnly, f))}, be), nil)
	tr := explain(t, tb, "OPTIONS", "http://x.test:8080/p", "Origin", "https://app.example.com", "Access-Control-Request-Method", "GET")
	if tr.Winner == nil || tr.Winner.Preflight["Access-Control-Allow-Origin"] != "https://app.example.com" {
		t.Fatalf("preflight explanation: %+v", tr.Winner)
	}
}

var _ = http.StatusOK

func tnow() time.Time { return time.Now() }
