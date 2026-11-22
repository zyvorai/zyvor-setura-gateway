package gateway

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func hmod(set, add, remove string) m {
	h := m{}
	if set != "" {
		n, v, _ := strings.Cut(set, "=")
		h["set"] = l{m{"name": n, "value": v}}
	}
	if add != "" {
		n, v, _ := strings.Cut(add, "=")
		h["add"] = l{m{"name": n, "value": v}}
	}
	if remove != "" {
		h["remove"] = l{remove}
	}
	return h
}

// TestUpstreamRequestMatchesProxy runs every filter type through the live
// proxy and through Explain, and fails if the upstream request they build
// diverges. Both call shapeUpstream; this guards against a new filter being
// wired into only one of them.
func TestUpstreamRequestMatchesProxy(t *testing.T) {
	be, ups := upstreams(t, "a", "mirror")
	refFilters := l{
		m{"type": "RequestHeaderModifier", "requestHeaderModifier": hmod("X-Ref=1", "X-Add=ref", "X-Drop2")},
		m{"type": "ResponseHeaderModifier", "responseHeaderModifier": hmod("X-Resp=ref", "", "")},
	}
	a := ref("a", 1)
	a["filters"] = refFilters
	routes := map[string]m{
		"rw": route("rw.test", m{
			"matches": l{m{"path": m{"type": "PathPrefix", "value": "/api"}}},
			"filters": l{
				m{"type": "RequestHeaderModifier", "requestHeaderModifier": hmod("X-Env=prod", "X-Add=rule", "X-Drop")},
				m{"type": "URLRewrite", "urlRewrite": m{"hostname": "internal.svc", "path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2"}}},
				m{"type": "ResponseHeaderModifier", "responseHeaderModifier": hmod("X-Resp=rule", "", "")},
				m{"type": "RequestMirror", "requestMirror": m{"backendRef": ref("mirror", -1)}},
			},
			"backendRefs": l{a},
		}),
		"full": route("full.test", m{
			"matches":     l{m{"path": m{"type": "Exact", "value": "/old"}}},
			"filters":     l{m{"type": "URLRewrite", "urlRewrite": m{"path": m{"type": "ReplaceFullPath", "replaceFullPath": "/new/full"}}}},
			"backendRefs": l{ref("a", 1)},
		}),
		"redir": route("redir.test", m{
			"filters": l{m{"type": "RequestRedirect", "requestRedirect": m{"scheme": "https", "statusCode": 308}}},
		}),
		// Gateway API 1.5 filters: each must go through the shared helpers on both paths.
		"cors": route("cors.test", withFilters(rule("/api", ref("a", 1)),
			m{"type": "CORS", "cors": m{"allowOrigins": l{"https://app.example.com"}, "allowCredentials": true, "exposeHeaders": l{"X-Out"}}},
			m{"type": "ResponseHeaderModifier", "responseHeaderModifier": hmod("X-Resp=cors", "", "")})),
		"auth": route("auth.test", withFilters(rule("/api", ref("a", 1)),
			m{"type": "ExternalAuth", "externalAuth": m{"protocol": "HTTP", "backendRef": ref("authz", -1), "http": m{"path": "/v", "allowedResponseHeaders": l{"X-User"}}}},
			m{"type": "RequestHeaderModifier", "requestHeaderModifier": hmod("X-After-Auth=1", "", "")})),
	}
	authSrv, _ := httpAuthServer(t)
	be["authz"] = strings.TrimPrefix(authSrv.URL, "http://")
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	hdrs := []string{"X-Drop", "x", "X-Drop2", "y", "X-Add", "client", "X-Keep", "k", "Forwarded", "for=6.6.6.6",
		"X-Forwarded-For", "6.6.6.6", "X-Forwarded-Proto", "https", "Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"Tracestate", "v=1", "X-Request-Id", "req-42", "Origin", "https://app.example.com", "Authorization", "Bearer ok"}
	type tc struct{ host, target string }
	for _, c := range []tc{{"rw.test", "/api/users?x=1"}, {"rw.test", "/api"}, {"full.test", "/old"}, {"cors.test", "/api"}, {"auth.test", "/api"}} {
		before := len(ups["a"].seen())
		live := req(t, client(s.Addr(8080), nil), "http", "GET", c.host+":8080", c.target, "", hdrs...)
		if live.Status != 200 {
			t.Fatalf("%s%s: status %d", c.host, c.target, live.Status)
		}
		got := ups["a"].seen()[before:]
		if len(got) != 1 {
			t.Fatalf("%s%s: backend saw %d requests", c.host, c.target, len(got))
		}
		seen := got[0]

		er, err := ParseExplainRequest("GET", "http://"+c.host+":8080"+c.target, headerLines(hdrs), "", "")
		if err != nil {
			t.Fatal(err)
		}
		er.Remote = "127.0.0.1"
		tr := Explain(s.Table(), er)
		if tr.Winner == nil || len(tr.Winner.Backends) == 0 || tr.Winner.Backends[0].Request == nil {
			t.Fatalf("%s%s: no upstream request\n%s", c.host, c.target, dumpTrace(tr))
		}
		up := tr.Winner.Backends[0].Request
		u, _ := url.Parse(up.URL)
		if u.Path != seen.Path || u.RawQuery != seen.Query || up.Host != seen.Host || up.Method != seen.Method {
			t.Fatalf("%s%s: explain %s %s host %s, proxy sent %s %s?%s host %s", c.host, c.target, up.Method, u.Path, up.Host, seen.Method, seen.Path, seen.Query, seen.Host)
		}
		ignored := map[string]bool{"user-agent": true, "accept-encoding": true, "content-length": true, "x-setura-mirror": true}
		for k, v := range up.Headers {
			lk := strings.ToLower(k)
			sv, ok := seen.Headers[lk]
			if !ok {
				t.Errorf("%s%s: explain shows %s: %s, proxy did not send it", c.host, c.target, k, v)
				continue
			}
			switch lk {
			case "traceparent":
				// the span id is generated per request: compare the rest
				if !strings.HasPrefix(sv, "00-0af7651916cd43dd8448eb211c80319c-") || !strings.HasSuffix(sv, "-01") || !strings.HasPrefix(v, "00-0af7651916cd43dd8448eb211c80319c-") {
					t.Errorf("%s%s: traceparent explain %q proxy %q", c.host, c.target, v, sv)
				}
			case "x-user":
				// ExternalAuth: the answer is only known at run time, so explain
				// shows a placeholder where the proxy sends the service's value.
				if v != authPreviewValue || sv != "alice" || c.host != "auth.test" {
					t.Errorf("%s%s: x-user explain %q proxy %q", c.host, c.target, v, sv)
				}
			case "tracestate", "x-request-id", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-env", "x-add", "x-ref", "x-keep":
				if sv != v {
					t.Errorf("%s%s: %s explain %q proxy %q", c.host, c.target, k, v, sv)
				}
			default:
				if sv != v {
					t.Errorf("%s%s: %s explain %q proxy %q", c.host, c.target, k, v, sv)
				}
			}
		}
		for k := range seen.Headers {
			if _, ok := up.Headers[http.CanonicalHeaderKey(k)]; !ok && !ignored[k] {
				t.Errorf("%s%s: proxy sent %s, explain does not show it", c.host, c.target, k)
			}
		}
		if seen.Headers["forwarded"] != "" || (c.host == "rw.test" && seen.Headers["x-drop"] != "") {
			t.Errorf("%s%s: forwarded/removed headers reached the backend: %v", c.host, c.target, seen.Headers)
		}
		if seen.Headers["x-forwarded-for"] != "127.0.0.1" {
			t.Errorf("client X-Forwarded-For must be replaced, got %q", seen.Headers["x-forwarded-for"])
		}
		// Response side: what Explain says the gateway adds must be what the client gets.
		for k, v := range tr.Winner.Backends[0].ResponseHeaders {
			if got := strings.Join(live.Header.Values(k), ", "); got != v {
				t.Errorf("%s%s: response header %s explain %q live %q", c.host, c.target, k, v, got)
			}
		}
		if c.host == "cors.test" {
			if len(tr.Winner.Backends[0].ResponseHeaders) == 0 || live.Header.Get("Access-Control-Allow-Origin") == "" {
				t.Errorf("%s: explain shows no response headers: %+v", c.host, tr.Winner.Backends[0].ResponseHeaders)
			}
		}
	}
	// ResponseHeaderModifier and RequestRedirect are response-side: the
	// explainer must report the same Location the proxy sends.
	live := req(t, client(s.Addr(8080), nil), "http", "GET", "redir.test:8080", "/x?q=1", "")
	er, _ := ParseExplainRequest("GET", "http://redir.test:8080/x?q=1", nil, "", "")
	tr := Explain(s.Table(), er)
	if tr.Winner.Redirect == nil || tr.Winner.Redirect.Location != live.Header.Get("Location") || tr.Winner.Redirect.Status != live.Status {
		t.Fatalf("redirect: explain %+v live %d %q", tr.Winner.Redirect, live.Status, live.Header.Get("Location"))
	}
	live = req(t, client(s.Addr(8080), nil), "http", "GET", "rw.test:8080", "/api", "")
	if live.Header.Get("X-Resp") != "ref" {
		t.Fatalf("response header modifiers: rule then backendRef, got %q", live.Header.Get("X-Resp"))
	}
	er, _ = ParseExplainRequest("GET", "http://rw.test:8080/api", nil, "", "")
	tr = Explain(s.Table(), er)
	types := map[string]bool{}
	for _, f := range tr.Winner.Filters {
		types[f.Type] = true
	}
	for _, want := range []string{"RequestHeaderModifier", "ResponseHeaderModifier", "URLRewrite", "RequestMirror"} {
		if !types[want] {
			t.Errorf("explain does not describe filter %s: %+v", want, tr.Winner.Filters)
		}
	}
}

func headerLines(h []string) []string {
	var out []string
	for i := 0; i+1 < len(h); i += 2 {
		out = append(out, h[i]+": "+h[i+1])
	}
	return out
}

func TestExplainTraceAndForwardedHeaders(t *testing.T) {
	be := fakeBackends("a")
	tb := tableOf(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, be), nil)
	up := func(hs ...string) *TraceUpstream {
		tr := explain(t, tb, "GET", "http://x.test:8080/", hs...)
		return tr.Winner.Backends[0].Request
	}
	g := up()
	if !strings.Contains(g.Headers["Traceparent"], "<generated-trace-id>") || g.Headers["X-Request-Id"] != "<generated>" || g.Headers["X-Forwarded-For"] != "<client-ip>" {
		t.Fatalf("generated headers: %+v", g.Headers)
	}
	c := up("Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-00", "X-Request-Id", "abc", "X-Forwarded-For", "9.9.9.9", "Forwarded", "for=1.1.1.1", "Connection", "close")
	if c.Headers["Traceparent"] != "00-0af7651916cd43dd8448eb211c80319c-<new-span-id>-00" || c.Headers["X-Request-Id"] != "abc" {
		t.Fatalf("continued trace: %+v", c.Headers)
	}
	if c.Headers["X-Forwarded-For"] != "<client-ip>" || c.Headers["Forwarded"] != "" || c.Headers["Connection"] != "" {
		t.Fatalf("client forwarding headers must not survive: %+v", c.Headers)
	}
}

func TestExplainRateLimitRetryMirrors(t *testing.T) {
	be := fakeBackends("a", "shadow")
	pct := 25
	rl := rule("/", ref("a", 1))
	rl["retry"] = m{"codes": l{502, 503}, "attempts": 2, "backoff": "50ms"}
	rl["filters"] = l{m{"type": "RequestMirror", "requestMirror": m{"backendRef": ref("shadow", -1), "percent": pct,
		ShadowDiffKey: m{"compare": true, "sample": 40, "ignoreHeaders": l{"X-Trace"}, "latencyThresholdMs": 20}}}}
	tb := tableOf(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, be), nil)

	req, _ := ParseExplainRequest("POST", "http://x.test:8080/", nil, "", "")
	req.Server.RateLimit = RateLimitConfig{Rate: 5, Per: time.Second, Burst: 10, Key: "ip"}
	req.Remote = "10.1.2.3"
	tr := Explain(tb, req)
	w := tr.Winner
	if w.Retry == nil || w.Retry.Attempts != 2 || len(w.Retry.Codes) != 2 || w.Retry.Idempotent || w.Retry.Backoff != "50ms" || !strings.Contains(w.Retry.Budget, "20%") {
		t.Fatalf("retry: %+v", w.Retry)
	}
	if rlm := w.RateLimit; rlm == nil || !rlm.Enabled || rlm.Live || !strings.Contains(rlm.Policy, "burst 10") || !strings.Contains(rlm.Bucket, "10.1.2.3") || rlm.Limited != nil {
		t.Fatalf("rate limit: %+v", w.RateLimit)
	}
	if len(w.MirrorTargets) != 1 || w.MirrorTargets[0].Percent != 25 || !strings.Contains(w.MirrorTargets[0].ShadowDiff, "40%") || !strings.Contains(w.MirrorTargets[0].ShadowDiff, "x-trace") || !strings.Contains(w.MirrorTargets[0].ShadowDiff, "+20 ms") {
		t.Fatalf("mirrors: %+v", w.MirrorTargets)
	}
	req.Server = ExplainServer{}
	if tr = Explain(tb, req); tr.Winner.RateLimit.Enabled {
		t.Fatalf("no policy means no limit: %+v", tr.Winner.RateLimit)
	}
}

func TestAdminWhyLiveRateLimit(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, be), func(o *Options) {
		o.Obs.RateLimit = RateLimitConfig{Rate: 1, Per: time.Hour, Burst: 1, Key: "route"}
	})
	c := client(s.Addr(8080), nil)
	if r := req(t, c, "http", "GET", "x.test:8080", "/", ""); r.Status != 200 {
		t.Fatalf("first request %d", r.Status)
	}
	er, _ := ParseExplainRequest("GET", "http://x.test:8080/", nil, "", "")
	er.Live, er.Now, er.Server = true, s.res.now(), s.liveServerPolicy()
	tr := Explain(s.Table(), er)
	rlm := tr.Winner.RateLimit
	if rlm == nil || !rlm.Live || rlm.Limited == nil || !*rlm.Limited {
		t.Fatalf("the bucket is empty, the next request is limited: %+v", rlm)
	}
	if r := req(t, c, "http", "GET", "x.test:8080", "/", ""); r.Status != 429 {
		t.Fatalf("live status %d, explain said limited", r.Status)
	}
}

func TestCreationTimestampTieBreak(t *testing.T) {
	mk := func(a, b m) []byte {
		ra, rb := route("", rule("/", ref("a", 1))), route("", rule("/", ref("b", 1)))
		for k, v := range a {
			ra[k] = v
		}
		for k, v := range b {
			rb[k] = v
		}
		return snap(httpGateway(""), map[string]m{"a-route": ra, "b-route": rb}, fakeBackends("a", "b"))
	}
	meta := func(ts string) m { return m{"metadata": m{"creationTimestamp": ts}} }
	top := func(ts string) m { return m{"creationTimestamp": ts} }
	cases := []struct {
		name         string
		raw          []byte
		winner, rule string
	}{
		{"metadata, b older", mk(meta("2026-02-01T00:00:00Z"), meta("2026-01-01T00:00:00Z")), "b", "the oldest creationTimestamp wins"},
		{"top level, b older", mk(top("2026-02-01T00:00:00Z"), top("2026-01-01T00:00:00Z")), "b", "the oldest creationTimestamp wins"},
		{"metadata beats top level", mk(m{"metadata": m{"creationTimestamp": "2026-01-01T00:00:00Z"}, "creationTimestamp": "2027-01-01T00:00:00Z"}, top("2026-06-01T00:00:00Z")), "a", "the oldest creationTimestamp wins"},
		{"none, name order", mk(nil, nil), "a", "neither route has a creationTimestamp"},
		{"equal, name order", mk(top("2026-01-01T00:00:00Z"), top("2026-01-01T00:00:00Z")), "a", "created at the same time"},
		{"one stamped, unstamped counts oldest", mk(top("2026-01-01T00:00:00Z"), nil), "b", "counts as oldest"},
	}
	for _, c := range cases {
		tr := explain(t, tableOf(t, c.raw, nil), "GET", "http://x.test:8080/")
		if winnerName(tr) != c.winner || !anyReason(tr, c.rule) {
			t.Errorf("%s: winner %q\n%s", c.name, winnerName(tr), dumpTrace(tr))
		}
	}
	if _, err := ParseConfig(mk(top("yesterday"), nil), t.TempDir()); err == nil || !strings.Contains(err.Error(), "RFC 3339") {
		t.Fatalf("bad timestamp should be rejected, got %v", err)
	}
}
