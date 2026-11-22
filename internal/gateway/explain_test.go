package gateway

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tableOf(t *testing.T, raw []byte, mod func(*Config)) *Table {
	t.Helper()
	cfg, err := ParseConfig(raw, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(cfg)
	}
	return BuildTable(cfg)
}

func explain(t *testing.T, tb *Table, method, url string, hdr ...string) *Trace {
	t.Helper()
	var hs []string
	for i := 0; i+1 < len(hdr); i += 2 {
		hs = append(hs, hdr[i]+": "+hdr[i+1])
	}
	req, err := ParseExplainRequest(method, url, hs, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return Explain(tb, req)
}

func winnerName(tr *Trace) string {
	if tr.Winner == nil || len(tr.Winner.Backends) == 0 {
		return ""
	}
	return tr.Winner.Backends[0].Name
}

func anyReason(tr *Trace, sub string) bool {
	for _, c := range tr.Candidates {
		if strings.Contains(c.Reason, sub) {
			return true
		}
	}
	return false
}

func fakeBackends(names ...string) map[string]any {
	be := map[string]any{}
	for _, n := range names {
		be[n] = "127.0.0.1:9"
	}
	return be
}

func dumpTrace(tr *Trace) string {
	b, _ := json.MarshalIndent(tr, "", " ")
	return string(b)
}

func allReasons(tr *Trace) string {
	var b strings.Builder
	for _, c := range tr.Candidates {
		b.WriteString(c.Reason + "\n")
	}
	for _, l := range tr.Listeners {
		b.WriteString(l.Reason + "\n")
	}
	return b.String()
}

func TestExplainPrecedence(t *testing.T) {
	pathRule := func(typ, val, backend string, extra m) m {
		match := m{"path": m{"type": typ, "value": val}}
		for k, v := range extra {
			match[k] = v
		}
		return m{"matches": l{match}, "backendRefs": l{ref(backend, 1)}}
	}
	names := []string{"exact", "long", "short", "root", "method", "hdr2", "hdr1", "q2", "q1", "regex", "wild", "host", "default"}
	routes := map[string]m{
		"a": route("",
			pathRule("PathPrefix", "/", "root", nil),
			pathRule("PathPrefix", "/api", "short", nil),
			pathRule("PathPrefix", "/api/v1", "long", nil),
			pathRule("Exact", "/api/v1/users", "exact", nil),
			pathRule("RegularExpression", "/api/v1/[a-z]+", "regex", nil),
			pathRule("PathPrefix", "/m", "default", nil),
			pathRule("PathPrefix", "/m", "method", m{"method": "POST"}),
			pathRule("PathPrefix", "/h", "default", nil),
			pathRule("PathPrefix", "/h", "hdr1", m{"headers": l{m{"name": "X-A", "value": "1"}}}),
			pathRule("PathPrefix", "/h", "hdr2", m{"headers": l{m{"name": "X-A", "value": "1"}, m{"name": "X-B", "type": "RegularExpression", "value": "b+"}}}),
			pathRule("PathPrefix", "/q", "q1", m{"queryParams": l{m{"name": "a", "value": "1"}}}),
			pathRule("PathPrefix", "/q", "q2", m{"queryParams": l{m{"name": "a", "value": "1"}, m{"name": "b", "type": "RegularExpression", "value": "[0-9]"}}}),
		),
		"wild": route("*.mactra.test", pathRule("PathPrefix", "/w", "wild", nil)),
		"host": route("orders.mactra.test", pathRule("PathPrefix", "/w", "host", nil)),
	}
	tb := tableOf(t, snap(httpGateway(""), routes, fakeBackends(names...)), nil)
	cases := []struct {
		name, method, url string
		hdr               []string
		want              string // winning backend
		reason            string // substring expected in some candidate's reason
	}{
		{"exact beats prefix and regex", "GET", "http://x.test:8080/api/v1/users", nil, "exact", "path type"},
		{"regex beats prefix", "GET", "http://x.test:8080/api/v1/other", nil, "regex", "path type"},
		{"longest prefix", "GET", "http://x.test:8080/api/v1/", nil, "long", "longest path prefix"},
		{"shorter prefix", "GET", "http://x.test:8080/api/v2", nil, "short", "longest path prefix"},
		{"prefix is element wise", "GET", "http://x.test:8080/apix", nil, "root", "is not under the prefix"},
		{"catch all", "GET", "http://x.test:8080/zzz", nil, "root", "is not under the prefix"},
		{"method wins", "POST", "http://x.test:8080/m/x", nil, "method", "method match"},
		{"method miss", "GET", "http://x.test:8080/m/x", nil, "default", "method is GET, the match needs POST"},
		{"one header", "GET", "http://x.test:8080/h", []string{"X-A", "1"}, "hdr1", "header matches"},
		{"header count", "GET", "http://x.test:8080/h", []string{"X-A", "1", "X-B", "bbb"}, "hdr2", "most header matches"},
		{"header value mismatch", "GET", "http://x.test:8080/h", []string{"X-A", "2"}, "default", "header x-a is \"2\""},
		{"header missing", "GET", "http://x.test:8080/h", nil, "default", "header x-a is missing"},
		{"one query", "GET", "http://x.test:8080/q?a=1", nil, "q1", "query parameter b is missing"},
		{"two queries", "GET", "http://x.test:8080/q?a=1&b=7", nil, "q2", "most query parameter matches"},
		{"query regex miss", "GET", "http://x.test:8080/q?a=1&b=x", nil, "q1", "query parameter b is \"x\""},
		{"exact host beats wildcard", "GET", "http://orders.mactra.test:8080/w", nil, "host", "hostname specificity"},
		{"wildcard host", "GET", "http://api.mactra.test:8080/w", nil, "wild", "hostname specificity"},
		{"wildcard needs a label", "GET", "http://mactra.test:8080/w", nil, "root", "host mismatch"},
		{"host case", "GET", "http://ORDERS.Mactra.test:8080/w", nil, "host", "hostname specificity"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := explain(t, tb, c.method, c.url, c.hdr...)
			if got := winnerName(tr); got != c.want {
				t.Fatalf("winner %q, want %q\n%s", got, c.want, dumpTrace(tr))
			}
			if !anyReason(tr, c.reason) {
				t.Fatalf("no candidate reason contains %q\n%s", c.reason, dumpTrace(tr))
			}
			if tr.Verdict != VerdictRouted {
				t.Fatalf("verdict %q", tr.Verdict)
			}
		})
	}
}

func TestExplainNoRoute(t *testing.T) {
	routes := map[string]m{"r": route("only.test", rule("/ok", ref("ok", 1)))}
	tb := tableOf(t, snap(httpGateway(""), routes, fakeBackends("ok")), nil)
	for _, c := range []struct{ url, verdict, reason string }{
		{"http://other.test:8080/ok", VerdictNoListener + VerdictNoRoute, "host mismatch"},
		{"http://only.test:8080/nope", VerdictNoRoute, "is not under the prefix"},
		{"http://only.test:9999/ok", VerdictNoListener, "no serving listener is on port 9999"},
		{"https://only.test:8080/ok", VerdictNoListener, "plain HTTP"},
	} {
		tr := explain(t, tb, "GET", c.url)
		if !strings.Contains(c.verdict, tr.Verdict) || !strings.Contains(tr.Reason+allReasons(tr), c.reason) {
			t.Errorf("%s: verdict %q reason %q\n%s", c.url, tr.Verdict, tr.Reason, dumpTrace(tr))
		}
	}
}

func TestExplainCreationTimeTie(t *testing.T) {
	mk := func() []byte {
		return snap(httpGateway(""), map[string]m{
			"a-new": route("", rule("/", ref("new", 1))),
			"z-old": route("", rule("/", ref("old", 1))),
		}, fakeBackends("new", "old"))
	}
	setTimes := func(newT, oldT time.Time) func(*Config) {
		return func(c *Config) {
			for _, r := range c.Routes {
				if r.Name == "a-new" {
					r.Created = newT
				} else {
					r.Created = oldT
				}
			}
		}
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tr := explain(t, tableOf(t, mk(), setTimes(t0.Add(time.Hour), t0)), "GET", "http://x.test:8080/")
	if winnerName(tr) != "old" || !anyReason(tr, "the oldest route wins") {
		t.Fatalf("older route should win\n%s", dumpTrace(tr))
	}
	tr = explain(t, tableOf(t, mk(), setTimes(t0, t0)), "GET", "http://x.test:8080/")
	if winnerName(tr) != "new" || !anyReason(tr, "name sorts first") {
		t.Fatalf("equal times: name order\n%s", dumpTrace(tr))
	}
}

func TestExplainAllowedRoutesAndGrants(t *testing.T) {
	gw := func(ar m) m {
		lst := m{"name": "web", "protocol": "HTTP", "port": 8080}
		if ar != nil {
			lst["allowedRoutes"] = ar
		}
		return m{"gatewayClassName": "setura", "listeners": l{lst}}
	}
	build := func(gwSpec m) []byte {
		res := m{gwKeyT + "t/gw": gwSpec,
			rtKeyT + "other/r": m{"parentRefs": l{m{"name": "gw", "namespace": "t"}}, "rules": l{rule("/", ref("svc", 1))}},
			rtKeyT + "t/own":   m{"parentRefs": l{m{"name": "gw"}}, "rules": l{rule("/own", ref("svc", 1))}}}
		doc := m{"schema": SnapshotSchema, "namespace": "t", "resources": res,
			"backends":   m{"t/svc:80": "127.0.0.1:9", "other/svc:80": "127.0.0.1:9"},
			"namespaces": m{"other": m{"labels": m{"team": "a"}}}}
		raw, _ := json.Marshal(doc)
		return raw
	}
	cases := []struct {
		name     string
		gw       m
		attached bool
		reason   string
	}{
		{"same namespace default", gw(nil), false, "Same"},
		{"from All", gw(m{"namespaces": m{"from": "All"}}), true, ""},
		{"selector hit", gw(m{"namespaces": m{"from": "Selector", "selector": m{"matchLabels": m{"team": "a"}}}}), true, ""},
		{"selector miss", gw(m{"namespaces": m{"from": "Selector", "selector": m{"matchLabels": m{"team": "b"}}}}), false, "team=b"},
		{"kinds exclude HTTPRoute", gw(m{"namespaces": m{"from": "All"}, "kinds": l{m{"kind": "GRPCRoute"}}}), false, "allowedRoutes.kinds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := explain(t, tableOf(t, build(c.gw), nil), "GET", "http://x.test:8080/")
			found := false
			for _, r := range tr.Routes {
				if r.Route != "other/r" {
					continue
				}
				found = true
				if r.Attached != c.attached || (c.reason != "" && !strings.Contains(r.Reason, c.reason)) {
					t.Fatalf("attached=%v reason=%q", r.Attached, r.Reason)
				}
			}
			if !found {
				t.Fatalf("route other/r not in trace: %s", dumpTrace(tr))
			}
			if !c.attached && tr.Winner != nil && tr.Winner.Route == "other/r" {
				t.Fatalf("rejected route must not win")
			}
		})
	}

	// A cross-namespace backendRef needs a ReferenceGrant.
	cross := func(extra func(m)) *Trace {
		res := m{gwKeyT + "t/gw": gw(nil),
			rtKeyT + "t/r": m{"parentRefs": l{m{"name": "gw"}}, "rules": l{m{"backendRefs": l{m{"name": "svc", "namespace": "other", "port": 80}}}}}}
		doc := m{"schema": SnapshotSchema, "namespace": "t", "resources": res, "backends": m{"other/svc:80": "127.0.0.1:9"}}
		if extra != nil {
			extra(doc)
		}
		raw, _ := json.Marshal(doc)
		return explain(t, tableOf(t, raw, nil), "GET", "http://x.test:8080/")
	}
	tr := cross(nil)
	if tr.Verdict != VerdictNoBackend || tr.Winner.Backends[0].Status != "unresolved" || !strings.Contains(tr.Winner.Backends[0].Reason, "RefNotPermitted") {
		t.Fatalf("missing grant: %s", dumpTrace(tr))
	}
	tr = cross(func(d m) {
		d["referenceGrants"] = l{m{"metadata": m{"namespace": "other"}, "spec": m{
			"from": l{m{"group": APIGroup, "kind": "HTTPRoute", "namespace": "t"}},
			"to":   l{m{"group": "", "kind": "Service"}}}}}
	})
	if tr.Verdict != VerdictRouted || tr.Winner.Backends[0].Status != "ok" {
		t.Fatalf("with grant: %s", dumpTrace(tr))
	}
}

func TestExplainWeightsFiltersAndUpstream(t *testing.T) {
	routes := map[string]m{"r": route("", m{
		"matches": l{m{"path": m{"type": "PathPrefix", "value": "/api"}}},
		"filters": l{
			m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{"set": l{m{"name": "X-Env", "value": "prod"}}, "remove": l{"X-Drop"}}},
			m{"type": "URLRewrite", "urlRewrite": m{"hostname": "internal.svc", "path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2"}}},
		},
		"backendRefs": l{ref("a", 90), ref("b", 10), ref("never", 0)},
	})}
	tb := tableOf(t, snap(httpGateway(""), routes, fakeBackends("a", "b", "never")), nil)
	tr := explain(t, tb, "GET", "http://x.test:8080/api/users?x=1", "X-Drop", "me", "X-Keep", "k")
	w := tr.Winner
	if w == nil || len(w.Backends) != 3 {
		t.Fatalf("%s", dumpTrace(tr))
	}
	if w.Backends[0].Percent != 90 || w.Backends[1].Percent != 10 || w.Backends[2].Status != "excluded" || w.Backends[2].Percent != 0 {
		t.Fatalf("distribution wrong: %+v", w.Backends)
	}
	up := w.Backends[0].Request
	if up.URL != "http://127.0.0.1:9/v2/users?x=1" || up.Host != "internal.svc" || up.Headers["X-Env"] != "prod" || up.Headers["X-Keep"] != "k" || up.Headers["X-Forwarded-Host"] != "x.test:8080" {
		t.Fatalf("upstream %+v", up)
	}
	if _, ok := up.Headers["X-Drop"]; ok {
		t.Fatal("X-Drop should be removed")
	}
	if len(w.Filters) != 2 {
		t.Fatalf("filters %+v", w.Filters)
	}
}

func TestExplainRedirect(t *testing.T) {
	routes := map[string]m{"r": route("", m{
		"matches": l{m{"path": m{"type": "PathPrefix", "value": "/old"}}},
		"filters": l{m{"type": "RequestRedirect", "requestRedirect": m{"hostname": "new.test", "statusCode": 301, "path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/new"}}}},
	})}
	tr := explain(t, tableOf(t, snap(httpGateway(""), routes, nil), nil), "GET", "http://x.test:8080/old/a")
	if tr.Verdict != VerdictRedirect || tr.Winner.Redirect.Status != 301 || tr.Winner.Redirect.Location != "http://new.test:8080/new/a" {
		t.Fatalf("%s", dumpTrace(tr))
	}
}

func TestExplainListenerHostnames(t *testing.T) {
	gw := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "wild", "protocol": "HTTP", "port": 8080, "hostname": "*.example.test"},
		m{"name": "exact", "protocol": "HTTP", "port": 8080, "hostname": "api.example.test"},
	}}
	routes := map[string]m{"r": route("", rule("/", ref("svc", 1)))}
	tb := tableOf(t, snap(gw, routes, fakeBackends("svc")), nil)
	tr := explain(t, tb, "GET", "http://api.example.test:8080/")
	got := map[string]string{}
	for _, li := range tr.Listeners {
		got[li.Listener] = li.Verdict
	}
	if got["t/gw/exact"] != "chosen" || got["t/gw/wild"] != "lost" {
		t.Fatalf("%v\n%s", got, dumpTrace(tr))
	}
	tr = explain(t, tb, "GET", "http://other.example.test:8080/")
	if got := tr.Listeners[0].Verdict; got != "chosen" {
		t.Fatalf("wildcard listener should be chosen: %s", dumpTrace(tr))
	}
	tr = explain(t, tb, "GET", "http://nope.test:8080/")
	if tr.Verdict != VerdictNoListener {
		t.Fatalf("%s", dumpTrace(tr))
	}
}

func TestExplainGRPCAndSNI(t *testing.T) {
	gw := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080},
		m{"name": "pass", "protocol": "TLS", "port": 8443, "tls": m{"mode": "Passthrough"}},
	}}
	res := m{gwKeyT + "t/gw": gw,
		rtKeyT + "t/web": m{"parentRefs": l{m{"name": "gw", "sectionName": "web"}}, "rules": l{rule("/", ref("http", 1))}},
		grpcKeyT + "t/g": m{"parentRefs": l{m{"name": "gw", "sectionName": "web"}}, "rules": l{
			m{"matches": l{m{"method": m{"service": "hello.Greeter", "method": "SayHello"}}}, "backendRefs": l{ref("greeter", 1)}},
			m{"matches": l{m{"method": m{"service": "hello.Greeter"}}}, "backendRefs": l{ref("greeter-any", 1)}},
		}},
		tlsKeyT + "t/s": m{"parentRefs": l{m{"name": "gw", "sectionName": "pass"}}, "hostnames": l{"*.secure.test"}, "rules": l{m{"backendRefs": l{ref("tls-wild", 1)}}}},
		tlsKeyT + "t/e": m{"parentRefs": l{m{"name": "gw", "sectionName": "pass"}}, "hostnames": l{"db.secure.test"}, "rules": l{m{"backendRefs": l{ref("tls-exact", 1)}}}},
	}
	raw, _ := json.Marshal(m{"schema": SnapshotSchema, "namespace": "t", "resources": res,
		"backends": m{"t/http:80": "127.0.0.1:9", "t/greeter:80": "127.0.0.1:9", "t/greeter-any:80": "127.0.0.1:9", "t/tls-wild:80": "127.0.0.1:9", "t/tls-exact:80": "127.0.0.1:9"}})
	tb := tableOf(t, raw, nil)

	grpcReq := func(svcMethod string) *Trace {
		req, err := ParseExplainRequest("", "http://x.test:8080", nil, svcMethod, "")
		if err != nil {
			t.Fatal(err)
		}
		return Explain(tb, req)
	}
	if tr := grpcReq("hello.Greeter/SayHello"); winnerName(tr) != "greeter" || tr.Winner.Kind != "GRPCRoute" {
		t.Fatalf("%s", dumpTrace(tr))
	}
	if tr := grpcReq("hello.Greeter/Other"); winnerName(tr) != "greeter-any" {
		t.Fatalf("%s", dumpTrace(tr))
	}
	if tr := grpcReq("other.Svc/X"); tr.Verdict != VerdictNoRoute {
		t.Fatalf("%s", dumpTrace(tr))
	}
	// A plain HTTP request never matches GRPCRoute rules.
	if tr := explain(t, tb, "POST", "http://x.test:8080/hello.Greeter/SayHello"); winnerName(tr) != "http" || !anyReason(tr, "GRPCRoute") {
		t.Fatalf("%s", dumpTrace(tr))
	}

	sni := func(name string) *Trace {
		req, err := ParseExplainRequest("", "tls://"+name+":8443", nil, "", name)
		if err != nil {
			t.Fatal(err)
		}
		return Explain(tb, req)
	}
	if tr := sni("db.secure.test"); winnerName(tr) != "tls-exact" || tr.Winner.Kind != "TLSRoute" {
		t.Fatalf("%s", dumpTrace(tr))
	}
	if tr := sni("web.secure.test"); winnerName(tr) != "tls-wild" {
		t.Fatalf("%s", dumpTrace(tr))
	}
	if tr := sni("nope.example"); tr.Verdict != VerdictNoRoute {
		t.Fatalf("%s", dumpTrace(tr))
	}
}

func TestExplainLiveHealth(t *testing.T) {
	routes := map[string]m{"r": route("", rule("/", ref("a", 50), ref("b", 50)))}
	be, _ := upstreams(t, "a", "b")
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	tb := s.Table()
	tb.Backends[backendKey("t", "b", 80)].Eps[0].healthy.Store(false)
	req, _ := ParseExplainRequest("GET", "http://x.test:8080/", nil, "", "")
	req.Live = true
	tr := Explain(tb, req)
	b := tr.Winner.Backends
	if b[0].Percent != 100 || b[1].Status != "excluded" || b[1].Endpoints[0].State != "unhealthy" {
		t.Fatalf("%s", dumpTrace(tr))
	}
	req.Live = false
	tr = Explain(tb, req)
	if tr.Winner.Backends[0].Percent != 50 || tr.Winner.Backends[1].Endpoints[0].State != "unknown" {
		t.Fatalf("static config must not claim health: %s", dumpTrace(tr))
	}
}

func TestAdminWhyEndpoint(t *testing.T) {
	be, _ := upstreams(t, "a")
	routes := map[string]m{"r": route("", rule("/", ref("a", 1)))}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	s.opts.Admin = "127.0.0.1:0"
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + s.AdminAddr() + "/why?method=GET&url=http%3A%2F%2Fx.test%3A8080%2Fapi&header=X-A%3A%201")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tr Trace
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil || resp.StatusCode != 200 {
		t.Fatalf("%d %v", resp.StatusCode, err)
	}
	if tr.Verdict != VerdictRouted || tr.Winner.Backends[0].Name != "a" || tr.Winner.Backends[0].Endpoints[0].State != "up" {
		t.Fatalf("%s", dumpTrace(&tr))
	}
	bad, _ := http.Get("http://" + s.AdminAddr() + "/why?url=ftp%3A%2F%2Fx")
	defer bad.Body.Close()
	if bad.StatusCode != 400 {
		t.Fatalf("bad request status %d", bad.StatusCode)
	}
	if s.Stats().Snapshot()["requests"].(int64) != 0 {
		t.Fatal("/why must not send traffic")
	}
}

// TestExplainMatchesLiveProxy proves there is one implementation: for random
// requests Explain's winner is exactly the rule the running proxy serves.
func TestExplainMatchesLiveProxy(t *testing.T) {
	names := []string{"root", "api", "apiv1", "users", "re", "post", "h1", "h2", "q1", "q2", "wild", "orders", "tie-a", "tie-b"}
	be, _ := upstreams(t, names...)
	pr := func(typ, val, backend string, extra m) m {
		match := m{"path": m{"type": typ, "value": val}}
		for k, v := range extra {
			match[k] = v
		}
		return m{"matches": l{match}, "backendRefs": l{ref(backend, 1)}}
	}
	hdr := func(n, v string) m { return m{"name": n, "value": v} }
	routes := map[string]m{
		"main": route("*.test",
			pr("PathPrefix", "/", "root", nil),
			pr("PathPrefix", "/api", "api", nil),
			pr("PathPrefix", "/api/v1", "apiv1", nil),
			pr("Exact", "/api/v1/users", "users", nil),
			pr("RegularExpression", "/api/v1/[a-z]+/[0-9]+", "re", nil),
			pr("PathPrefix", "/p", "post", m{"method": "POST"}),
			pr("PathPrefix", "/h", "h1", m{"headers": l{hdr("X-A", "1")}}),
			pr("PathPrefix", "/h", "h2", m{"headers": l{hdr("X-A", "1"), m{"name": "X-B", "type": "RegularExpression", "value": "b+"}}}),
			pr("PathPrefix", "/q", "q1", m{"queryParams": l{hdr("a", "1")}}),
			pr("PathPrefix", "/q", "q2", m{"queryParams": l{hdr("a", "1"), m{"name": "b", "type": "RegularExpression", "value": "[0-9]"}}}),
		),
		"wild":   route("*.shop.test", pr("PathPrefix", "/", "wild", nil)),
		"orders": route("orders.shop.test", pr("PathPrefix", "/o", "orders", nil)),
		"tie-a":  route("tie.test", pr("PathPrefix", "/t", "tie-a", nil)),
		"tie-b":  route("tie.test", pr("PathPrefix", "/t", "tie-b", nil)),
		"gone": route("gone.test", m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/g"}}},
			"filters": l{m{"type": "RequestRedirect", "requestRedirect": m{"statusCode": 301}}}}),
	}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	rng := rand.New(rand.NewPCG(7, 11))
	pick := func(xs ...string) string { return xs[rng.IntN(len(xs))] }
	hosts := []string{"x.test", "api.shop.test", "orders.shop.test", "shop.test", "tie.test", "gone.test", "ORDERS.shop.test", "nomatch.example"}
	paths := []string{"/", "/api", "/api/", "/apix", "/api/v1", "/api/v1/users", "/api/v1/users/9", "/api/v1/abc/42", "/p", "/p/x", "/h", "/h/z", "/q", "/o", "/o/1", "/t", "/g", "/zzz"}
	c := client(s.Addr(8080), nil)
	routed, noRoute := 0, 0
	for i := 0; i < 220; i++ {
		method := pick("GET", "GET", "POST", "PUT")
		host, path := pick(hosts...), pick(paths...)
		var hs []string
		if rng.IntN(2) == 0 {
			hs = append(hs, "X-A", pick("1", "2"))
		}
		if rng.IntN(3) == 0 {
			hs = append(hs, "X-B", pick("b", "bbb", "c"))
		}
		target := path
		switch rng.IntN(3) {
		case 0:
			target += "?a=" + pick("1", "2") + "&b=" + pick("1", "x")
		case 1:
			target += "?a=1"
		}
		live := req(t, c, "http", method, host+":8080", target, "", hs...)

		var xh []string
		for j := 0; j+1 < len(hs); j += 2 {
			xh = append(xh, hs[j]+": "+hs[j+1])
		}
		er, err := ParseExplainRequest(method, "http://"+host+":8080"+target, xh, "", "")
		if err != nil {
			t.Fatal(err)
		}
		tr := Explain(s.Table(), er)
		desc := fmt.Sprintf("%s %s%s hdr=%v", method, host, target, hs)
		switch tr.Verdict {
		case VerdictNoRoute, VerdictNoListener:
			noRoute++
			if live.Status != 404 {
				t.Fatalf("%s: explain says no route, live answered %d (%s)", desc, live.Status, live.Echo.Name)
			}
		case VerdictRedirect:
			routed++
			if live.Status != 301 {
				t.Fatalf("%s: explain says redirect, live answered %d", desc, live.Status)
			}
			if loc := live.Header.Get("Location"); loc != tr.Winner.Redirect.Location {
				t.Fatalf("%s: Location live %q explain %q", desc, loc, tr.Winner.Redirect.Location)
			}
		default:
			routed++
			if got := live.Header.Get(BackendHeader); got != tr.Winner.Backends[0].Name || live.Status != 200 {
				t.Fatalf("%s: live %q (%d), explain %q\n%s", desc, got, live.Status, tr.Winner.Backends[0].Name, dumpTrace(tr))
			}
			if !strings.HasSuffix(strings.SplitN(tr.Winner.Backends[0].Request.URL, "?", 2)[0], live.Echo.Path) {
				t.Fatalf("%s: upstream path live %q explain %q", desc, live.Echo.Path, tr.Winner.Backends[0].Request.URL)
			}
		}
	}
	if routed < 60 || noRoute < 5 {
		t.Fatalf("random requests should exercise both outcomes, routed=%d noRoute=%d", routed, noRoute)
	}
}

// TestTracerOffTheHotPath asserts the data-path selection allocates nothing
// extra when no trace is attached.
func TestTracerOffTheHotPath(t *testing.T) {
	be, _ := upstreams(t, "a")
	routes := map[string]m{"r": route("", rule("/", ref("a", 1)), rule("/x", ref("a", 1)))}
	tb := tableOf(t, snap(httpGateway(""), routes, be), nil)
	r := httptest.NewRequest("GET", "http://x.test/x", nil)
	pg := tb.Ports[8080]
	allocs := testing.AllocsPerRun(100, func() {
		l := pg.pickListener("x.test")
		if l.selectEntry(r, "x.test") == nil {
			t.Fatal("no entry")
		}
	})
	if allocs != 0 {
		t.Fatalf("data-path selection allocates %v times", allocs)
	}
}
