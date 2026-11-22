package gateway

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMatchingPrecedence(t *testing.T) {
	be, _ := upstreams(t, "exact", "long", "short", "root", "method", "hdr2", "hdr1", "q2", "q1", "regex", "wild", "host", "default")
	pathRule := func(typ, val, backend string, extra m) m {
		match := m{"path": m{"type": typ, "value": val}}
		for k, v := range extra {
			match[k] = v
		}
		return m{"matches": l{match}, "backendRefs": l{ref(backend, 1)}}
	}
	routes := map[string]m{
		"a": route("",
			pathRule("PathPrefix", "/", "root", nil),
			pathRule("PathPrefix", "/api", "short", nil),
			pathRule("PathPrefix", "/api/v1", "long", nil),
			pathRule("Exact", "/api/v1/users", "exact", nil),
			pathRule("RegularExpression", "/re/[0-9]+", "regex", nil),
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
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	cases := []struct {
		name, method, host, target string
		hdr                        []string
		want                       string
		status                     int
	}{
		{"exact beats prefix", "GET", "x.test", "/api/v1/users", nil, "exact", 200},
		{"longest prefix", "GET", "x.test", "/api/v1/other", nil, "long", 200},
		{"shorter prefix", "GET", "x.test", "/api/v2", nil, "short", 200},
		{"prefix is element wise", "GET", "x.test", "/apix", nil, "root", 200},
		{"prefix trailing slash", "GET", "x.test", "/api/", nil, "short", 200},
		{"catch all", "GET", "x.test", "/zzz", nil, "root", 200},
		{"regex", "GET", "x.test", "/re/42", nil, "regex", 200},
		{"regex is anchored", "GET", "x.test", "/re/42x", nil, "root", 200},
		{"method wins at equal path", "POST", "x.test", "/m/x", nil, "method", 200},
		{"method miss falls back", "GET", "x.test", "/m/x", nil, "default", 200},
		{"one header", "GET", "x.test", "/h", []string{"X-A", "1"}, "hdr1", 200},
		{"two headers win", "GET", "x.test", "/h", []string{"X-A", "1", "X-B", "bbb"}, "hdr2", 200},
		{"header mismatch", "GET", "x.test", "/h", []string{"X-A", "2"}, "default", 200},
		{"one query", "GET", "x.test", "/q?a=1", nil, "q1", 200},
		{"two queries win", "GET", "x.test", "/q?a=1&b=7", nil, "q2", 200},
		{"query regex miss", "GET", "x.test", "/q?a=1&b=x", nil, "q1", 200},
		{"exact host beats wildcard", "GET", "orders.mactra.test", "/w", nil, "host", 200},
		{"wildcard host", "GET", "api.mactra.test", "/w", nil, "wild", 200},
		{"wildcard needs a label", "GET", "mactra.test", "/w", nil, "root", 200},
		{"host with port", "GET", "orders.mactra.test:8080", "/w", nil, "host", 200},
		{"host case", "GET", "ORDERS.Mactra.test", "/w", nil, "host", 200},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := req(t, client(s.Addr(8080), nil), "http", c.method, c.host, c.target, "", c.hdr...)
			if r.Status != c.status || r.Echo.Name != c.want {
				t.Fatalf("status %d backend %q, want %d %q (%s)", r.Status, r.Echo.Name, c.status, c.want, r.Body)
			}
			if got := r.Header.Get(BackendHeader); got != c.want {
				t.Fatalf("%s = %q, want %q (upstream value must be replaced)", BackendHeader, got, c.want)
			}
		})
	}
}

func TestNoMatchAndNoBackends(t *testing.T) {
	be, _ := upstreams(t, "ok")
	routes := map[string]m{"r": route("only.test",
		rule("/ok", ref("ok", 1)),
		rule("/zero", ref("ok", 0)),
		rule("/missing", ref("ghost", 1)),
		m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/empty"}}}},
	)}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	for _, c := range []struct {
		host, path string
		want       int
	}{
		{"only.test", "/ok", 200},
		{"other.test", "/ok", 404},
		{"only.test", "/nothing", 404},
		{"only.test", "/zero", 500},
		{"only.test", "/missing", 500},
		{"only.test", "/empty", 500},
	} {
		if r := get(t, s, c.host, c.path); r.Status != c.want {
			t.Errorf("%s%s = %d, want %d", c.host, c.path, r.Status, c.want)
		}
	}
}

func TestWeights(t *testing.T) {
	be, _ := upstreams(t, "a", "b", "never")
	routes := map[string]m{"r": route("", rule("/", ref("a", 90), ref("b", 10), ref("never", 0)))}
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.Rand = seededRand(42) })
	counts := map[string]int{}
	const n = 2000
	for i := 0; i < n; i++ {
		counts[get(t, s, "x.test", "/").Echo.Name]++
	}
	if counts["never"] != 0 {
		t.Fatalf("weight 0 backend served %d requests", counts["never"])
	}
	// 90/10 over 2000 draws: sigma(b) is about 13, so +-5 sigma is [135, 265].
	if b := counts["b"]; b < 135 || b > 265 || counts["a"]+b != n {
		t.Fatalf("distribution %v outside bounds", counts)
	}
	// Fixed seed means a repeatable outcome.
	s2 := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.Rand = seededRand(42) })
	again := 0
	for i := 0; i < n; i++ {
		if get(t, s2, "x.test", "/").Echo.Name == "b" {
			again++
		}
	}
	if again != counts["b"] {
		t.Fatalf("seeded runs differ: %d vs %d", again, counts["b"])
	}
}

func TestDefaultWeightIsOne(t *testing.T) {
	be, _ := upstreams(t, "a", "b")
	routes := map[string]m{"r": route("", rule("/", ref("a", -1), ref("b", -1)))}
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.Rand = seededRand(7) })
	counts := map[string]int{}
	for i := 0; i < 400; i++ {
		counts[get(t, s, "x.test", "/").Echo.Name]++
	}
	if counts["a"] < 140 || counts["b"] < 140 {
		t.Fatalf("expected an even split, got %v", counts)
	}
}

func TestRoundRobinEndpoints(t *testing.T) {
	_, ups := upstreams(t, "e1", "e2", "e3")
	be := map[string]any{"svc": m{"endpoints": l{ups["e1"].addr(), ups["e2"].addr(), ups["e3"].addr()}}}
	routes := map[string]m{"r": route("", rule("/", ref("svc", 1)))}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	for i := 0; i < 9; i++ {
		get(t, s, "x.test", "/")
	}
	for n, u := range ups {
		if got := len(u.seen()); got != 3 {
			t.Errorf("%s served %d, want 3", n, got)
		}
	}
}

func TestFilters(t *testing.T) {
	be, ups := upstreams(t, "app", "mirror")
	reqMod := m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{
		"set": l{m{"name": "X-Set", "value": "new"}}, "add": l{m{"name": "X-Add", "value": "two"}}, "remove": l{"X-Drop"}}}
	respMod := m{"type": "ResponseHeaderModifier", "responseHeaderModifier": m{
		"set": l{m{"name": "X-Resp-Set", "value": "gateway"}}, "add": l{m{"name": "X-Resp-Add", "value": "yes"}}, "remove": l{"X-Upstream"}}}
	rewritePrefix := m{"type": "URLRewrite", "urlRewrite": m{"hostname": "internal.svc", "path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2"}}}
	rewriteFull := m{"type": "URLRewrite", "urlRewrite": m{"path": m{"type": "ReplaceFullPath", "replaceFullPath": "/fixed"}}}
	rewriteRoot := m{"type": "URLRewrite", "urlRewrite": m{"path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}}}
	mirror := m{"type": "RequestMirror", "requestMirror": m{"backendRef": ref("mirror", -1)}}
	withFilters := func(path string, fs ...m) m {
		r := rule(path, ref("app", 1))
		r["filters"] = toList(fs)
		return r
	}
	routes := map[string]m{"r": route("", withFilters("/hdr", reqMod, respMod), withFilters("/pre", rewritePrefix), withFilters("/full", rewriteFull),
		withFilters("/strip", rewriteRoot), withFilters("/mir", mirror))}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)

	r := get(t, s, "x.test", "/hdr/p", "X-Set", "old", "X-Add", "one", "X-Drop", "bye")
	for k, want := range map[string]string{"x-set": "new", "x-add": "one,two"} {
		if r.Echo.Headers[k] != want {
			t.Errorf("request header %s = %q, want %q", k, r.Echo.Headers[k], want)
		}
	}
	if _, ok := r.Echo.Headers["x-drop"]; ok {
		t.Error("X-Drop was not removed")
	}
	if r.Header.Get("X-Resp-Set") != "gateway" || r.Header.Get("X-Resp-Add") != "yes" || r.Header.Get("X-Upstream") != "" {
		t.Errorf("response headers wrong: %v", r.Header)
	}
	if r.Echo.Headers["x-forwarded-host"] != "x.test" {
		t.Errorf("x-forwarded-host = %q", r.Echo.Headers["x-forwarded-host"])
	}
	if r.Echo.Host != "x.test" {
		t.Errorf("upstream Host = %q, want the original", r.Echo.Host)
	}

	for _, c := range []struct{ target, path, query, host string }{
		{"/pre/a/b?k=v", "/v2/a/b", "k=v", "internal.svc"},
		{"/pre", "/v2", "", "internal.svc"},
		{"/full/anything?z=1", "/fixed", "z=1", "x.test"},
		{"/strip/a", "/a", "", "x.test"},
		{"/strip", "/", "", "x.test"},
	} {
		r := get(t, s, "x.test", c.target)
		if r.Echo.Path != c.path || r.Echo.Query != c.query || r.Echo.Host != c.host {
			t.Errorf("%s -> path %q query %q host %q, want %q %q %q", c.target, r.Echo.Path, r.Echo.Query, r.Echo.Host, c.path, c.query, c.host)
		}
	}

	r = req(t, client(s.Addr(8080), nil), "http", "POST", "x.test", "/mir/x?m=1", "payload")
	if r.Echo.Name != "app" || r.Echo.Body != "payload" {
		t.Fatalf("primary response wrong: %+v", r.Echo)
	}
	s.mirrorWG.Wait()
	got := ups["mirror"].seen()
	if len(got) != 1 || got[0].Body != "payload" || got[0].Path != "/mir/x" || got[0].Query != "m=1" || got[0].Headers["x-setura-mirror"] != "1" {
		t.Fatalf("mirror saw %+v", got)
	}
}

func TestMirrorPercentAndFailureIsInvisible(t *testing.T) {
	be, ups := upstreams(t, "app", "mirror")
	be["dead"] = "127.0.0.1:1"
	mir := func(name string, pct int) m {
		return m{"type": "RequestMirror", "requestMirror": m{"backendRef": ref(name, -1), "percent": pct}}
	}
	r := rule("/", ref("app", 1))
	r["filters"] = l{mir("mirror", 25), mir("dead", 100)}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", r)}, be), func(o *Options) { o.Rand = seededRand(3) })
	for i := 0; i < 400; i++ {
		if get(t, s, "x.test", "/").Status != 200 {
			t.Fatal("a dead mirror must not affect the client")
		}
	}
	s.mirrorWG.Wait()
	if n := len(ups["mirror"].seen()); n < 60 || n > 140 {
		t.Fatalf("25%% mirror of 400 requests saw %d", n)
	}
}

func TestRedirects(t *testing.T) {
	redirect := func(rd m) m { return m{"filters": l{m{"type": "RequestRedirect", "requestRedirect": rd}}} }
	withMatch := func(path string, r m) m {
		r["matches"] = l{m{"path": m{"type": "PathPrefix", "value": path}}}
		return r
	}
	routes := map[string]m{"r": route("old.test",
		withMatch("/scheme", redirect(m{"scheme": "https", "statusCode": 301})),
		withMatch("/host", redirect(m{"hostname": "new.test"})),
		withMatch("/port", redirect(m{"port": 9443, "scheme": "https"})),
		withMatch("/full", redirect(m{"path": m{"type": "ReplaceFullPath", "replaceFullPath": "/landing"}, "statusCode": 308})),
		withMatch("/prefix", redirect(m{"path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/next"}})),
	)}
	s := startServer(t, snap(httpGateway(""), routes, nil), nil)
	for _, c := range []struct {
		target string
		code   int
		loc    string
	}{
		{"/scheme/a?x=1", 301, "https://old.test/scheme/a?x=1"},
		{"/host/a", 302, "http://new.test:8080/host/a"},
		{"/port", 302, "https://old.test:9443/port"},
		{"/full/q?a=b", 308, "http://old.test:8080/landing?a=b"},
		{"/prefix/deep", 302, "http://old.test:8080/next/deep"},
	} {
		r := req(t, client(s.Addr(8080), nil), "http", "GET", "old.test:8080", c.target, "")
		if r.Status != c.code || r.Header.Get("Location") != c.loc {
			t.Errorf("%s -> %d %q, want %d %q", c.target, r.Status, r.Header.Get("Location"), c.code, c.loc)
		}
	}
}

func TestTimeoutsAndUpstreamErrors(t *testing.T) {
	be, _ := upstreams(t, "slow")
	be["dead"] = "127.0.0.1:1"
	timed := rule("/slow", ref("slow", 1))
	timed["timeouts"] = m{"request": "50ms"}
	routes := map[string]m{"r": route("", timed, rule("/ok", ref("slow", 1)), rule("/dead", ref("dead", 1)))}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	if r := get(t, s, "x.test", "/slow"); r.Status != 504 {
		t.Errorf("slow = %d, want 504", r.Status)
	}
	if r := get(t, s, "x.test", "/ok/slow"); r.Status != 200 {
		t.Errorf("untimed slow = %d, want 200", r.Status)
	}
	if r := get(t, s, "x.test", "/dead"); r.Status != 502 || r.Header.Get(BackendHeader) != "dead" {
		t.Errorf("dead = %d %q, want 502 with backend header", r.Status, r.Header.Get(BackendHeader))
	}
}

func TestHealthChecksSkipBadEndpoints(t *testing.T) {
	_, ups := upstreams(t, "good")
	bad := newUpstream(t, "bad")
	bad.Close() // connection refused
	be := map[string]any{"svc": m{"endpoints": l{bad.addr(), ups["good"].addr()}, "healthCheck": m{"path": "/health", "interval": "20ms"}}}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, be), nil)
	deadline := time.Now().Add(3 * time.Second)
	for {
		ok := true
		for i := 0; i < 10; i++ {
			ok = ok && get(t, s, "x.test", "/").Status == 200
		}
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("unhealthy endpoint was never ejected")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestListenerHostnameIntersection(t *testing.T) {
	be, _ := upstreams(t, "ok")
	routes := map[string]m{
		"in":  route("a.mactra.test", rule("/", ref("ok", 1))),
		"out": route("other.example", rule("/out", ref("ok", 1))),
		"any": route("", rule("/any", ref("ok", 1))),
	}
	s := startServer(t, snap(httpGateway("*.mactra.test"), routes, be), nil)
	for _, c := range []struct {
		host, path string
		want       int
	}{
		{"a.mactra.test", "/", 200},
		{"b.mactra.test", "/", 404},    // route host a.mactra.test only
		{"b.mactra.test", "/any", 200}, // route without hostnames inherits the listener's
		{"other.example", "/out", 404}, // listener does not serve this host
	} {
		if r := get(t, s, c.host, c.path); r.Status != c.want {
			t.Errorf("%s%s = %d, want %d", c.host, c.path, r.Status, c.want)
		}
	}
	st := s.Status().Routes["t/out"].Parents[0]
	if st.Conditions[0].Status != "False" || st.Conditions[0].Reason != "NoMatchingListenerHostname" {
		t.Errorf("out route status: %+v", st.Conditions)
	}
}

func TestIntersect(t *testing.T) {
	for _, c := range []struct {
		r, l, want string
		ok         bool
	}{
		{"a.x.io", "", "a.x.io", true}, {"", "a.x.io", "a.x.io", true}, {"a.x.io", "a.x.io", "a.x.io", true},
		{"*.x.io", "a.x.io", "a.x.io", true}, {"a.x.io", "*.x.io", "a.x.io", true}, {"a.b.x.io", "*.x.io", "a.b.x.io", true},
		{"*.b.x.io", "*.x.io", "*.b.x.io", true}, {"*.x.io", "*.b.x.io", "*.b.x.io", true},
		{"x.io", "*.x.io", "", false}, {"a.y.io", "*.x.io", "", false}, {"*.y.io", "*.x.io", "", false},
	} {
		got, ok := intersect(c.r, c.l)
		if got != c.want || ok != c.ok {
			t.Errorf("intersect(%q,%q) = %q,%v want %q,%v", c.r, c.l, got, ok, c.want, c.ok)
		}
	}
}

func TestAllowedRoutes(t *testing.T) {
	be, _ := upstreams(t, "ok")
	gw := func(ar m) m {
		g := httpGateway("")
		g["listeners"].([]any)[0].(m)["allowedRoutes"] = ar
		return g
	}
	// Build cross-namespace configs directly: route lives in namespace "apps".
	build := func(ar m) *Server {
		res := m{gwKeyT + "gw": gw(ar), rtKeyT + "apps/r": m{"parentRefs": l{m{"name": "gw", "namespace": "t"}}, "rules": l{rule("/", ref("ok", 1))}}}
		raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t", "resources": res,
			"backends": m{"apps/ok:80": be["ok"]}, "namespaces": m{"apps": m{"labels": m{"team": "a"}}}})
		return startServer(t, raw, nil)
	}
	for _, c := range []struct {
		name string
		ar   m
		want int
	}{
		{"default is Same", nil, 404},
		{"Same", m{"namespaces": m{"from": "Same"}}, 404},
		{"All", m{"namespaces": m{"from": "All"}}, 200},
		{"Selector match", m{"namespaces": m{"from": "Selector", "selector": m{"matchLabels": m{"team": "a"}}}}, 200},
		{"Selector miss", m{"namespaces": m{"from": "Selector", "selector": m{"matchLabels": m{"team": "b"}}}}, 404},
		{"Kinds excludes HTTPRoute", m{"namespaces": m{"from": "All"}, "kinds": l{m{"kind": "GRPCRoute"}}}, 404},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := build(c.ar)
			if r := get(t, s, "x.test", "/"); r.Status != c.want {
				t.Fatalf("status %d, want %d", r.Status, c.want)
			}
			reason := s.Status().Routes["apps/r"].Parents[0].Conditions[0].Reason
			if c.want == 404 && reason != "NotAllowedByListeners" {
				t.Fatalf("reason %q", reason)
			}
		})
	}
}

func TestStatsAndAccessLog(t *testing.T) {
	be, _ := upstreams(t, "a")
	var buf syncBuf
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/ok", ref("a", 1)))}, be), func(o *Options) { o.AccessLog = &buf })
	get(t, s, "x.test", "/ok")
	get(t, s, "x.test", "/ok")
	get(t, s, "x.test", "/nope")
	s.FlushAccessLog()
	st := s.Stats().Snapshot()
	if st["requests"].(int64) != 3 || st["unmatched"].(int64) != 1 {
		t.Fatalf("stats %v", st)
	}
	rc := st["routes"].(map[string]Counter)["t/r"]
	if rc.Requests != 2 || rc.Status["2xx"] != 2 {
		t.Fatalf("route counter %+v", rc)
	}
	if bc := st["backends"].(map[string]Counter)["t/a:80"]; bc.Requests != 2 {
		t.Fatalf("backend counter %+v", bc)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"route":"t/r"`) || !strings.Contains(lines[0], `"backend":"t/a:80"`) || !strings.Contains(lines[2], `"status":404`) {
		t.Fatalf("access log:\n%s", strings.Join(lines, "\n"))
	}
	for _, ln := range lines {
		var v map[string]any
		if err := jsonUnmarshal(ln, &v); err != nil {
			t.Fatalf("log line is not JSON: %q", ln)
		}
	}
}

func TestUpgradePassesThrough(t *testing.T) {
	// A raw Upgrade handshake must reach the backend and relay both ways.
	up := httpTestUpgrade(t)
	be := map[string]any{"ws": up}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("ws", 1)))}, be), nil)
	conn, err := dialRaw(s.Addr(8080))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: x.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	br := bufioReader(conn)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "101") {
		t.Fatalf("handshake: %q", line)
	}
	for {
		l, _ := br.ReadString('\n')
		if l == "\r\n" || l == "" {
			break
		}
	}
	fmt.Fprint(conn, "ping\n")
	got, _ := br.ReadString('\n')
	if got != "ping\n" {
		t.Fatalf("echo %q", got)
	}
}

var _ = http.StatusOK
