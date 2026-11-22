package gateway

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"
)

// probe is one request and the outcome the Gateway API conformance suite
// expects for it. want is a backend name, or "" when only status matters.
type probe struct {
	method, host, target string
	hdr                  []string
	status               int
	backend, location    string
}

func p(target string, status int, backend string) probe {
	return probe{method: "GET", host: "conf.test", target: target, status: status, backend: backend}
}

func filtered(r m, fs ...m) m { r["filters"] = toList(fs); return r }

func match(r m, ms ...m) m { r["matches"] = toList(ms); return r }

// TestConformanceMatrix mirrors, by name, the HTTPRoute conformance tests the
// built-in gateway claims to pass. It is a self-check, not a certification.
func TestConformanceMatrix(t *testing.T) {
	pathPrefix := func(v string) m { return m{"path": m{"type": "PathPrefix", "value": v}} }
	rows := []struct {
		name, level string
		rules       []m
		probes      []probe
	}{
		{"HTTPRouteSimpleSameNamespace", "Core",
			[]m{rule("/", ref("a", 1))}, []probe{p("/", 200, "a"), p("/anything/at/all", 200, "a")}},
		{"HTTPRouteExactPathMatching", "Core",
			[]m{match(rule("", ref("a", 1)), m{"path": m{"type": "Exact", "value": "/one"}}), match(rule("", ref("b", 1)), m{"path": m{"type": "Exact", "value": "/two"}})},
			[]probe{p("/one", 200, "a"), p("/two", 200, "b"), p("/one/", 404, ""), p("/one/x", 404, ""), p("/three", 404, "")}},
		{"HTTPRoutePathMatchOrder", "Core",
			[]m{match(rule("", ref("a", 1)), pathPrefix("/match")), match(rule("", ref("b", 1)), pathPrefix("/match/exact")),
				match(rule("", ref("c", 1)), m{"path": m{"type": "Exact", "value": "/match/exact/two"}})},
			[]probe{p("/match", 200, "a"), p("/match/other", 200, "a"), p("/match/exact", 200, "b"), p("/match/exact/x", 200, "b"), p("/match/exact/two", 200, "c"), p("/matchx", 404, "")}},
		{"HTTPRouteHeaderMatching", "Core",
			[]m{
				match(rule("", ref("a", 1)), m{"headers": l{m{"name": "Version", "value": "one"}}}),
				match(rule("", ref("b", 1)), m{"headers": l{m{"name": "Version", "value": "two"}}}),
				match(rule("", ref("c", 1)), m{"headers": l{m{"name": "Color", "value": "orange"}, m{"name": "Size", "value": "big"}}}),
				match(rule("", ref("c", 1)), m{"headers": l{m{"name": "Color", "type": "RegularExpression", "value": "or.*"}}}),
			},
			[]probe{{method: "GET", host: "conf.test", target: "/", hdr: []string{"version", "one"}, status: 200, backend: "a"},
				{method: "GET", host: "conf.test", target: "/", hdr: []string{"Version", "two"}, status: 200, backend: "b"},
				{method: "GET", host: "conf.test", target: "/", hdr: []string{"Color", "orange", "Size", "big"}, status: 200, backend: "c"},
				{method: "GET", host: "conf.test", target: "/", hdr: []string{"Color", "orange"}, status: 200, backend: "c"},
				{method: "GET", host: "conf.test", target: "/", hdr: []string{"Version", "three"}, status: 404},
				{method: "GET", host: "conf.test", target: "/", status: 404}}},
		{"HTTPRouteQueryParamMatching", "Extended",
			[]m{match(rule("", ref("a", 1)), m{"queryParams": l{m{"name": "animal", "value": "dolphin"}}}),
				match(rule("", ref("b", 1)), m{"queryParams": l{m{"name": "animal", "value": "whale"}}}),
				match(rule("", ref("c", 1)), m{"queryParams": l{m{"name": "color", "value": "blue"}, m{"name": "size", "value": "large"}}})},
			[]probe{p("/?animal=dolphin", 200, "a"), p("/?animal=whale", 200, "b"), p("/?color=blue&size=large", 200, "c"),
				p("/?color=blue", 404, ""), p("/?animal=shark", 404, "")}},
		{"HTTPRouteMethodMatching", "Extended",
			[]m{match(rule("", ref("a", 1)), m{"method": "POST"}), match(rule("", ref("b", 1)), m{"method": "GET"})},
			[]probe{{method: "POST", host: "conf.test", target: "/", status: 200, backend: "a"}, p("/", 200, "b"), {method: "DELETE", host: "conf.test", target: "/", status: 404}}},
		{"HTTPRouteMatchingAcrossRoutes (method over header over query)", "Core",
			[]m{match(rule("", ref("a", 1)), pathPrefix("/x")),
				match(rule("", ref("b", 1)), m{"path": m{"type": "PathPrefix", "value": "/x"}, "method": "POST"}),
				match(rule("", ref("c", 1)), m{"path": m{"type": "PathPrefix", "value": "/x"}, "headers": l{m{"name": "H", "value": "1"}}}),
				match(rule("", ref("a", 1)), m{"path": m{"type": "PathPrefix", "value": "/x"}, "queryParams": l{m{"name": "q", "value": "1"}}})},
			[]probe{{method: "POST", host: "conf.test", target: "/x", status: 200, backend: "b"},
				{method: "POST", host: "conf.test", target: "/x", hdr: []string{"H", "1"}, status: 200, backend: "b"},    // method outranks headers
				{method: "GET", host: "conf.test", target: "/x?q=1", hdr: []string{"H", "1"}, status: 200, backend: "c"}, // headers outrank query
				p("/x?q=1", 200, "a")}},
		{"HTTPRouteWeight", "Core (statistical)",
			[]m{rule("/", ref("a", 1), ref("b", 0))}, []probe{p("/", 200, "a")}},
		{"HTTPRouteInvalidBackendRefs (500 for unresolved weight)", "Core",
			[]m{rule("/", ref("ghost", 1))}, []probe{p("/", 500, "")}},
		{"HTTPRouteRequestHeaderModifier", "Core",
			[]m{filtered(rule("/", ref("a", 1)), m{"type": "RequestHeaderModifier", "requestHeaderModifier": m{"set": l{m{"name": "X-Hdr", "value": "v"}}}})},
			[]probe{p("/", 200, "a")}},
		{"HTTPRouteRedirectScheme", "Extended",
			[]m{filtered(rule("/", ref("a", 1)), m{"type": "RequestRedirect", "requestRedirect": m{"scheme": "https", "statusCode": 302}})}, // backendRefs ignored beside a redirect
			[]probe{{method: "GET", host: "conf.test:8080", target: "/x?y=1", status: 302, location: "https://conf.test/x?y=1"}}},
		{"HTTPRouteRedirectHostAndStatus", "Extended",
			[]m{filtered(rule("/", ref("a", 1)), m{"type": "RequestRedirect", "requestRedirect": m{"hostname": "example.org", "statusCode": 301}})},
			[]probe{{method: "GET", host: "conf.test:8080", target: "/x", status: 301, location: "http://example.org:8080/x"}}},
		{"HTTPRouteRedirectPortAndScheme", "Extended",
			[]m{filtered(rule("/", ref("a", 1)), m{"type": "RequestRedirect", "requestRedirect": m{"scheme": "https", "port": 8443}})},
			[]probe{{method: "GET", host: "conf.test:8080", target: "/", status: 302, location: "https://conf.test:8443/"}}},
		{"HTTPRouteRedirectPath", "Extended",
			[]m{filtered(match(rule("", ref("a", 1)), pathPrefix("/old")), m{"type": "RequestRedirect", "requestRedirect": m{"path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/new"}}})},
			[]probe{{method: "GET", host: "conf.test:8080", target: "/old/x", status: 302, location: "http://conf.test:8080/new/x"}}},
		{"HTTPRouteRewritePath", "Extended",
			[]m{filtered(match(rule("", ref("a", 1)), pathPrefix("/prefix")), m{"type": "URLRewrite", "urlRewrite": m{"path": m{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/other"}}})},
			[]probe{p("/prefix/one", 200, "a")}},
		{"HTTPRouteResponseHeaderModifier", "Extended",
			[]m{filtered(rule("/", ref("a", 1)), m{"type": "ResponseHeaderModifier", "responseHeaderModifier": m{"add": l{m{"name": "X-Conf", "value": "1"}}}})},
			[]probe{p("/", 200, "a")}},
		{"HTTPRouteRequestMirror", "Extended",
			[]m{filtered(rule("/", ref("a", 1)), m{"type": "RequestMirror", "requestMirror": m{"backendRef": ref("b", -1)}})},
			[]probe{p("/", 200, "a")}},
		{"HTTPRouteRequestTimeout", "Extended",
			[]m{func() m { r := rule("/", ref("a", 1)); r["timeouts"] = m{"request": "1h"}; return r }()},
			[]probe{p("/", 200, "a")}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			be, _ := upstreams(t, "a", "b", "c")
			s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", row.rules...)}, be), nil)
			for _, pr := range row.probes {
				r := req(t, client(s.Addr(8080), nil), "http", pr.method, pr.host, pr.target, "", pr.hdr...)
				if r.Status != pr.status {
					t.Errorf("%s %s%s -> %d, want %d", pr.method, pr.host, pr.target, r.Status, pr.status)
				}
				if pr.backend != "" && r.Echo.Name != pr.backend {
					t.Errorf("%s -> backend %q, want %q", pr.target, r.Echo.Name, pr.backend)
				}
				if pr.location != "" && r.Header.Get("Location") != pr.location {
					t.Errorf("%s -> Location %q, want %q", pr.target, r.Header.Get("Location"), pr.location)
				}
			}
		})
	}
}

// TestUpDemo runs the shipped demo end to end through Up, like a user would.
func TestUpDemo(t *testing.T) {
	var out, errb syncBuf
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Up(ctx, "../../examples/builtin-demo.json", Options{PortMap: map[int]int{8080: 0}, Admin: "off", Rand: seededRand(5)}, 50*time.Millisecond, &out, &errb)
	}()
	var port string
	waitFor(t, "demo hint", func() bool {
		mm := regexp.MustCompile(`setura explain http://orders\.mactra\.test:(\d+)/checkout --address 127\.0\.0\.1 --backend orders-v1`).FindStringSubmatch(out.String())
		if mm != nil {
			port = mm[1]
		}
		return mm != nil
	})
	c := client("127.0.0.1:"+port, nil)
	counts := map[string]int{}
	for i := 0; i < 300; i++ {
		r := req(t, c, "http", "GET", "orders.mactra.test:"+port, "/checkout", "")
		if r.Status != 200 || r.Header.Get("Setura-Nope") != "" {
			t.Fatalf("status %d: %s", r.Status, r.Body)
		}
		counts[r.Header.Get(BackendHeader)]++
	}
	if counts["orders-v1"] < 240 || counts["orders-v2"] < 10 || counts["orders-v1"]+counts["orders-v2"] != 300 {
		t.Fatalf("expected roughly 90/10, got %v", counts)
	}
	if r := req(t, c, "http", "GET", "orders.mactra.test:"+port, "/api/x", ""); r.Header.Get("X-Served-By") != "setura" || !bytes.Contains([]byte(r.Body), []byte("GET /x")) {
		t.Fatalf("rewrite+header: %v %q", r.Header, r.Body)
	}
	if r := req(t, c, "http", "GET", "orders.mactra.test:"+port, "/old/9", ""); r.Status != 301 || r.Header.Get("Location") != fmt.Sprintf("http://orders.mactra.test:%s/checkout/9", port) {
		t.Fatalf("redirect: %d %q", r.Status, r.Header.Get("Location"))
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
