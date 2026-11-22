package setura

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type jm = map[string]any
type jl = []any

// modelConfig writes a gateway config with an HTTP listener (:8080), a TLS
// passthrough listener (:8443), one HTTPRoute, one GRPCRoute and one TLSRoute.
// after switches on the changes the replay should find.
func modelConfig(t *testing.T, name string, after bool) string {
	t.Helper()
	ref := func(n string, port, w int) jm { return jm{"name": n, "port": port, "weight": w} }
	api := jm{"matches": jl{jm{"path": jm{"type": "PathPrefix", "value": "/api"}}}, "backendRefs": jl{ref("api", 80, 1)}}
	mir := jm{"matches": jl{jm{"path": jm{"type": "PathPrefix", "value": "/m"}}}, "backendRefs": jl{ref("web", 80, 1)}}
	grpcB, tlsB := "grpc-v1", "db-v1"
	if after {
		api["retry"] = jm{"codes": jl{503}, "attempts": 3, "backoff": "10ms"}
		api["timeouts"] = jm{"request": "5s"}
		mir["filters"] = jl{jm{"type": "RequestMirror", "requestMirror": jm{"backendRef": ref("shadow", 80, 1),
			"percent": 50, "setura.zyvor.dev/shadow-diff": jm{"compare": true, "sample": 20}}}}
		mir["backendRefs"] = jl{ref("bad", 80, 1)}
		grpcB, tlsB = "grpc-v2", "db-v2"
	}
	res := jm{
		"gateways.gateway.networking.k8s.io/gw": jm{"gatewayClassName": "setura", "listeners": jl{
			jm{"name": "web", "protocol": "HTTP", "port": 8080, "hostname": "orders.example.test"},
			jm{"name": "pass", "protocol": "TLS", "port": 8443, "tls": jm{"mode": "Passthrough"}},
		}},
		"httproutes.gateway.networking.k8s.io/orders": jm{"parentRefs": jl{jm{"name": "gw", "sectionName": "web"}}, "hostnames": jl{"orders.example.test"}, "rules": jl{api, mir}},
		"grpcroutes.gateway.networking.k8s.io/greeter": jm{"parentRefs": jl{jm{"name": "gw", "sectionName": "web"}}, "hostnames": jl{"orders.example.test"},
			"rules": jl{jm{"matches": jl{jm{"method": jm{"service": "helloworld.Greeter", "method": "SayHello"}}}, "backendRefs": jl{ref(grpcB, 80, 1)}}}},
		"tlsroutes.gateway.networking.k8s.io/db": jm{"parentRefs": jl{jm{"name": "gw", "sectionName": "pass"}}, "hostnames": jl{"db.example.test"},
			"rules": jl{jm{"backendRefs": jl{ref(tlsB, 443, 1)}}}},
	}
	be := jm{}
	for _, n := range []string{"api", "web", "shadow", "bad", "grpc-v1", "grpc-v2"} {
		be["shop/"+n+":80"] = "127.0.0.1:9"
	}
	for _, n := range []string{"db-v1", "db-v2"} {
		be["shop/"+n+":443"] = "127.0.0.1:9"
	}
	raw, _ := json.Marshal(jm{"schema": "setura.route-specs/v1", "namespace": "shop", "resources": res, "backends": be})
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func repeat(n int, line string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = line
	}
	return out
}

func TestReplayModelsPolicyGRPCTLSAndFormats(t *testing.T) {
	before, after := modelConfig(t, "before.json", false), modelConfig(t, "after.json", true)
	jsonl := func(method, path, route, backend string, status int) string {
		return fmt.Sprintf(`{"listener":"shop/gw/web","host":"orders.example.test","method":%q,"path":%q,"status":%d,"route":%q,"backend":%q}`, method, path, status, route, backend)
	}
	var lines []string
	// json, text and combined formats for the same /api traffic
	lines = append(lines, jsonl("GET", "/api/a", "shop/orders", "shop/api:80", 200))
	lines = append(lines, `time="2026-11-22T10:00:00Z" listener="shop/gw/web" host="orders.example.test" method="GET" path="/api/b?x=\"1\"" status=200 bytes=5 duration_ms=1.000 route="shop/orders" backend="shop/api:80" remote="10.0.0.1:1"`)
	lines = append(lines, `10.0.0.1 - bob [22/Nov/2026:10:00:00 +0000] "GET /api/c HTTP/1.1" 200 512 "-" "curl/8"`)
	lines = append(lines, `10.0.0.1 - - [22/Nov/2026:10:00:01 +0000] "GET http://orders.example.test/api/d HTTP/1.1" 200 512`)
	lines = append(lines, `10.0.0.1 - - [22/Nov/2026:10:00:02 +0000] "-" 408 0`)
	// gRPC by route kind, and a gRPC call that matched nothing (404), by path shape
	lines = append(lines, jsonl("POST", "/helloworld.Greeter/SayHello", "GRPCRoute/shop/greeter", "shop/grpc-v1:80", 200))
	lines = append(lines, jsonl("POST", "/other.Svc/Call", "", "", 404))
	// TLS passthrough lines: method TLS, host is the SNI, no path
	lines = append(lines, `{"listener":"shop/gw/pass","host":"db.example.test","method":"TLS","path":"","status":200,"route":"TLSRoute/shop/db","backend":"shop/db-v1:443"}`)
	lines = append(lines, `time="2026-11-22T10:00:00Z" listener="shop/gw/pass" host="db.example.test" method="TLS" status=200 bytes=9 duration_ms=1.000 route="TLSRoute/shop/db" backend="shop/db-v1:443" remote="10.0.0.1:2"`)
	// mirror target, and a backend that is failing in the log
	lines = append(lines, repeat(3, jsonl("GET", "/m/x", "shop/orders", "shop/web:80", 200))...)
	lines = append(lines, repeat(25, jsonl("GET", "/zzz", "", "shop/bad:80", 503))...)
	lines = append(lines, repeat(4, jsonl("GET", "/api/limited", "shop/orders", "", 429))...)
	log := replayLog(t, lines...)

	rep, _ := replayJSON(t, "--log", log, "--before", before, "--after", after, "--default-host", "orders.example.test",
		"--before-rate-limit", "10/s", "--after-rate-limit", "10/s,burst=5,key=route")
	in := rep.Input
	if in.Formats["json"] != 36 || in.Formats["text"] != 2 || in.Formats["common"] != 2 || in.SkippedNonJSON != 1 {
		t.Fatalf("formats %+v", in)
	}
	if in.GRPC != 2 || in.TLS != 2 {
		t.Fatalf("gRPC %d, TLS %d replayed; input %+v", in.GRPC, in.TLS, in)
	}
	if in.LoggedRouteMismatch != 0 {
		t.Errorf("logged routes must match the before config, got %d mismatches", in.LoggedRouteMismatch)
	}
	if classReq(rep, classPolicy) != 8 { // 4 json/text/clf/absolute lines + 4 429 lines
		t.Errorf("policy class %d, want 8", classReq(rep, classPolicy))
	}
	if classReq(rep, classMirror) != 3 {
		t.Errorf("mirror class %d, want 3", classReq(rep, classMirror))
	}
	if classReq(rep, classBackend) != 6 { // 1 gRPC + 2 TLS + 3 /m
		t.Errorf("backend class %d: gRPC and TLS decisions were not replayed", classReq(rep, classBackend))
	}
	var sawRetry, sawMirror, sawTimeout bool
	for _, p := range rep.PolicyChanges {
		sawRetry = sawRetry || p.Field == "retry" && p.Route == "shop/orders" && strings.Contains(p.After, "3 retries") && p.Before == "none"
		sawTimeout = sawTimeout || p.Field == "timeout" && p.After == "5s"
		sawMirror = sawMirror || p.Field == "mirror" && strings.Contains(p.After, "shop/shadow:80 50% shadow-diff 20%")
	}
	if !sawRetry || !sawTimeout || !sawMirror {
		t.Errorf("policy changes %+v", rep.PolicyChanges)
	}
	if len(rep.BackendHealth) != 1 || rep.BackendHealth[0].Backend != "shop/bad:80" || rep.BackendHealth[0].Percent != 100 {
		t.Fatalf("health %+v", rep.BackendHealth)
	}
	if classReq(rep, classHealth) != 3 { // /m now goes to shop/bad:80
		t.Errorf("health class %d, want 3", classReq(rep, classHealth))
	}
	rl := rep.RateLimit
	if rl == nil || rl.Before != "10/s burst 10 key ip" || rl.After != "10/s burst 5 key route" || rl.Logged != 4 || rl.Requests == 0 || classReq(rep, classRate) == 0 {
		t.Fatalf("rate limit %+v class %d", rl, classReq(rep, classRate))
	}
	// gRPC and TLS requests carry no HTTP rate limit
	if classReq(rep, classRate) >= rep.Input.Requests {
		t.Errorf("rate limit class counts gRPC/TLS requests: %d of %d", classReq(rep, classRate), rep.Input.Requests)
	}
	// health never changes a verdict, and is not part of "any"
	code, out, _ := replayRun(t, []string{"--log", log, "--before", before, "--after", before, "--fail-on", "any,health", "--format", "json"}, "")
	if code != 0 {
		t.Errorf("identical configs must pass, got %d\n%s", code, out)
	}
	if c, _, _ := replayRun(t, []string{"--log", log, "--before", before, "--after", after, "--fail-on", "policy", "--default-host", "x"}, ""); c != 1 {
		t.Errorf("--fail-on policy exit %d, want 1", c)
	}
}

func TestReplayCommonLogNeedsHost(t *testing.T) {
	before := modelConfig(t, "b.json", false)
	log := replayLog(t, `10.0.0.1 - - [22/Nov/2026:10:00:00 +0000] "GET /api/c HTTP/1.1" 200 512 "-" "curl/8"`)
	rep, _ := replayJSON(t, "--log", log, "--before", before, "--after", before)
	if rep.Input.Requests != 0 || rep.Input.SkippedIncomplete != 1 {
		t.Fatalf("a Common Log Format line without a host must be skipped, not guessed: %+v", rep.Input)
	}
}

func TestReplayParsers(t *testing.T) {
	var in interner
	var rec logRec
	for _, c := range []struct {
		line, format, host, path, method string
		status                           int
	}{
		{`{"host":"a.test","path":"/xA","method":"GET","status":200}`, fmtJSON, "a.test", "/xA", "GET", 200},
		{`{"time":"t","host":"a.test","path":"/x","status":502,"bytes":12,"duration_ms":1.5,"rule":0,"remote":"1.2.3.4:5"}`, fmtJSON, "a.test", "/x", "", 502},
		{`time=2026 host=a.test method=GET path=/p?q=1 status=404`, fmtText, "a.test", "/p?q=1", "GET", 404},
		{`1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "POST /a b HTTP/1.1" 201 -`, fmtCommon, "", "/a b", "POST", 201},
	} {
		rec = logRec{}
		if !in.parseLogLine([]byte(c.line), &rec, "") {
			t.Errorf("%s: not parsed", c.line)
			continue
		}
		if rec.format != c.format || string(rec.host) != c.host || string(rec.path) != c.path || rec.method != c.method || rec.status != c.status {
			t.Errorf("%s: got %+v host %q path %q", c.line, rec, rec.host, rec.path)
		}
	}
	for _, bad := range []string{`{"broken`, `hello world`, `[x] "y"`} {
		if in.parseLogLine([]byte(bad), &rec, "") {
			t.Errorf("%q should not parse", bad)
		}
	}
}
