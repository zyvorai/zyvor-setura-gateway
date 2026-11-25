package setura

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// startGateway runs the built-in gateway on a snapshot with every listener port
// mapped to a free loopback port, and returns it once ready.
func startGateway(t *testing.T, resources, backends map[string]any, ports ...int) *builtin.Server {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"schema": snapshotSchema, "namespace": "demo", "resources": resources, "backends": backends})
	if err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(t.TempDir(), "live.json")
	if err := os.WriteFile(live, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	m := map[int]int{}
	for _, p := range ports {
		m[p] = 0
	}
	gw := builtin.New(builtin.Options{PortMap: m, Admin: "127.0.0.1:0", Lint: gatewayLint, Diag: io.Discard})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gw.Run(ctx, builtin.FileSource{Path: live}, 50*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; !gw.Ready(); i++ {
		if i > 500 {
			t.Fatal("gateway never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return gw
}

func startEcho(t *testing.T, name string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready, done := make(chan string, 1), make(chan error, 1)
	go func() { done <- ServeEcho(ctx, "127.0.0.1:0", name, ready) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case addr := <-ready:
		return addr
	case err := <-done:
		done <- err
		t.Fatal(err)
		return ""
	}
}

func listenerPort(t *testing.T, gw *builtin.Server, port int) string {
	t.Helper()
	_, p, err := net.SplitHostPort(gw.Addr(port))
	if err != nil {
		t.Fatalf("listener %d: %v", port, err)
	}
	return p
}

func TestSplitGRPCRouteThroughGateway(t *testing.T) {
	v1, v2 := startEcho(t, "orders-v1"), startEcho(t, "orders-v2")
	gw := startGateway(t, map[string]any{
		"gateways.gateway.networking.k8s.io/edge": map[string]any{"gatewayClassName": "setura", "listeners": []any{
			map[string]any{"name": "grpc", "protocol": "HTTP", "port": 8080}}},
		"grpcroutes.gateway.networking.k8s.io/orders": map[string]any{
			"parentRefs": []any{map[string]any{"name": "edge"}}, "hostnames": []any{"grpc.mactra.test"},
			"rules": []any{map[string]any{"backendRefs": []any{
				map[string]any{"name": "v1", "port": 50051, "weight": 3}, map[string]any{"name": "v2", "port": 50051, "weight": 1}}}}},
	}, map[string]any{"v1:50051": v1, "v2:50051": v2}, 8080)
	// The built-in gateway names the backend Service in X-Setura-Backend.
	url := "http://grpc.mactra.test:" + listenerPort(t, gw, 8080)

	code, m := cliJSON(t, "split", url, "--grpc", "--address", "127.0.0.1", "--requests", "300",
		"--expect", "v1=3", "--expect", "v2=1", "--json")
	if code != 0 || m["ok"] != true || m["protocol"] != "grpc" || m["samples"] != float64(300) || m["errors"] != float64(0) {
		t.Fatalf("exit %d: %v", code, m)
	}
	// The reversed expectation is far outside the tolerance.
	code, out, _ := cli(t, nil, "split", url, "--grpc", "--address", "127.0.0.1", "--requests", "300",
		"--expect", "v1=1", "--expect", "v2=3")
	if code != 1 || !strings.Contains(out, "FAIL v1") || !strings.Contains(out, "via X-Setura-Backend") {
		t.Fatalf("exit %d: %s", code, out)
	}
	// Any other method needs the explicit flag; with it the echo backend answers.
	args := []string{"split", url, "--grpc-method", "mactra.orders.v1.Orders/Get", "--address", "127.0.0.1", "--requests", "100",
		"--expect", "v1=3", "--expect", "v2=1", "--request-header", "x-tenant: ops"}
	if code, _, errs := cli(t, nil, args...); code != 2 || !strings.Contains(errs, "--allow-unsafe-method") {
		t.Fatalf("unsafe method: %d %s", code, errs)
	}
	if code, out, errs := cli(t, nil, append(args, "--allow-unsafe-method")...); code != 0 {
		t.Fatalf("custom method: %d %s %s", code, out, errs)
	}
	// A host no GRPCRoute serves is an error, not a silent pass.
	code, m = cliJSON(t, "split", "http://other.test:"+listenerPort(t, gw, 8080), "--grpc", "--address", "127.0.0.1",
		"--requests", "20", "--expect", "v1=1", "--json")
	if code != 1 || m["errors"] != float64(20) || !strings.Contains(asStr(m["first_error"]), "grpc") {
		t.Fatalf("unrouted: %d %v", code, m)
	}
}

func TestSplitGRPCOverTLSAndFailures(t *testing.T) {
	tlsServer := func(h http.HandlerFunc) (string, string) {
		cfg, ca := selfSigned(t)
		srv := httptest.NewUnstartedServer(h)
		srv.TLS, srv.EnableHTTP2 = cfg, true
		srv.StartTLS()
		t.Cleanup(srv.Close)
		_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
		return "https://orders.mactra.test:" + port, ca
	}
	split := func(url, ca string, extra ...string) (int, map[string]any) {
		return cliJSON(t, append([]string{"split", url, "--grpc", "--ca", ca, "--address", "127.0.0.1", "--requests", "20",
			"--expect", "solo=1", "--json"}, extra...)...)
	}
	url, ca := tlsServer(EchoHandler("solo").ServeHTTP)
	if code, m := split(url, ca); code != 0 || m["ok"] != true {
		t.Fatalf("tls: %d %v", code, m)
	}
	// Identity sent as a trailer is read too.
	url, ca = tlsServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, X-Backend")
		w.Write([]byte{0, 0, 0, 0, 0})
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("X-Backend", "solo")
	})
	if code, m := split(url, ca, "--identity-header", "X-Backend"); code != 0 {
		t.Fatalf("trailer identity: %d %v", code, m)
	}
	// A trailers-only UNIMPLEMENTED is a failed call.
	url, ca = tlsServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("X-Setura-Backend", "solo")
		w.Header().Set("Grpc-Status", "12")
		w.Header().Set("Grpc-Message", "nope")
	})
	code, m := split(url, ca)
	if code != 1 || m["errors"] != float64(20) || !strings.Contains(asStr(m["first_error"]), "grpc-status 12 nope") {
		t.Fatalf("unimplemented: %d %v", code, m)
	}
	// No grpc-status at all.
	url, ca = tlsServer(func(w http.ResponseWriter, r *http.Request) {})
	if code, m := split(url, ca); code != 1 || !strings.Contains(asStr(m["first_error"]), "no grpc-status") {
		t.Fatalf("not grpc: %d %v", code, m)
	}
	// HTTP errors.
	url, ca = tlsServer(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	if code, m := split(url, ca); code != 1 || !strings.Contains(asStr(m["first_error"]), "HTTP status 503") {
		t.Fatalf("503: %d %v", code, m)
	}
}

func TestSplitProtocolUsageErrors(t *testing.T) {
	base := []string{"--expect", "a=1"}
	for _, args := range [][]string{
		{"http://x.test/path", "--grpc"},
		{"tls://x.test:1", "--grpc"},
		{"http://x.test", "--grpc", "--status", "200"},
		{"http://x.test", "--grpc", "--method", "GET"},
		{"http://x.test", "--grpc", "--request-header", "grpc-timeout: 1S"},
		{"http://x.test", "--grpc", "--request-header", "Content-Type: x"},
		{"http://x.test", "--grpc-method", "nomethod", "--allow-unsafe-method"},
		{"http://x.test", "--grpc-method", "a/b c", "--allow-unsafe-method"},
		{"http://x.test", "--grpc", "--address", "nope"},
		{"http://x.test", "--grpc", "--timeout", "0"},
		{"http://x.test", "--identity", "cert-cn"},
		{"http://x.test", "--sni", "x"},
		{"tls://x.test", "--ca", "x"},
		{"tls://x.test:99999"},
		{"tls://x.test:443/path"},
		{"tls://127.0.0.1:443"},
		{"tls://x.test:443", "--identity", "serial"},
		{"tls://x.test:443", "--status", "200"},
		{"tls://x.test:443", "--identity-header", "X"},
		{"tls://x.test:443", "--request-header", "a: b"},
	} {
		code, _, errs := cli(t, nil, append(append([]string{"split"}, args...), base...)...)
		if code != 2 {
			t.Errorf("%v: exit %d %s", args, code, errs)
		}
	}
}

func TestSplitTLSRoutePassthroughThroughGateway(t *testing.T) {
	pki := newPKI(t, 90, tls.NoClientCert)
	leafs := map[string]tls.Certificate{}
	backend := func(name string) string {
		cert, _, _ := issue(t, pki.ca, pki.caKey, &x509.Certificate{Subject: pkix.Name{CommonName: name},
			DNSNames: []string{name + ".internal", "db.secure.test"}, NotAfter: time.Now().Add(24 * time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		leafs[name] = cert
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		t.Cleanup(func() { ln.Close(); wg.Wait() })
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = io.Copy(io.Discard, c) // handshake, then wait for the client to leave
				}()
			}
		}()
		return ln.Addr().String()
	}
	blue, green := backend("db-blue"), backend("db-green")
	gw := startGateway(t, map[string]any{
		"gateways.gateway.networking.k8s.io/edge": map[string]any{"gatewayClassName": "setura", "listeners": []any{
			map[string]any{"name": "passthrough", "protocol": "TLS", "port": 8443, "tls": map[string]any{"mode": "Passthrough"}}}},
		"tlsroutes.gateway.networking.k8s.io/db": map[string]any{
			"parentRefs": []any{map[string]any{"name": "edge"}}, "hostnames": []any{"db.secure.test"},
			"rules": []any{map[string]any{"backendRefs": []any{
				map[string]any{"name": "blue", "port": 5432, "weight": 3}, map[string]any{"name": "green", "port": 5432, "weight": 1}}}}},
	}, map[string]any{"blue:5432": blue, "green:5432": green}, 8443)
	url := "tls://db.secure.test:" + listenerPort(t, gw, 8443)
	run := func(extra ...string) (int, map[string]any) {
		return cliJSON(t, append([]string{"split", url, "--address", "127.0.0.1", "--ca", pki.caPEM, "--requests", "300", "--json"}, extra...)...)
	}

	code, m := run("--expect", "db-blue=3", "--expect", "db-green=1")
	if code != 0 || m["ok"] != true || m["protocol"] != "tls" || m["identity"] != "cert-cn" || m["samples"] != float64(300) {
		t.Fatalf("cert-cn: %d %v", code, m)
	}
	if code, m = run("--expect", "db-blue=1", "--expect", "db-green=3"); code != 1 || m["hint"] != nil {
		t.Fatalf("reversed: %d %v", code, m)
	}
	if code, m = run("--identity", "cert-san", "--expect", "db-blue.internal=3", "--expect", "db-green.internal=1"); code != 0 {
		t.Fatalf("cert-san: %d %v", code, m)
	}
	fp := func(n string) string {
		s := sha256.Sum256(leafs[n].Certificate[0])
		return hex.EncodeToString(s[:])[:16]
	}
	if code, m = run("--identity", "cert-sha256", "--expect", fp("db-blue")+"=3", "--expect", fp("db-green")+"=1"); code != 0 {
		t.Fatalf("cert-sha256: %d %v", code, m)
	}
	// Without the CA every handshake fails verification.
	code, m = cliJSON(t, "split", url, "--address", "127.0.0.1", "--requests", "40", "--expect", "db-blue=3", "--expect", "db-green=1", "--json")
	if code != 1 || m["errors"] != float64(40) || !strings.Contains(asStr(m["first_error"]), "tls:") {
		t.Fatalf("untrusted: %d %v", code, m)
	}
	// One certificate for every connection gets a hint.
	code, out, _ := cli(t, nil, "split", "tls://db.secure.test:"+strings.Split(blue, ":")[1], "--address", "127.0.0.1", "--ca", pki.caPEM,
		"--requests", "40", "--expect", "db-blue=1", "--expect", "db-green=1")
	if code != 1 || !strings.Contains(out, "hint: every connection presented the same certificate identity") || !strings.Contains(out, "via cert-cn") {
		t.Fatalf("hint: %d %s", code, out)
	}
}

type fakeRDAP struct {
	mu    sync.Mutex
	hits  map[string]int
	srv   *httptest.Server
	dates map[string]string // domain -> expiration; "" means no event
}

func newRDAP(t *testing.T) *fakeRDAP {
	t.Helper()
	in := func(days int) string {
		return time.Now().Add(time.Duration(days)*24*time.Hour + time.Hour).UTC().Format(time.RFC3339)
	}
	f := &fakeRDAP{hits: map[string]int{}, dates: map[string]string{
		"mactra.test": in(400), "soon.test": in(10), "past.test": in(-5), "shop.co.test": in(200), "noexp.test": "", "bad.test": "tomorrow"}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		f.mu.Unlock()
		if r.URL.Path == "/dns.json" {
			fmt.Fprintf(w, `{"version":"1.0","services":[[["test"],[%q]],[["other"],["ftp://nope/"]]]}`, f.srv.URL+"/rdap/")
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/rdap/domain/")
		switch name {
		case "limited.test":
			w.WriteHeader(429)
			return
		case "wrong.test":
			io.WriteString(w, `{"ldhName":"else.test","events":[]}`)
			return
		case "html.test":
			io.WriteString(w, `<html>`)
			return
		case "www.soon.test": // some registries answer 400 below a registration
			w.WriteHeader(400)
			return
		}
		date, ok := f.dates[name]
		if !ok {
			w.WriteHeader(404)
			return
		}
		events := []any{map[string]any{"eventAction": "registration", "eventDate": "2001-01-01T00:00:00Z"}}
		if date != "" {
			events = append(events, map[string]any{"eventAction": "expiration", "eventDate": date})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ldhName": strings.ToUpper(name), "events": events})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRDAP) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func TestRDAPLookup(t *testing.T) {
	f := newRDAP(t)
	c := newRDAPClient(DomainOptions{Bootstrap: f.srv.URL + "/dns.json", WarnDays: 30})
	for _, tc := range []struct {
		host, name, status, detail string
		days                       int
	}{
		{host: "WWW.Mactra.Test.", name: "mactra.test", status: domainOK, days: 400},
		{host: "api.eu.mactra.test", name: "mactra.test", status: domainOK, days: 400},
		{host: "www.shop.co.test", name: "shop.co.test", status: domainOK, days: 200},
		{host: "www.soon.test", name: "soon.test", status: domainExpiring, days: 10},
		{host: "past.test", name: "past.test", status: domainExpiring, days: -5},
		{host: "noexp.test", name: "noexp.test", status: domainUnknown, detail: "publishes no expiration"},
		{host: "bad.test", name: "bad.test", status: domainUnknown, detail: "not RFC 3339"},
		{host: "limited.test", name: "limited.test", status: domainUnknown, detail: "HTTP 429"},
		{host: "wrong.test", name: "wrong.test", status: domainUnknown, detail: `answered for "else.test"`},
		{host: "html.test", name: "html.test", status: domainUnknown, detail: "not JSON"},
		{host: "missing.test", status: domainUnknown, detail: "no RDAP record"},
		{host: "x.example", name: "x.example", status: domainUnknown, detail: "no server for .example"},
		{host: "x.other", name: "x.other", status: domainUnknown, detail: "no server for .other"},
		{host: "bücher.test", status: domainUnknown, detail: "xn--"},
		{host: "127.0.0.1", status: domainSkipped},
		{host: "::1", status: domainSkipped},
		{host: "localhost", status: domainSkipped},
	} {
		got := c.Lookup(tc.host)
		if got.Name != tc.name || got.Status != tc.status || !strings.Contains(got.Detail, tc.detail) {
			t.Errorf("%s: %+v", tc.host, got)
		}
		if tc.days != 0 && (got.DaysLeft == nil || *got.DaysLeft != tc.days) {
			t.Errorf("%s: days %+v", tc.host, got.DaysLeft)
		}
	}
	if n := f.count("/dns.json"); n != 1 {
		t.Errorf("bootstrap read %d times", n)
	}
	if n := f.count("/rdap/domain/mactra.test"); n != 1 {
		t.Errorf("a domain is asked once, got %d", n)
	}
	broken := newRDAPClient(DomainOptions{Bootstrap: f.srv.URL + "/rdap/domain/nothing", WarnDays: 30})
	if got := broken.Lookup("a.test"); got.Status != domainUnknown || !strings.Contains(got.Detail, "bootstrap") {
		t.Errorf("broken bootstrap: %+v", got)
	}
}

func TestRDAPBootstrapPrefersHTTPSAndLongestMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"services":[[["uk"],["http://a.test/","https://b.test/"]],[["co.uk"],["https://c.test/"]]]}`)
	}))
	defer srv.Close()
	c := newRDAPClient(DomainOptions{Bootstrap: srv.URL})
	for name, want := range map[string]string{"x.uk": "https://b.test/", "x.co.uk": "https://c.test/"} {
		if got, err := c.serverFor(name); err != nil || got != want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
}

func TestCertsDomainExpiryCLI(t *testing.T) {
	f := newRDAP(t)
	pki := newPKI(t, 90, tls.NoClientCert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = pki.server
	srv.StartTLS()
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	rdap := []string{"--domain-expiry", "--rdap-bootstrap", f.srv.URL + "/dns.json", "--timeout", "2"}
	base := append([]string{"certs", addr, "--ca", pki.caPEM, "--sni", "orders.mactra.test"}, rdap...)

	// One target is enough to select the table; the domain comes from --sni for an IP target.
	code, out, errs := cli(t, nil, base...)
	if code != 0 || !strings.Contains(out, "DOMAIN") || !strings.Contains(out, "mactra.test") || !strings.Contains(out, "all 1 targets ok (certificate and domain)") {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	code, m := cliJSON(t, append(base, "--json")...)
	d := asMap(asMap(asList(m["targets"])[0])["domain"])
	if code != 0 || d["name"] != "mactra.test" || d["status"] != "ok" || d["days_left"] != float64(400) {
		t.Fatalf("json: %d %v", code, m)
	}
	code, out, _ = cli(t, nil, append(base, "--warn-domain-days", "500")...)
	if code != 1 || !strings.Contains(out, "EXPIRING") || !strings.Contains(out, "domain: the registration expires in under 500 days") || !strings.Contains(out, "1 of 1 need attention") {
		t.Fatalf("expiring: %d %s", code, out)
	}
	// --rdap-url skips the bootstrap; names that do not connect are still looked up and sort by what runs out first.
	code, m = cliJSON(t, "certs", "www.soon.invalid:1", "127.0.0.1:1", "--domain-expiry", "--rdap-url", f.srv.URL+"/rdap", "--timeout", "1", "--json")
	rows := asList(m["targets"])
	if code != 1 || len(rows) != 2 {
		t.Fatalf("errors: %d %v", code, m)
	}
	for _, r := range rows {
		row := asMap(r)
		want := map[string]string{"www.soon.invalid:1": "unknown", "127.0.0.1:1": "skipped"}[asStr(row["target"])]
		if row["status"] != "error" || asMap(row["domain"])["status"] != want {
			t.Errorf("row %v", row)
		}
	}
	// Without the flag the output is unchanged.
	code, out, _ = cli(t, nil, "certs", addr, addr+"0", "--ca", pki.caPEM, "--timeout", "1")
	if strings.Contains(out, "DOMAIN") {
		t.Errorf("unexpected domain column: %d %s", code, out)
	}
	for _, bad := range [][]string{
		{"certs", addr, "--warn-domain-days", "3"},
		{"certs", addr, "--rdap-url", "https://r.test/"},
		{"certs", addr, "--domain-expiry", "--rdap-url", "file:///etc"},
		{"certs", addr, "--domain-expiry", "--rdap-bootstrap", "nourl"},
		{"certs", addr, "--domain-expiry", "--warn-domain-days", "-1"},
	} {
		if code, _, errs := cli(t, nil, bad...); code != 2 {
			t.Errorf("%v: exit %d %s", bad, code, errs)
		}
	}
}

func TestCheckVariables(t *testing.T) {
	var mu sync.Mutex
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("X-Env", "staging")
		io.WriteString(w, `{"version":"v7","literal":"{{keep}}"}`)
	}))
	defer srv.Close()
	file := writeChecks(t, `[{"url":"{{base}}/health","request_headers":{"Authorization":"Bearer {{api-token}}"},
		"headers":{"X-Env":"{{env}}"},"json":{"$.version":"{{version}}","$.literal":"\\{{keep}}"},"body_contains":"{{version}}"}]`)
	vars := filepath.Join(t.TempDir(), "staging.vars")
	if err := os.WriteFile(vars, []byte("# staging\n base = "+srv.URL+"\nenv=production\napi-token=from-file\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SETURA_VAR_version", "v7")
	t.Setenv("SETURA_VAR_env", "from-environment")
	code, out, errs := cli(t, nil, "check", file, "--vars-file", vars, "--var", "env=staging", "--format", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	if len(auth) != 1 || auth[0] != "Bearer from-file" {
		t.Fatalf("authorization: %q", auth)
	}
	if strings.Contains(out, "from-file") {
		t.Errorf("a request header value reached the report: %s", out)
	}
	// An undefined variable stops the run before any request, naming it only.
	code, _, errs = cli(t, nil, "check", file, "--var", "base="+srv.URL, "--var", "env=s3cr3t")
	if code != 2 || !strings.Contains(errs, "{{api-token}} is not defined") || strings.Contains(errs, "s3cr3t") {
		t.Fatalf("undefined: %d %s", code, errs)
	}
	if len(auth) != 1 {
		t.Fatal("a request was sent despite the undefined variable")
	}
	dup := filepath.Join(t.TempDir(), "dup.vars")
	_ = os.WriteFile(dup, []byte("a=1\na=2\n"), 0o600)
	broken := filepath.Join(t.TempDir(), "broken.vars")
	_ = os.WriteFile(broken, []byte("secretvalue\n"), 0o600)
	for _, bad := range [][]string{
		{"--var", "novalue"}, {"--var", "1x=2"}, {"--var", "a=" + strings.Repeat("x", 5000)},
		{"--vars-file", dup}, {"--vars-file", broken}, {"--vars-file", filepath.Join(t.TempDir(), "none")},
	} {
		code, _, errs := cli(t, nil, append([]string{"check", file}, bad...)...)
		if code == 0 || strings.Contains(errs, "secretvalue") {
			t.Errorf("%.60v: %d %s", bad, code, errs)
		}
	}
	// A value cannot rewrite the file's structure.
	inject := writeChecks(t, `[{"url":"`+srv.URL+`/","body_contains":"{{x}}"}]`)
	if code, _, _ := cli(t, nil, "check", inject, "--var", `x=v7","status":500,"a":"`); code != 1 {
		t.Errorf("injection should just fail the substring: %d", code)
	}
	// The library entry point reads the environment.
	t.Setenv("SETURA_VAR_base", srv.URL)
	t.Setenv("SETURA_VAR_api-token", "t")
	t.Setenv("SETURA_VAR_env", "staging")
	rows, err := Check(file)
	if err != nil || !rows[0].OK {
		t.Fatalf("env only: %v", err)
	}
}

func TestWatchVariables(t *testing.T) {
	srv := httptest.NewServer(EchoHandler("orders-v1"))
	defer srv.Close()
	file := writeChecks(t, `[{"url":"{{base}}/","backend":"{{backend}}"}]`)
	code, out, errs := cli(t, nil, "watch", "--file", file, "--var", "base="+srv.URL, "--var", "backend=orders-v1", "--count", "1")
	if code != 0 || !strings.Contains(out, "ok backend=orders-v1") {
		t.Fatalf("exit %d: %s %s", code, out, errs)
	}
	if code, _, errs = cli(t, nil, "watch", "--file", file, "--count", "1"); code != 2 || !strings.Contains(errs, "{{backend}}") {
		t.Fatalf("undefined: %d %s", code, errs)
	}
	if code, _, _ = cli(t, nil, "watch", srv.URL, "--var", "a=b", "--count", "1"); code != 2 {
		t.Fatalf("--var without --file: %d", code)
	}
}

func TestRolloutRejectsUndefinedVariableBeforeApplying(t *testing.T) {
	e := newE2E(t, "served by v1")
	if err := os.WriteFile(e.checks, []byte(`[{"url":"http://{{no-such-host}}/"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cand := e.candidate(t, e.snap([2]any{"orders-v2", -1}))
	before := mustRead(t, e.live)
	var out, errb strings.Builder
	code := runGateway([]string{"rollout", "--config", e.live, "--new", cand, "--checks", e.checks, "--admin", e.admin, "--observe", "200ms"}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String()+out.String(), "no-such-host") {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if mustRead(t, e.live) != before {
		t.Fatal("the live config changed")
	}
}

func TestAlertStreaks(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	a, clk, _ := testAlerter(t, alertConfig{Webhook: srv.URL, FailAfter: 3, RecoverAfter: 2}, io.Discard)
	step := func(ok bool, wantAlerts int) {
		t.Helper()
		clk.advance(time.Hour)
		a.observe("t", ok, "http", "boom", 1)
		a.wait()
		if got := rec.count(); got != wantAlerts {
			t.Fatalf("ok=%v: %d alerts, want %d", ok, got, wantAlerts)
		}
	}
	step(false, 0)
	step(false, 0)
	step(true, 0) // the streak is broken
	step(false, 0)
	step(false, 0)
	step(false, 1)
	step(false, 1)
	step(true, 1)
	step(false, 1) // still the failure recipients know about
	step(true, 1)
	step(true, 2)
	step(true, 2)
	if rec.bodies[0]["event"] != "failure" || rec.bodies[0]["consecutive"] != float64(3) ||
		rec.bodies[1]["event"] != "recovery" || rec.bodies[1]["consecutive"] != float64(2) {
		t.Fatalf("payloads: %v", rec.bodies)
	}
	// The default keeps the old behaviour and payload.
	one := &recorder{}
	s2 := httptest.NewServer(one)
	defer s2.Close()
	b, _, _ := testAlerter(t, alertConfig{Webhook: s2.URL}, io.Discard)
	b.observe("t", false, "http", "boom", 1)
	b.wait()
	if one.count() != 1 || one.bodies[0]["consecutive"] != nil {
		t.Fatalf("default: %v", one.bodies)
	}
}

func TestAlertStreakCLI(t *testing.T) {
	rec := &recorder{}
	hook := httptest.NewServer(rec)
	defer hook.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	code, _, errs := cli(t, nil, "watch", bad.URL, "--count", "2", "--interval", "1s", "--alert-webhook", hook.URL, "--alert-after", "3")
	if code != 1 || rec.count() != 0 {
		t.Fatalf("below the threshold: %d %d %s", code, rec.count(), errs)
	}
	code, _, errs = cli(t, nil, "watch", bad.URL, "--count", "2", "--interval", "1s", "--alert-webhook", hook.URL, "--alert-after", "2")
	if code != 1 || rec.count() != 1 {
		t.Fatalf("at the threshold: %d %d %s", code, rec.count(), errs)
	}
	for _, args := range [][]string{
		{"--alert-after", "0", "--alert-webhook", hook.URL},
		{"--alert-recover-after", "1001", "--alert-webhook", hook.URL},
		{"--alert-after", "2"},
	} {
		if code, _, _ := cli(t, nil, append([]string{"watch", bad.URL, "--count", "1"}, args...)...); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
}

func TestParseThresholds(t *testing.T) {
	s := benchStats{latencies: []float64{1, 2, 3, 4, 100}, sum: 110, failures: 1, seconds: 0.5}
	for expr, want := range map[string]bool{
		"p95<=100": true, "p(95) < 100": false, "p50<4": true, "med==3": true, "p(99.9)>99ms": true, "min>=1": true,
		"max<101ms": true, "avg<23": true, "mean<=22": true, "avg<22": false, "error_rate<0.3": true, "error_rate<0.2": false,
		"errors==1": true, "errors!=1": false, "requests>=5": true, "rps>=10": true, "rps>10": false, "p100==100": true,
	} {
		ts, err := ParseThresholds([]string{expr})
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		res, violations := evalThresholds(ts, s)
		if ok := asMap(res[0])["ok"] == true; ok != want || (len(violations) == 0) != want {
			t.Errorf("%s: %v %v", expr, res, violations)
		}
	}
	ts, _ := ParseThresholds([]string{"p95<10", "rps>=0", "requests==0"})
	res, violations := evalThresholds(ts, benchStats{})
	if len(violations) != 2 || asMap(res[2])["ok"] != true || !strings.Contains(violations[0], "no samples") {
		t.Errorf("empty run: %v %v", res, violations)
	}
	for _, bad := range []string{"", "p95", "p101<1", "p95<-1", "p95=1", "foo<1", "rps>1ms", "error_rate<5", "p95<1s", "p95<1%",
		"p95<" + strings.Repeat("9", 400)} {
		if _, err := ParseThresholds([]string{bad}); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
	if _, err := ParseThresholds(make([]string, 33)); err == nil {
		t.Error("too many thresholds")
	}
}

func TestBenchThresholdCLI(t *testing.T) {
	var n int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		k := n
		mu.Unlock()
		if k%10 == 0 {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	code, out, errs := cli(t, nil, "bench", srv.URL, "--requests", "20", "--concurrency", "1",
		"--threshold", "error_rate<=0.1", "--threshold", "p95<30000", "--threshold", "requests==20")
	if code != 0 || strings.Count(out, "threshold ok:") != 3 {
		t.Fatalf("pass: %d %s %s", code, out, errs)
	}
	code, m := cliJSON(t, "bench", srv.URL, "--requests", "20", "--concurrency", "1", "--threshold", "errors<1", "--threshold", "max>=0", "--json")
	rows := asList(m["thresholds"])
	if code != 1 || m["ok"] != false || len(rows) != 2 || asMap(rows[0])["observed"] != float64(2) || asMap(rows[1])["ok"] != true || len(asList(m["violations"])) != 1 {
		t.Fatalf("fail: %d %v", code, m)
	}
	code, m = cliJSON(t, "bench", srv.URL, "--requests", "2", "--json")
	if _, has := m["thresholds"]; has {
		t.Errorf("no thresholds key without the flag: %d %v", code, m)
	}
	before := n
	if code, _, _ := cli(t, nil, "bench", srv.URL, "--threshold", "nonsense"); code != 2 || n != before {
		t.Errorf("bad threshold must be refused before any request: %d, %s requests", code, strconv.Itoa(n-before))
	}
}

func TestEchoStillServesHTTP1(t *testing.T) {
	addr := startEcho(t, "plain")
	code, out, errs := cli(t, nil, "explain", "http://"+addr+"/", "--backend", "plain", "--json")
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
}

func TestSubstituteCheckFileSkipsFlagValues(t *testing.T) {
	file := writeChecks(t, `[{"url":"http://{context}.test/{{context}}"}]`)
	dst := filepath.Join(t.TempDir(), "out.json")
	got := substituteCheckFile([]string{"check", "--var", "a=b", "--retries", "2", "--vars-file=x", file, "--format", "json"}, "prod", dst)
	if got[6] != dst {
		t.Fatalf("args: %v", got)
	}
	if body := mustRead(t, dst); body != `[{"url":"http://prod.test/{{context}}"}]` {
		t.Fatalf("body: %s", body)
	}
}
