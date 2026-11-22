package setura

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// h2Server starts a loopback TLS server with HTTP/2 enabled (or not).
func h2Server(t *testing.T, enableH2 bool, h http.Handler) (addr, caPath string) {
	t.Helper()
	cfg, ca := selfSigned(t)
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.TLS = cfg
	srv.EnableHTTP2 = enableH2
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), ca
}

func orders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Setura-Backend", "orders-v1")
	if !strings.HasPrefix(r.Host, "orders.mactra.test:") || r.URL.RequestURI() != "/checkout?q=1" {
		w.WriteHeader(404)
		return
	}
	io.WriteString(w, r.Proto)
}

func TestHTTP2Probe(t *testing.T) {
	addr, ca := h2Server(t, true, http.HandlerFunc(orders))
	_, port, _ := net.SplitHostPort(addr)
	o := NewProbe("https://orders.mactra.test:" + port + "/checkout?q=1")
	o.Address, o.CA, o.HTTP2, o.Backend, o.BodyContains = "127.0.0.1", ca, true, "orders-v1", "HTTP/2.0"
	r, err := Probe(o)
	if err != nil || !r.OK {
		t.Fatalf("%v %+v", err, r)
	}
	is(t, r.Step("dns").State(), "overridden")
	is(t, r.Step("tls").Get("alpn"), "h2")
	is(t, r.Step("http").Get("proto"), "HTTP/2.0")
	is(t, r.Step("backend").State(), "ok")
	// wrong TLS identity is still rejected over h2
	o.URL = "https://wrong.mactra.test:" + port + "/checkout?q=1"
	r, _ = Probe(o)
	is(t, r.OK, false)
	is(t, r.Step("tls").State(), "failed")
}

func TestHTTP2NotNegotiated(t *testing.T) {
	addr, ca := h2Server(t, false, http.HandlerFunc(orders))
	_, port, _ := net.SplitHostPort(addr)
	o := NewProbe("https://orders.mactra.test:" + port + "/checkout?q=1")
	o.Address, o.CA, o.HTTP2 = "127.0.0.1", ca, true
	r, err := Probe(o)
	if err != nil {
		t.Fatal(err)
	}
	is(t, r.OK, false)
	is(t, r.Step("tls").State(), "failed")
	contains(t, asStr(r.Step("tls").Get("reason")), "did not negotiate h2")
	is(t, r.Step("http").State(), "untested")
	// plaintext URL with --http2 is a usage error
	o.URL = "http://orders.mactra.test/"
	if _, err := Probe(o); err == nil {
		t.Fatal("http2 over plaintext accepted")
	}
}

func TestHTTP2CLIAndCheck(t *testing.T) {
	addr, ca := h2Server(t, true, http.HandlerFunc(orders))
	_, port, _ := net.SplitHostPort(addr)
	url := "https://orders.mactra.test:" + port + "/checkout?q=1"
	code, out, errs := cli(t, nil, "explain", url, "--address", "127.0.0.1", "--ca", ca, "--http2")
	if code != 0 || !strings.Contains(out, "alpn=h2") {
		t.Fatalf("exit %d %s %s", code, out, errs)
	}
	path := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(path, []byte(`[{"url":"`+url+`","address":"127.0.0.1","ca":"`+ca+`","http2":true}]`), 0o600)
	if code, out, _ := cli(t, nil, "check", path); code != 0 || !strings.Contains(out, `"alpn": "h2"`) {
		t.Fatalf("exit %d %s", code, out)
	}
	os.WriteFile(path, []byte(`[{"url":"`+url+`","http2":"yes"}]`), 0o600)
	if code, _, _ := cli(t, nil, "check", path); code != 2 {
		t.Fatalf("non-bool http2 accepted: %d", code)
	}
}

func TestProtoCodec(t *testing.T) {
	frame := encodeHealthRequest("svc")
	is(t, len(frame), 5+2+3)
	is(t, binary.BigEndian.Uint32(frame[1:5]), 5)
	is(t, string(frame[5:]), "\x0a\x03svc")
	is(t, len(encodeHealthRequest("")), 5)
	st, err := decodeHealthResponse([]byte{0, 0, 0, 0, 2, 0x08, 2})
	is(t, st, 2)
	is(t, err, nil)
	if _, err := decodeHealthResponse([]byte{0, 0, 0, 0, 9, 8}); err == nil {
		t.Fatal("truncated message accepted")
	}
	if _, err := decodeHealthResponse(nil); err == nil {
		t.Fatal("empty body accepted")
	}
}

// healthHandler speaks grpc.health.v1.Health/Check: "" and "ok" are SERVING,
// "down" is NOT_SERVING and anything else is a NOT_FOUND trailers-only reply.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != healthPath || r.Method != "POST" || r.Header.Get("Content-Type") != "application/grpc" || r.ProtoMajor != 2 {
		w.WriteHeader(404)
		return
	}
	body, _ := io.ReadAll(r.Body)
	service := ""
	if len(body) > 7 && body[5] == 0x0a {
		service = string(body[7 : 7+int(body[6])])
	}
	w.Header().Set("Content-Type", "application/grpc")
	var status byte
	switch service {
	case "", "ok":
		status = 1
	case "down":
		status = 2
	default:
		w.Header().Set("Grpc-Status", "5")
		w.Header().Set("Grpc-Message", "unknown service")
		w.WriteHeader(200)
		return
	}
	w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
	w.Write([]byte{0, 0, 0, 0, 2, 0x08, status})
	w.Header().Set("Grpc-Status", "0")
	w.Header().Set("Grpc-Message", "")
}

func TestGRPCHealthChecksIdentity(t *testing.T) {
	addr, ca := h2Server(t, true, http.HandlerFunc(healthHandler))
	// The test certificate names orders.mactra.test only, so verifying it
	// against 127.0.0.1 must fail.
	res, err := GRPCHealth(GRPCHealthOptions{Target: addr, CA: ca, Timeout: 4})
	if err != nil {
		t.Fatal(err)
	}
	is(t, res["ok"], false)
	contains(t, asStr(res["error"]), "certificate")
}

func TestGRPCHealthServing(t *testing.T) {
	addr, ca := h2Server(t, true, http.HandlerFunc(healthHandler))
	_, port, _ := net.SplitHostPort(addr)
	withHostMap(t, "orders.mactra.test", "127.0.0.1")
	target := "orders.mactra.test:" + port
	for service, want := range map[string]string{"": "SERVING", "ok": "SERVING", "down": "NOT_SERVING"} {
		res, err := GRPCHealth(GRPCHealthOptions{Target: target, Service: service, CA: ca, Timeout: 4})
		if err != nil {
			t.Fatal(err)
		}
		is(t, res["status"], want)
		is(t, res["grpc_status"], 0)
		is(t, res["alpn"], "h2")
		is(t, res["ok"], want == "SERVING")
	}
	res, _ := GRPCHealth(GRPCHealthOptions{Target: target, Service: "nope", CA: ca, Timeout: 4})
	is(t, res["ok"], false)
	is(t, res["grpc_status"], 5)
	contains(t, asStr(res["error"]), "grpc-status 5")

	code, out, errs := cli(t, nil, "grpc-health", target, "--ca", ca, "--json")
	if code != 0 || !strings.Contains(out, `"status": "SERVING"`) {
		t.Fatalf("exit %d %s %s", code, out, errs)
	}
	code, out, _ = cli(t, nil, "grpc-health", target, "--ca", ca, "--service", "down")
	is(t, code, 1)
	contains(t, out, "NOT_SERVING")
	if code, _, _ := cli(t, nil, "grpc-health", target, "--tls=false"); code != 2 {
		t.Fatalf("plaintext accepted: %d", code)
	}
	if code, _, _ := cli(t, nil, "grpc-health", "nohostport"); code != 2 {
		t.Fatalf("bad target accepted: %d", code)
	}
}

func TestGRPCHealthNeedsH2(t *testing.T) {
	addr, ca := h2Server(t, false, http.HandlerFunc(healthHandler))
	_, port, _ := net.SplitHostPort(addr)
	withHostMap(t, "orders.mactra.test", "127.0.0.1")
	res, err := GRPCHealth(GRPCHealthOptions{Target: "orders.mactra.test:" + port, CA: ca, Timeout: 4})
	if err != nil {
		t.Fatal(err)
	}
	is(t, res["ok"], false)
	if e := asStr(res["error"]); e == "" {
		t.Fatal("expected an error")
	}
}

func TestBench(t *testing.T) {
	var hits int64
	url := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt64(&hits, 1)
		if r.URL.Path == "/flaky" && n%2 == 0 {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path == "/slow" {
			time.Sleep(30 * time.Millisecond)
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()
	url = "http://orders.mactra.test:" + strings.Split(srv.Listener.Addr().String(), ":")[1]
	withHostMap(t, "orders.mactra.test", "127.0.0.1")

	code, m := cliJSON(t, "bench", url+"/", "--requests", "20", "--concurrency", "4", "--json")
	is(t, code, 0)
	is(t, m["requests"], 20)
	is(t, m["errors"], 0)
	is(t, asMap(m["status"])["200"], 20)
	for _, k := range []string{"p50", "p90", "p99", "max"} {
		if _, ok := asMap(m["latency_ms"])[k]; !ok {
			t.Fatalf("missing %s", k)
		}
	}
	is(t, atomic.LoadInt64(&hits), 20)

	code, m = cliJSON(t, "bench", url+"/flaky", "--requests", "10", "--concurrency", "1", "--max-error-rate", "0.1", "--json")
	is(t, code, 1)
	is(t, m["ok"], false)
	is(t, asMap(m["status"])["503"], 5)
	contains(t, asStr(asList(m["violations"])[0]), "error rate")
	if code, _ := cliJSON(t, "bench", url+"/flaky", "--requests", "10", "--max-error-rate", "0.9", "--json"); code != 0 {
		t.Fatalf("within budget exit %d", code)
	}

	code, m = cliJSON(t, "bench", url+"/slow", "--requests", "4", "--concurrency", "2", "--max-p99-ms", "5", "--json")
	is(t, code, 1)
	contains(t, asStr(asList(m["violations"])[0]), "p99")

	code, m = cliJSON(t, "bench", url+"/", "--duration", "150ms", "--concurrency", "2", "--json")
	is(t, code, 0)
	if n, _ := num(m["requests"]); n < 2 {
		t.Fatalf("duration run issued %v requests", n)
	}

	code, out, _ := cli(t, nil, "bench", url+"/", "--requests", "3")
	is(t, code, 0)
	contains(t, out, "p99=")
	for _, args := range [][]string{{"bench"}, {"bench", url, "--concurrency", "0"}, {"bench", "ftp://x/"}, {"bench", url, "--http2"}} {
		if code, _, _ := cli(t, nil, args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestBenchHTTP2(t *testing.T) {
	addr, ca := h2Server(t, true, http.HandlerFunc(orders))
	_, port, _ := net.SplitHostPort(addr)
	url := "https://orders.mactra.test:" + port + "/checkout?q=1"
	code, m := cliJSON(t, "bench", url, "--address", "127.0.0.1", "--ca", ca, "--http2", "--requests", "6", "--concurrency", "3", "--json")
	is(t, code, 0)
	is(t, asMap(m["status"])["200"], 6)
}

func TestPercentile(t *testing.T) {
	s := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	is(t, percentile(s, 50), 5)
	is(t, percentile(s, 90), 9)
	is(t, percentile(s, 99), 10)
	is(t, percentile(s, 100), 10)
	is(t, percentile(nil, 50), 0)
}

// withHostMap resolves one name to ip for Probe (lookupIP) and GRPCHealth
// (grpcDialHost) without touching DNS.
func withHostMap(t *testing.T, name, ip string) {
	t.Helper()
	oldLookup, oldDial := lookupIP, grpcDialHost
	lookupIP = func(h string) ([]string, error) {
		if h == name {
			return []string{ip}, nil
		}
		return oldLookup(h)
	}
	grpcDialHost = func(h string) string {
		if h == name {
			return ip
		}
		return h
	}
	t.Cleanup(func() { lookupIP, grpcDialHost = oldLookup, oldDial })
}
