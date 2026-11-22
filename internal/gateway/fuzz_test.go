package gateway

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Native fuzz targets for the parsers that take untrusted input. `go test`
// runs every seed (the f.Add values here and the files under
// testdata/fuzz/<Target>), which is what CI does; to explore, run for example
//
//	go test ./internal/gateway -run '^$' -fuzz FuzzParseConfig -fuzztime 30s
//
// A crash is saved by the fuzzer under testdata/fuzz/<Target> and from then on
// is a regression seed. Set SETURA_WRITE_SEEDS=1 to (re)write the committed
// seed files from the inline seeds, see TestWriteFuzzSeeds.

// helloBytes captures the first TLS record a real client sends.
func helloBytes(sni string, alpn ...string) []byte {
	c, s := net.Pipe()
	defer s.Close()
	go func() {
		tls.Client(c, &tls.Config{ServerName: sni, NextProtos: alpn, InsecureSkipVerify: true}).Handshake()
		c.Close()
	}()
	s.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, _ := s.Read(buf)
	return buf[:n]
}

var configSeeds = func() [][]byte {
	seeds := [][]byte{
		[]byte(`{}`),
		[]byte(`{"schema":"setura.route-specs/v1","resources":{}}`),
		[]byte(`{"schema":"setura.route-specs/v1","namespace":"t","resources":{"gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"web","protocol":"HTTP","port":8080,"hostname":"*.example.com"}]},"httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"hostnames":["a.example.com"],"rules":[{"matches":[{"path":{"type":"RegularExpression","value":"/a(b|c)+"},"headers":[{"name":"X","value":"y"}],"queryParams":[{"name":"q","type":"RegularExpression","value":"[0-9]+"}],"method":"GET"}],"backendRefs":[{"name":"app","port":80,"weight":3}]}]}},"backends":{"t/app:80":{"endpoints":["127.0.0.1:1"],"timeout":"5s"}}}`),
		[]byte(`{"schema":"setura.route-specs/v1","resources":{"httproutes.gateway.networking.k8s.io/r":{"rules":[{"filters":[{"type":"RequestMirror","requestMirror":{"backendRef":{"name":"x"}}}]}]}}}`),
		[]byte(`{"schema":"setura.route-specs/v1","resources":{"gateways.gateway.networking.k8s.io/gw":{"listeners":[{"name":"t","protocol":"HTTPS","port":8443,"tls":{"mode":"Terminate","certificateRefs":[{"name":"missing"}]}}]}},"secrets":{"missing":{"certFile":"../../etc/passwd","keyFile":"/nonexistent"}}}`),
	}
	if b, err := os.ReadFile("../../examples/builtin-demo.json"); err == nil {
		seeds = append(seeds, b)
	}
	if b, err := os.ReadFile("../../examples/grpc-tls-routes.json"); err == nil {
		seeds = append(seeds, b)
	}
	return seeds
}()

func FuzzParseConfig(f *testing.F) {
	for _, s := range configSeeds {
		f.Add(s)
	}
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, raw []byte) {
		cfg, err := ParseConfig(raw, dir)
		if err != nil {
			return
		}
		tb := BuildTable(cfg) // a parsed config must always resolve to a table
		for _, pg := range tb.Ports {
			for _, l := range pg.Listeners {
				_ = l.Host
			}
		}
		cfg.Dump()
	})
}

func FuzzHostMatching(f *testing.F) {
	for _, s := range [][3]string{
		{"*.example.com", "a.example.com", "A.Example.COM:8080"},
		{"example.com", "example.com", "example.com."},
		{"", "x", "[::1]:80"},
		{"*.", "", "[::1"},
		{"*.a.b", "x.a.b", ":::"},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, pattern, host, header string) {
		h := hostOnly(header)
		if strings.ContainsAny(h, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Fatalf("hostOnly(%q) = %q is not lowercase", header, h)
		}
		if hostMatches(pattern, host) && pattern != "" && !strings.HasPrefix(pattern, "*.") && pattern != host {
			t.Fatalf("hostMatches(%q, %q) matched without being equal", pattern, host)
		}
		_ = hostRank(pattern)
		intersect(pattern, host)
		intersect(host, pattern)
	})
}

func FuzzPathMatching(f *testing.F) {
	for _, s := range [][5]string{
		{"PathPrefix", "/api", "/api/v1", "GET", "x-env=prod"},
		{"Exact", "/a", "/a/", "POST", ""},
		{"RegularExpression", "/u/[0-9]+(/.*)?", "/u/12/x", "", "x=1"},
		{"RegularExpression", "(", "/", "", ""},
		{"PathPrefix", "/", "//%2e%2e/x?y=1", "get", "a=b=c"},
		{"", "", "", "", ""},
	} {
		f.Add(s[0], s[1], s[2], s[3], s[4])
	}
	f.Fuzz(func(t *testing.T, typ, value, target, method, hdr string) {
		if len(value) > 256 { // keep regex compilation cheap
			return
		}
		k, v, _ := strings.Cut(hdr, "=")
		m, err := compileMatch(Match{Path: &PathMatch{Type: typ, Value: value}, Method: method,
			Headers: []ValueMatch{{Name: k, Value: v}}, QueryParams: []ValueMatch{{Name: k, Value: v, Type: typ}}})
		if err != nil {
			return
		}
		req, err := http.NewRequest("GET", "http://x.test/", nil)
		if err != nil {
			return
		}
		req.URL.Path, req.URL.RawQuery = target, hdr
		if k != "" && !strings.ContainsAny(k, " \r\n:") {
			req.Header[k] = []string{v}
		}
		var why string
		m.matchesWhy(req, &why)
		m.matches(req)
		prefixMatches(value, target)
	})
}

func FuzzJSONPath(f *testing.F) {
	for _, s := range []string{"$", "$.a", "$.a.b[0]", "$.items[*].name", "$..x", "$['a b']", "$.a[", "$[", "a.b", "$.a[-1]", "$.a[99999999999999999999]", ""} {
		f.Add(s)
	}
	doc := map[string]any{"a": map[string]any{"b": []any{1.0, "x", nil, map[string]any{"c": true}}}, "items": []any{map[string]any{"name": "n"}}}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := parseJSONPath(s)
		if err != nil {
			return
		}
		p.prune(doc)
	})
}

func FuzzTraceparent(f *testing.F) {
	for _, s := range []string{
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01",
		"ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7", "", "-", "----",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, parent, flags, ok := parseTraceparent(s)
		if ok && (len(id) != 32 || len(parent) != 16 || len(flags) != 2 || allZero(id) || allZero(parent) || !isHex(id+parent+flags)) {
			t.Fatalf("accepted %q as %q %q %q", s, id, parent, flags)
		}
		h := http.Header{}
		h.Set("Traceparent", s)
		h.Set("X-Request-Id", s)
		tr := newTrace(h)
		if len(tr.TraceID) != 32 || len(tr.SpanID) != 16 {
			t.Fatalf("newTrace(%q) produced %+v", s, tr)
		}
		validRequestID(s)
	})
}

func FuzzClientHello(f *testing.F) {
	h := helloBytes("app.example.com", "h2", "http/1.1")
	f.Add(h)
	f.Add(helloBytes("", "h2"))
	f.Add(helloBytes("a.b"))
	if len(h) > 9 {
		f.Add(h[5:]) // the bare handshake message
		f.Add(h[:len(h)/2])
	}
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01})
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseClientHelloALPN(b)
		raw, _, _, _ := readClientHelloALPN(bytes.NewReader(b))
		if len(raw) > len(b) {
			t.Fatalf("read %d bytes from a %d byte input", len(raw), len(b))
		}
		if len(raw) > 0 && !bytes.Equal(raw, b[:len(raw)]) {
			t.Fatal("raw is not a prefix of the input")
		}
	})
}

// TestWriteFuzzSeeds regenerates the committed seed files under testdata/fuzz
// from the inline seeds. It does nothing unless SETURA_WRITE_SEEDS=1.
func TestWriteFuzzSeeds(t *testing.T) {
	if os.Getenv("SETURA_WRITE_SEEDS") != "1" {
		t.Skip("set SETURA_WRITE_SEEDS=1 to rewrite testdata/fuzz")
	}
	write := func(target, name, body string) {
		dir := filepath.Join("testdata", "fuzz", target)
		os.MkdirAll(dir, 0o755)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("go test fuzz v1\n"+body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, s := range configSeeds {
		write("FuzzParseConfig", "seed"+strconv.Itoa(i), "[]byte("+strconv.Quote(string(s))+")")
	}
	hello := helloBytes("app.example.com", "h2", "http/1.1")
	write("FuzzClientHello", "seed-h2", "[]byte("+strconv.Quote(string(hello))+")")
	write("FuzzClientHello", "seed-truncated", "[]byte("+strconv.Quote(string(hello[:len(hello)/2]))+")")
	write("FuzzClientHello", "seed-nosni", "[]byte("+strconv.Quote(string(helloBytes("")))+")")
	for i, s := range []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x", "00-0-0-0"} {
		write("FuzzTraceparent", "seed"+strconv.Itoa(i), "string("+strconv.Quote(s)+")")
	}
	for i, s := range []string{"$.a.b[0].c", "$..items[*]", "$['x y'][", "$.a[99999999999999999999]"} {
		write("FuzzJSONPath", "seed"+strconv.Itoa(i), "string("+strconv.Quote(s)+")")
	}
	for i, s := range [][5]string{{"RegularExpression", "/u/[0-9]+(/.*)?", "/u/12/x", "GET", "x=1"}, {"PathPrefix", "/api", "/api2", "", ""}, {"Exact", "/a", "/a/", "post", "k=v"}} {
		write("FuzzPathMatching", "seed"+strconv.Itoa(i), "string("+strconv.Quote(s[0])+")\nstring("+strconv.Quote(s[1])+")\nstring("+strconv.Quote(s[2])+")\nstring("+strconv.Quote(s[3])+")\nstring("+strconv.Quote(s[4])+")")
	}
	for i, s := range [][3]string{{"*.example.com", "a.example.com", "A.Example.COM:8080"}, {"", "x", "[::1]:80"}, {"a.b", "a.b", "a.b."}} {
		write("FuzzHostMatching", "seed"+strconv.Itoa(i), "string("+strconv.Quote(s[0])+")\nstring("+strconv.Quote(s[1])+")\nstring("+strconv.Quote(s[2])+")")
	}
}
