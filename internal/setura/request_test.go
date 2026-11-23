package setura

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type seenRequest struct {
	method, host, origin string
	hdr                  http.Header
}

func captureServer(t *testing.T) (*httptest.Server, func() seenRequest) {
	t.Helper()
	var mu sync.Mutex
	var last seenRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		last = seenRequest{r.Method, r.Host, r.Header.Get("Origin"), r.Header.Clone()}
		mu.Unlock()
		w.Header().Set("X-Setura-Backend", "b1")
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	return srv, func() seenRequest { mu.Lock(); defer mu.Unlock(); return last }
}

func TestProbeSendsMethodAndRequestHeaders(t *testing.T) {
	srv, seen := captureServer(t)
	o := NewProbe(srv.URL + "/p?q=1")
	o.Status = 204
	o.Method = "options"
	o.RequestHeaders = map[string]string{"Origin": "https://app.example", "X-Canary": "always"}
	r, err := Probe(o)
	if err != nil || !r.OK {
		t.Fatalf("probe: %v %+v", err, r)
	}
	got := seen()
	if got.method != "OPTIONS" || got.origin != "https://app.example" || got.hdr.Get("X-Canary") != "always" {
		t.Errorf("request not shaped: %+v", got)
	}
	if got.hdr.Get("User-Agent") != "zyvor-setura" {
		t.Errorf("default user agent missing: %v", got.hdr)
	}

	o.Method, o.RequestHeaders = "HEAD", map[string]string{"User-Agent": "custom"}
	if r, err = Probe(o); err != nil || !r.OK {
		t.Fatalf("HEAD probe: %v %+v", err, r)
	}
	if got = seen(); got.method != "HEAD" || got.hdr.Get("User-Agent") != "custom" {
		t.Errorf("HEAD or user-agent override: %+v", got)
	}

	o.Method, o.AllowUnsafeMethod, o.RequestHeaders = "POST", true, nil
	if r, err = Probe(o); err != nil || !r.OK {
		t.Fatalf("POST probe: %v %+v", err, r)
	}
	if got = seen(); got.method != "POST" || got.hdr.Get("Content-Length") != "0" {
		t.Errorf("POST must carry an empty body: %+v", got)
	}
}

func TestRequestValidationHostile(t *testing.T) {
	long := strings.Repeat("a", maxRequestHeaderValue+1)
	many := map[string]string{}
	for i := 0; i <= maxRequestHeaders; i++ {
		many["X-H"+strings.Repeat("a", i)] = "v"
	}
	big := map[string]string{}
	for i := 0; i < 10; i++ {
		big["X-Big-"+string(rune('a'+i))] = strings.Repeat("b", maxRequestHeaderValue)
	}
	cases := map[string]struct {
		method string
		unsafe bool
		hdr    map[string]string
		want   string
	}{
		"CRLF injection in value":   {"", false, map[string]string{"X-A": "v\r\nX-Evil: 1"}, "control character"},
		"newline injection":         {"", false, map[string]string{"X-A": "v\nX"}, "control character"},
		"NUL in value":              {"", false, map[string]string{"X-A": "v\x00"}, "control character"},
		"DEL in value":              {"", false, map[string]string{"X-A": "v\x7f"}, "control character"},
		"colon in name":             {"", false, map[string]string{"X:A": "v"}, "invalid character"},
		"space in name":             {"", false, map[string]string{"X A": "v"}, "invalid character"},
		"CRLF in name":              {"", false, map[string]string{"X\r\nEvil": "v"}, "invalid character"},
		"empty name":                {"", false, map[string]string{"": "v"}, "1 to"},
		"host override":             {"", false, map[string]string{"host": "evil.test"}, "cannot be overridden"},
		"content length":            {"", false, map[string]string{"Content-Length": "5"}, "cannot be overridden"},
		"transfer encoding":         {"", false, map[string]string{"Transfer-Encoding": "chunked"}, "cannot be overridden"},
		"connection":                {"", false, map[string]string{"CONNECTION": "keep-alive"}, "cannot be overridden"},
		"upgrade":                   {"", false, map[string]string{"Upgrade": "websocket"}, "cannot be overridden"},
		"case duplicate":            {"", false, map[string]string{"x-a": "1", "X-A": "2"}, "given twice"},
		"value too long":            {"", false, map[string]string{"X-A": long}, "longer than"},
		"too many headers":          {"", false, many, "at most"},
		"total size":                {"", false, big, "total more than"},
		"CONNECT":                   {"CONNECT", true, nil, "unsupported method"},
		"TRACE":                     {"TRACE", true, nil, "unsupported method"},
		"method with space":         {"GET /x", true, nil, "unsupported method"},
		"POST without confirmation": {"POST", false, nil, "allow-unsafe-method"},
		"DELETE without":            {"delete", false, nil, "allow-unsafe-method"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			o := NewProbe("http://127.0.0.1:1/")
			o.Method, o.AllowUnsafeMethod, o.RequestHeaders = c.method, c.unsafe, c.hdr
			_, err := Probe(o)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
			if strings.Contains(err.Error(), "evil.test") || strings.Contains(err.Error(), "X-Evil") {
				t.Errorf("error echoes a header value: %v", err)
			}
		})
	}
}

func TestRequestHeaderFlagsAndCheckKeys(t *testing.T) {
	if m, err := parseRequestHeaderFlags([]string{"X-A: 1", "X-B:2"}); err != nil || m["X-A"] != "1" || m["X-B"] != "2" {
		t.Errorf("flags: %v %v", m, err)
	}
	for _, bad := range [][]string{{"nocolon"}, {": v"}, {"X-A: 1", "X-A: 2"}} {
		if _, err := parseRequestHeaderFlags(bad); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
	for name, m := range map[string]obj{
		"method type":  {"method": 5},
		"unsafe type":  {"allow_unsafe_method": "yes"},
		"headers type": {"request_headers": []any{"a"}},
		"value type":   {"request_headers": obj{"X-A": 1}},
	} {
		var o ProbeOptions
		if err := applyCheckRequest(m, &o); err == nil {
			t.Errorf("%s should be refused", name)
		}
	}

	srv, seen := captureServer(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "checks.json")
	body := `[{"url":"` + srv.URL + `/","status":204,"method":"OPTIONS","request_headers":{"Origin":"https://a.test"},"headers":{"X-Setura-Backend":"b1"}}]`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := Check(file)
	if err != nil || len(rows) != 1 || !rows[0].OK {
		t.Fatalf("check file: %v %+v", err, rows)
	}
	if got := seen(); got.method != "OPTIONS" || got.origin != "https://a.test" {
		t.Errorf("check case did not shape the request: %+v", got)
	}
	opts, err := parseWatchFile(file)
	if err != nil || len(opts) != 1 || opts[0].Method != "OPTIONS" || opts[0].RequestHeaders["Origin"] == "" {
		t.Errorf("watch file: %v %+v", err, opts)
	}
}

func TestProbeRequestShapeOverHTTP2(t *testing.T) {
	var mu sync.Mutex
	var method, canary string
	var major int
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		method, canary, major = r.Method, r.Header.Get("X-Canary"), r.ProtoMajor
		mu.Unlock()
		w.WriteHeader(204)
	}))
	cfg, ca := selfSigned(t)
	cfg.NextProtos = []string{"h2", "http/1.1"}
	srv.TLS = cfg
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	o := NewProbe(strings.Replace(srv.URL, "127.0.0.1", "orders.mactra.test", 1) + "/")
	o.Address = "127.0.0.1"
	o.CA, o.HTTP2, o.Status = ca, true, 204
	o.Method, o.RequestHeaders = "OPTIONS", map[string]string{"X-Canary": "yes"}
	r, err := Probe(o)
	if err != nil || !r.OK {
		t.Fatalf("h2 probe: %v %+v", err, r)
	}
	mu.Lock()
	defer mu.Unlock()
	if method != "OPTIONS" || canary != "yes" || major != 2 {
		t.Errorf("h2 request: method=%s canary=%s major=%d", method, canary, major)
	}
}
