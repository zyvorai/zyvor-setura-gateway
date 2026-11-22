package setura

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadGeneratorReportsKeepAliveRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			io.Copy(io.Discard, r.Body)
		}
		io.WriteString(w, "ok")
	}))
	defer srv.Close()

	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"goroutines":12,"heap_inuse_bytes":1048576,"rss_bytes":0,"num_gc":3}`)
	}))
	defer runtime.Close()

	out := filepath.Join(t.TempDir(), "load.json")
	code, m := cliJSON(t, "load", srv.URL+"/x", "--duration", "300ms", "--concurrency", "4", "--sample-url", runtime.URL,
		"--sample-interval", "100ms", "--json", "--json-out", out)
	is(t, code, 0)
	is(t, m["errors"], 0)
	if m["requests"].(float64) < 10 {
		t.Fatalf("too few requests: %v", m["requests"])
	}
	for _, k := range []string{"p50", "p90", "p99", "p99.9", "max"} {
		if _, ok := asMap(m["latency_ms"])[k]; !ok {
			t.Errorf("missing latency %s", k)
		}
	}
	if rt := asMap(m["runtime"]); rt["peak_goroutines"] != float64(12) {
		t.Errorf("runtime samples: %v", rt)
	}
	if b, err := os.ReadFile(out); err != nil || !strings.Contains(string(b), `"rps"`) {
		t.Errorf("json-out: %v %q", err, b)
	}

	code, m = cliJSON(t, "load", srv.URL, "--method", "POST", "--body-bytes", "100", "--duration", "100ms", "--concurrency", "2", "--status", "201", "--json")
	is(t, code, 1) // every response was 200, not the expected 201
	is(t, m["requests"], m["errors"])

	if code, _, _ := cli(t, nil, "load", srv.URL, "--concurrency", "0"); code != 2 {
		t.Errorf("concurrency 0 exit %d", code)
	}
	if code, _, _ := cli(t, nil, "load", "ftp://x"); code != 2 {
		t.Errorf("bad scheme exit %d", code)
	}
}

func TestLatencyHistogramQuantiles(t *testing.T) {
	var h latHist
	for us := int64(1); us <= 10000; us++ {
		h.add(us)
	}
	for p, want := range map[float64]float64{50: 5.0, 90: 9.0, 99: 9.9, 99.9: 9.99} {
		got := h.quantile(p)
		if got < want*0.9 || got > want*1.15 {
			t.Errorf("p%v = %v ms, want about %v", p, got, want)
		}
	}
	if h.quantile(100) != 10 {
		t.Errorf("max %v", h.quantile(100))
	}
}
