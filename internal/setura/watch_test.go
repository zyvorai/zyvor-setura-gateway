package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTicks returns a ticker source pre-loaded with n ticks.
func fakeTicks(n int) func(time.Duration) (<-chan time.Time, func()) {
	return func(time.Duration) (<-chan time.Time, func()) {
		c := make(chan time.Time, n)
		for i := 0; i < n; i++ {
			c <- time.Unix(int64(i), 0)
		}
		return c, func() {}
	}
}

func flipServer(t *testing.T, goodFor int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Setura-Backend", "orders-v1")
		if n.Add(1) > goodFor {
			w.WriteHeader(500)
			return
		}
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestWatchFlipEmitsExactlyOneChange(t *testing.T) {
	srv, _ := flipServer(t, 2)
	var out bytes.Buffer
	w := newWatcher([]ProbeOptions{NewProbe(srv.URL + "/")}, time.Second, &out)
	w.newTick = fakeTicks(10)
	w.count = 5
	var evs []WatchEvent
	w.OnEvent = func(e WatchEvent) { evs = append(evs, e) }
	failing, err := w.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !failing {
		t.Fatal("last state should be failing")
	}
	changes := 0
	for _, e := range evs {
		if e.Kind == "change" {
			changes++
			contains(t, e.Text, "ok -> failed at http")
			contains(t, e.Text, "received 500")
		}
	}
	is(t, changes, 1)
	is(t, len(evs), 2) // baseline plus the one change
	w.summary()
	contains(t, out.String(), "probes=5 failed=3 changes=1 last=failed at http")
}

func TestWatchRecoveryAndBackendIdentity(t *testing.T) {
	w := newWatcher(nil, time.Second, io.Discard)
	mk := func(ok bool, backend string) *Report {
		r := &Report{URL: "http://x/", OK: ok, Steps: map[string]*Step{}}
		for _, n := range stages {
			r.Steps[n] = &Step{{"state", "ok"}}
		}
		r.Steps["backend"] = &Step{{"state", "ok"}, {"identity", backend}}
		if !ok {
			r.Steps["tcp"] = &Step{{"state", "failed"}, {"reason", "refused"}}
		}
		return r
	}
	is(t, len(w.observe(mk(true, "a"))), 1) // initial
	is(t, len(w.observe(mk(true, "a"))), 0)
	e := w.observe(mk(true, "b"))
	is(t, len(e), 1)
	contains(t, e[0].Text, `"a" -> "b"`)
	e = w.observe(mk(false, "b"))
	contains(t, e[0].Text, "failed at tcp")
	is(t, len(w.observe(mk(false, "b"))), 0)
	e = w.observe(mk(true, "b"))
	contains(t, e[0].Text, "failed -> ok")
}

func TestWatchDurationStops(t *testing.T) {
	srv, _ := flipServer(t, 100)
	w := newWatcher([]ProbeOptions{NewProbe(srv.URL + "/")}, time.Second, io.Discard)
	w.newTick = fakeTicks(0) // never ticks
	w.duration = time.Minute
	fired := make(chan time.Time, 1)
	fired <- time.Now()
	w.after = func(time.Duration) <-chan time.Time { return fired }
	failing, err := w.Run(context.Background())
	if err != nil || failing {
		t.Fatalf("failing=%v err=%v", failing, err)
	}
}

func TestWatchContextCancelExitsCleanly(t *testing.T) {
	srv, _ := flipServer(t, 100)
	w := newWatcher([]ProbeOptions{NewProbe(srv.URL + "/")}, time.Second, io.Discard)
	w.newTick = fakeTicks(0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failing, err := w.Run(ctx)
	if err != nil || failing {
		t.Fatalf("failing=%v err=%v", failing, err)
	}
}

func TestWatchHistoryAndMetrics(t *testing.T) {
	srv, _ := flipServer(t, 1)
	hist := filepath.Join(t.TempDir(), "h.jsonl")
	f, err := os.OpenFile(hist, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	target := srv.URL + "/"
	w := newWatcher([]ProbeOptions{NewProbe(target)}, time.Second, io.Discard)
	w.newTick, w.count, w.history, w.metrics = fakeTicks(5), 3, f, newMetricsStore()
	if _, err := w.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.Close()
	raw, _ := os.ReadFile(hist)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	is(t, len(lines), 3)
	var first, last map[string]any
	json.Unmarshal([]byte(lines[0]), &first)
	json.Unmarshal([]byte(lines[2]), &last)
	is(t, first["ok"], true)
	is(t, first["target"], target)
	is(t, last["ok"], false)
	is(t, last["failing_stage"], "http")
	if _, err := time.Parse(time.RFC3339, last["time"].(string)); err != nil {
		t.Fatal(err)
	}
	if _, ok := last["elapsed_ms"].(float64); !ok {
		t.Fatal("elapsed_ms missing")
	}

	// Scrape the real endpoint on loopback.
	addr, stop, err := serveMetrics("127.0.0.1:0", false, w.metrics)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	contains(t, resp.Header.Get("Content-Type"), "version=0.0.4")
	text := string(body)
	contains(t, text, `setura_probe_up{target="`+target+`"} 0`)
	contains(t, text, `setura_probe_duration_seconds{target="`+target+`"} `)
	contains(t, text, `setura_probe_stage_ok{target="`+target+`",stage="tcp"} 1`)
	contains(t, text, `setura_probe_stage_ok{target="`+target+`",stage="http"} 0`)
	contains(t, text, `setura_probe_total{target="`+target+`",result="ok"} 1`)
	contains(t, text, `setura_probe_total{target="`+target+`",result="failed"} 2`)
	hz, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	hz.Body.Close()
	is(t, hz.StatusCode, 200)
}

func TestMetricsLabelEscaping(t *testing.T) {
	is(t, promLabel("a\"b\\c\nd"), `a\"b\\c\nd`)
}

func TestListenRefusesNonLoopback(t *testing.T) {
	for _, a := range []string{"0.0.0.0:9464", ":9464", "192.0.2.1:9464", "example.com:1"} {
		if err := checkListenAddr(a, false); err == nil {
			t.Fatalf("%s should be refused", a)
		}
	}
	for _, a := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		if err := checkListenAddr(a, false); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
	if err := checkListenAddr("0.0.0.0:0", true); err != nil {
		t.Fatal(err)
	}
	code, _, errs := cli(t, nil, "watch", "--listen", "0.0.0.0:9464", "--count", "1", "http://127.0.0.1:1/")
	is(t, code, 2)
	contains(t, errs, "allow-remote")
}

func TestWatchCLI(t *testing.T) {
	srv, _ := flipServer(t, 1000)
	code, out, _ := cli(t, nil, "watch", "--count", "1", srv.URL+"/")
	is(t, code, 0)
	contains(t, out, "summary: 1 target(s)")

	bad := httptest.NewServer(http.NotFoundHandler())
	defer bad.Close()
	code, out, _ = cli(t, nil, "watch", "--count", "1", bad.URL+"/")
	is(t, code, 1)
	contains(t, out, "failed at http")

	file := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(file, []byte(`[{"url":"`+srv.URL+`/","backend":"orders-v1"}]`), 0o600)
	code, out, _ = cli(t, nil, "watch", "--file", file, "--count", "1")
	is(t, code, 0)
	contains(t, out, "backend=orders-v1")

	code, _, _ = cli(t, nil, "watch")
	is(t, code, 2)
	code, _, errs := cli(t, nil, "watch", "--interval", "100ms", srv.URL+"/")
	is(t, code, 2)
	contains(t, errs, "at least 1s")
	code, _, _ = cli(t, nil, "watch", "--count", "1", "ftp://nope")
	is(t, code, 2)
}
