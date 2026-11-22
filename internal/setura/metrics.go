package setura

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// metricsStore holds the latest probe result per target for the /metrics endpoint.
type metricsStore struct {
	mu      sync.Mutex
	targets map[string]*targetMetrics
}

type targetMetrics struct {
	up       bool
	duration float64 // seconds
	stages   map[string]bool
	okTotal  int
	failTot  int
}

func newMetricsStore() *metricsStore { return &metricsStore{targets: map[string]*targetMetrics{}} }

// Record stores one probe result.
func (m *metricsStore) Record(r *Report) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.targets[r.URL]
	if t == nil {
		t = &targetMetrics{}
		m.targets[r.URL] = t
	}
	t.up, t.duration, t.stages = r.OK, r.ElapsedMS/1000, map[string]bool{}
	for _, name := range stages {
		switch r.Step(name).State() {
		case "ok", "overridden":
			t.stages[name] = true
		case "failed":
			t.stages[name] = false
		}
	}
	if r.OK {
		t.okTotal++
	} else {
		t.failTot++
	}
}

func promLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func b2f(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Render writes the Prometheus text exposition format (version 0.0.4).
func (m *metricsStore) Render() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.targets))
	for k := range m.targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("# HELP setura_probe_up Whether the last probe of the target passed (1) or failed (0).\n# TYPE setura_probe_up gauge\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "setura_probe_up{target=\"%s\"} %d\n", promLabel(k), b2f(m.targets[k].up))
	}
	b.WriteString("# HELP setura_probe_duration_seconds Duration of the last probe.\n# TYPE setura_probe_duration_seconds gauge\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "setura_probe_duration_seconds{target=\"%s\"} %g\n", promLabel(k), m.targets[k].duration)
	}
	b.WriteString("# HELP setura_probe_stage_ok Whether a stage of the last probe passed (1) or failed (0); untested and unused stages are omitted.\n# TYPE setura_probe_stage_ok gauge\n")
	for _, k := range keys {
		for _, name := range stages {
			if ok, seen := m.targets[k].stages[name]; seen {
				fmt.Fprintf(&b, "setura_probe_stage_ok{target=\"%s\",stage=\"%s\"} %d\n", promLabel(k), name, b2f(ok))
			}
		}
	}
	b.WriteString("# HELP setura_probe_total Probes run, by result.\n# TYPE setura_probe_total counter\n")
	for _, k := range keys {
		t := m.targets[k]
		fmt.Fprintf(&b, "setura_probe_total{target=\"%s\",result=\"ok\"} %d\n", promLabel(k), t.okTotal)
		fmt.Fprintf(&b, "setura_probe_total{target=\"%s\",result=\"failed\"} %d\n", promLabel(k), t.failTot)
	}
	return b.String()
}

// Handler serves /metrics and /healthz.
func (m *metricsStore) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprint(w, m.Render())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// checkListenAddr refuses non-loopback bind addresses unless allowRemote is set.
func checkListenAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return userErrorf("invalid --listen address %q: %v", addr, err)
	}
	if allowRemote {
		return nil
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return userErrorf("--listen %q is not a loopback address; pass --allow-remote to expose metrics beyond this host", addr)
}

// serveMetrics binds addr and serves the store until the returned stop is called.
func serveMetrics(addr string, allowRemote bool, m *metricsStore) (bound string, stop func(), err error) {
	if err := checkListenAddr(addr, allowRemote); err != nil {
		return "", nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, err
	}
	srv := &http.Server{Handler: m.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { _ = srv.Close() }, nil
}
