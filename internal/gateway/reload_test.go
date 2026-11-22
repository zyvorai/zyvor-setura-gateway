package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func configFor(be map[string]any, backend string, extra ...string) []byte {
	routes := map[string]m{"r": route("", rule("/", ref(backend, 1)))}
	for _, e := range extra {
		routes[e] = route("", rule("/"+e, ref(backend, 1)))
	}
	return snap(httpGateway(""), routes, be)
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestHotReloadUnderConcurrentLoad(t *testing.T) {
	be, _ := upstreams(t, "a", "b")
	path := filepath.Join(t.TempDir(), "cfg.json")
	writeFile(t, path, configFor(be, "a"))
	s, _, _ := startFile(t, path, nil)
	addr := s.Addr(8080)

	var fails, total atomic.Int64
	seen := sync.Map{}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// One transport per goroutine with one idle connection: eight long-lived
			// keep-alive connections that must survive every swap (a shared default
			// transport keeps only two idle conns per host and churns the rest).
			tr := &http.Transport{MaxIdleConnsPerHost: 1}
			defer tr.CloseIdleConnections()
			c := &http.Client{Timeout: 5 * time.Second, Transport: tr}
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := c.Get("http://" + addr + "/")
				if err != nil {
					fails.Add(1)
					t.Logf("request error: %v", err)
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				total.Add(1)
				var e echo
				json.Unmarshal(body, &e)
				seen.Store(e.Name, true)
				if resp.StatusCode != 200 {
					fails.Add(1)
					t.Logf("status %d", resp.StatusCode)
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		name := []string{"b", "a"}[i%2]
		// Read the generation BEFORE writing: if the poller applies the write first,
		// reading it afterwards would wait for a change that already happened.
		gen := s.Status().Generation
		writeFile(t, path, configFor(be, name, fmt.Sprintf("x%d", i)))
		waitFor(t, "reload", func() bool { return s.Status().Generation > gen })
	}
	close(stop)
	wg.Wait()
	if fails.Load() != 0 || total.Load() < 100 {
		t.Fatalf("%d failures out of %d requests", fails.Load(), total.Load())
	}
	for _, n := range []string{"a", "b"} {
		if _, ok := seen.Load(n); !ok {
			t.Errorf("never served by %s", n)
		}
	}
}

func TestReloadKeepsListenerSocket(t *testing.T) {
	be, _ := upstreams(t, "a", "b")
	path := filepath.Join(t.TempDir(), "cfg.json")
	writeFile(t, path, configFor(be, "a"))
	s, _, _ := startFile(t, path, nil)
	before := s.Addr(8080)
	c := &http.Client{} // a keep-alive connection opened before the swap
	get1 := func() string {
		resp, err := c.Get("http://" + before + "/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var e echo
		json.NewDecoder(resp.Body).Decode(&e)
		return e.Name
	}
	if get1() != "a" {
		t.Fatal("v1 should serve a")
	}
	gen := s.Status().Generation
	writeFile(t, path, configFor(be, "b"))
	waitFor(t, "reload", func() bool { return s.Status().Generation > gen })
	if got := get1(); got != "b" {
		t.Fatalf("existing connection served %q after swap, want b", got)
	}
	if s.Addr(8080) != before {
		t.Fatal("listener socket was replaced")
	}
}

func TestReloadAddsAndRemovesListeners(t *testing.T) {
	be, _ := upstreams(t, "a")
	path := filepath.Join(t.TempDir(), "cfg.json")
	writeFile(t, path, configFor(be, "a"))
	s, _, _ := startFile(t, path, func(o *Options) { o.PortMap[9090] = 0 })
	two := httpGateway("")
	two["listeners"] = append(two["listeners"].([]any), m{"name": "second", "protocol": "HTTP", "port": 9090})
	gen := s.Status().Generation
	writeFile(t, path, snap(two, map[string]m{"r": route("", rule("/", ref("a", 1)))}, be))
	waitFor(t, "second listener", func() bool { return s.Status().Generation > gen && s.Addr(9090) != "" })
	if r := req(t, client(s.Addr(9090), nil), "http", "GET", "x.test", "/", ""); r.Status != 200 {
		t.Fatalf("second listener status %d", r.Status)
	}
	gen = s.Status().Generation
	writeFile(t, path, configFor(be, "a"))
	waitFor(t, "second listener removal", func() bool { return s.Status().Generation > gen && s.Addr(9090) == "" })
}

func fakeLint(raw []byte) (bool, string) {
	if strings.Contains(string(raw), "LINTERROR") {
		return false, "ERROR SET001  route has no parents\n1 error(s), 0 warning(s)\n"
	}
	return true, ""
}

func TestLintGatedReload(t *testing.T) {
	be, _ := upstreams(t, "a", "b")
	path := filepath.Join(t.TempDir(), "cfg.json")
	writeFile(t, path, configFor(be, "a"))
	s, _, _ := startFile(t, path, func(o *Options) { o.Lint = fakeLint })
	gen := s.Status().Generation

	bad := configFor(be, "b")
	bad = []byte(strings.Replace(string(bad), `"schema"`, `"x-note":"LINTERROR","schema"`, 1))
	writeFile(t, path, bad)
	waitFor(t, "rejection", func() bool { return !s.Status().LastReload.OK })
	st := s.Status()
	if st.Generation != gen || !strings.Contains(st.LastReload.Error, "lint errors") || !strings.Contains(st.LastReload.Error, "--force") {
		t.Fatalf("status after refusal: %+v", st.LastReload)
	}
	time.Sleep(150 * time.Millisecond) // several more polls of the same rejected file
	if st := s.Status(); st.LastReload.OK || st.Generation != gen {
		t.Fatalf("a rejected file must stay reported as rejected: %+v", st.LastReload)
	}
	if get(t, s, "x.test", "/").Echo.Name != "a" {
		t.Fatal("old configuration must keep serving after a refused reload")
	}

	// Not valid JSON at all is refused the same way.
	writeFile(t, path, []byte("{not json"))
	waitFor(t, "json rejection", func() bool { return strings.Contains(s.Status().LastReload.Error, "valid JSON") })
	if get(t, s, "x.test", "/").Echo.Name != "a" {
		t.Fatal("old configuration must keep serving")
	}

	// A good file recovers.
	writeFile(t, path, configFor(be, "b"))
	waitFor(t, "recovery", func() bool { return s.Status().LastReload.OK && s.Status().Generation > gen })
	if get(t, s, "x.test", "/").Echo.Name != "b" {
		t.Fatal("recovered configuration not applied")
	}
}

func TestForceAppliesLintErrors(t *testing.T) {
	be, _ := upstreams(t, "a", "b")
	path := filepath.Join(t.TempDir(), "cfg.json")
	writeFile(t, path, configFor(be, "a"))
	s, _, _ := startFile(t, path, func(o *Options) { o.Lint = fakeLint; o.Force = true })
	gen := s.Status().Generation
	bad := []byte(strings.Replace(string(configFor(be, "b")), `"schema"`, `"x-note":"LINTERROR","schema"`, 1))
	writeFile(t, path, bad)
	waitFor(t, "forced apply", func() bool { return s.Status().Generation > gen })
	if get(t, s, "x.test", "/").Echo.Name != "b" {
		t.Fatal("--force should apply")
	}
}

func TestInitialLintFailureRefusesToStart(t *testing.T) {
	be, _ := upstreams(t, "a")
	path := filepath.Join(t.TempDir(), "cfg.json")
	writeFile(t, path, []byte(strings.Replace(string(configFor(be, "a")), `"schema"`, `"x-note":"LINTERROR","schema"`, 1)))
	s := New(Options{Admin: "off", Lint: fakeLint, PortMap: map[int]int{8080: 0}})
	err := s.Run(context.Background(), FileSource{path}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "lint errors") {
		t.Fatalf("Run = %v, want a lint refusal", err)
	}
	if s.Ready() {
		t.Fatal("must not serve a refused config")
	}
}

func TestCertificateFileRotationReloads(t *testing.T) {
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	dir := t.TempDir()
	sec := func() m {
		c, k := p.issue("a.test")
		os.WriteFile(filepath.Join(dir, "c.crt"), c, 0o600)
		os.WriteFile(filepath.Join(dir, "c.key"), k, 0o600)
		return m{"certFile": "c.crt", "keyFile": "c.key"} // relative to the config file
	}
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": httpsGateway(tlsListener("web", "a.test", "c")), rtKeyT + "r": route("", rule("/", ref("a", 1)))},
		"backends":  m{"t/a:80": be["a"]}, "secrets": m{"c": sec()}})
	path := filepath.Join(dir, "cfg.json")
	writeFile(t, path, raw)
	s, _, _ := startFile(t, path, func(o *Options) { o.PortMap[8443] = 0 })
	serial := func() int64 {
		conn, err := tlsDial(s.Addr(8443), p, "a.test")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	first := serial()
	gen := s.Status().Generation
	sec() // rotate the files in place; the config itself is untouched
	waitFor(t, "rotation reload", func() bool { return s.Status().Generation > gen })
	if second := serial(); second == first {
		t.Fatal("rotated certificate was not picked up")
	}
}
