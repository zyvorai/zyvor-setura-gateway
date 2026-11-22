package gateway

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestPprofLoopbackOnly(t *testing.T) {
	for _, bad := range []string{":6060", "0.0.0.0:0", "10.1.2.3:6060", "example.com:80", "nonsense"} {
		s := New(Options{Pprof: bad, Admin: "off"})
		if err := s.startPprof(); err == nil {
			t.Errorf("--pprof %q was accepted", bad)
		}
		s.Close()
	}
	s := New(Options{Pprof: "127.0.0.1:0", Admin: "off"})
	t.Cleanup(s.Close)
	if err := s.startPprof(); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + s.PprofAddr() + "/debug/runtime")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var v map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil || v["goroutines"] == nil {
		t.Fatalf("runtime sample %v %v", v, err)
	}
	r2, err := http.Get("http://" + s.PprofAddr() + "/debug/pprof/goroutine?debug=1")
	if err != nil || r2.StatusCode != 200 {
		t.Fatalf("goroutine profile: %v %v", r2, err)
	}
	r2.Body.Close()
}

func TestPprofOffByDefault(t *testing.T) {
	s := New(Options{Admin: "off"})
	t.Cleanup(s.Close)
	if err := s.startPprof(); err != nil || s.PprofAddr() != "" {
		t.Fatalf("pprof should be off: %v %q", err, s.PprofAddr())
	}
}
