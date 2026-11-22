package gateway

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// startPprof serves net/http/pprof and /debug/runtime on Options.Pprof. The
// address must be loopback: profiles expose memory contents and the endpoint
// has no authentication. Empty disables it.
func (s *Server) startPprof() error {
	addr := s.opts.Pprof
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--pprof %q: want HOST:PORT on a loopback address", addr)
	}
	if host == "" {
		return fmt.Errorf("--pprof %q: refusing to listen on every interface, use 127.0.0.1:PORT", addr)
	}
	if host != "localhost" {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("--pprof %q: only loopback addresses are allowed", addr)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("pprof listener: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	mux.HandleFunc("/debug/runtime", func(w http.ResponseWriter, _ *http.Request) {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"goroutines": runtime.NumGoroutine(), "heap_alloc_bytes": ms.HeapAlloc, "heap_inuse_bytes": ms.HeapInuse,
			"sys_bytes": ms.Sys, "rss_bytes": rssBytes(), "num_gc": ms.NumGC, "gc_pause_total_ns": ms.PauseTotalNs,
			"mallocs": ms.Mallocs, "frees": ms.Frees, "time": time.Now().UTC().Format(time.RFC3339),
		})
	})
	s.pprofLn = ln
	s.pprofSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go s.pprofSrv.Serve(ln)
	s.diag("pprof on http://%s/debug/pprof/", ln.Addr())
	return nil
}

// PprofAddr is the bound pprof address, "" when disabled.
func (s *Server) PprofAddr() string {
	if s.pprofLn == nil {
		return ""
	}
	return s.pprofLn.Addr().String()
}

// rssBytes is the resident set size where /proc exposes it (Linux), else 0;
// scripts/loadtest.sh reads it with ps elsewhere.
func rssBytes() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, _ := strconv.ParseUint(f[1], 10, 64)
	return pages * uint64(os.Getpagesize())
}
