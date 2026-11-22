package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The benchmarks below drive a real Server over real loopback sockets with
// parallel keep-alive clients. Client, gateway and upstream share one process,
// so allocs/op and B/op include the client and the upstream; compare numbers
// between commits, not against another proxy. Run them with:
//
//	go test ./internal/gateway -run '^$' -bench . -benchtime 2s -cpu 4
//
// scripts/loadtest.sh drives the real binary as separate processes instead.

var benchBody = []byte(`{"ok":true,"name":"bench","payload":"0123456789012345678901234567890123456789012345678901234567890123"}`)

func benchUpstream(b testing.TB) string {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Write(benchBody)
	}))
	b.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func benchServer(b *testing.B, raw []byte, mod func(*Options)) *Server {
	b.Helper()
	opts := Options{PortMap: map[int]int{8080: 0, 8443: 0}, Admin: "off", Rand: seededRand(1), HistoryInterval: -1}
	if mod != nil {
		mod(&opts)
	}
	s := New(opts)
	b.Cleanup(s.Close)
	cfg, err := ParseConfig(raw, b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h"}); err != nil {
		b.Fatal(err)
	}
	return s
}

func benchClient(addr string, tc *tls.Config, h2 bool) *http.Client {
	tr := &http.Transport{MaxIdleConns: 1024, MaxIdleConnsPerHost: 1024, IdleConnTimeout: time.Minute, TLSClientConfig: tc,
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		}}
	if tc != nil && h2 {
		tr.ForceAttemptHTTP2 = true
	} else if tc != nil {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return &http.Client{Transport: tr}
}

// hammer runs one GET per iteration across GOMAXPROCS*4 parallel clients.
func hammer(b *testing.B, c *http.Client, url string) {
	b.Helper()
	b.ReportAllocs()
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := c.Get(url)
			if err != nil {
				b.Error(err)
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				b.Errorf("status %d", resp.StatusCode)
				return
			}
		}
	})
	b.StopTimer()
	c.CloseIdleConnections()
}

func benchHTTPSnap(be string, mirror string) []byte {
	r := rule("/", ref("app", 1))
	backends := map[string]any{"app": be}
	if mirror != "" {
		r["filters"] = l{m{"type": "RequestMirror", "requestMirror": m{"backendRef": ref("shadow", -1)}}}
		backends["shadow"] = mirror
	}
	return snap(httpGateway(""), map[string]m{"r": route("", r)}, backends)
}

// BenchmarkDirect is the upstream with no gateway in front: the floor.
func BenchmarkDirect(b *testing.B) {
	be := benchUpstream(b)
	hammer(b, benchClient(be, nil, false), "http://"+be+"/")
}

func BenchmarkHTTP1(b *testing.B) {
	otlp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.Copy(io.Discard, r.Body) }))
	b.Cleanup(otlp.Close)
	cases := []struct {
		name   string
		mirror bool
		mod    func(*Options)
	}{
		{"bare", false, func(o *Options) { o.ConnHistory = -1 }},
		{"default", false, nil}, // connection history on, as shipped
		{"accesslog", false, func(o *Options) { o.AccessLog = io.Discard }},
		{"accesslog-text", false, func(o *Options) { o.AccessLog = io.Discard; o.Obs.AccessLogFormat = "text" }},
		{"tracing-otlp", false, func(o *Options) { o.Obs.OTLPEndpoint = otlp.URL }},
		{"ratelimit", false, func(o *Options) { o.Obs.RateLimit = RateLimitConfig{Rate: 1e9, Key: "route"} }},
		{"shadow-mirror", true, nil},
		{"shadow-diff100", true, func(o *Options) { o.ShadowDiff = 100 }},
		{"everything", true, func(o *Options) {
			o.AccessLog = io.Discard
			o.Obs.OTLPEndpoint = otlp.URL
			o.Obs.RateLimit = RateLimitConfig{Rate: 1e9}
			o.ShadowDiff = 100
		}},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			be := benchUpstream(b)
			mirror := ""
			if tc.mirror {
				mirror = benchUpstream(b)
			}
			s := benchServer(b, benchHTTPSnap(be, mirror), tc.mod)
			hammer(b, benchClient(s.Addr(8080), nil, false), "http://bench.test/x/y?a=1")
			s.mirrorWG.Wait()
		})
	}
}

func benchTLSServer(b *testing.B, mod func(*Options)) (*Server, *pki) {
	p := newPKI(b)
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": httpsGateway(tlsListener("a", "", "cert")), rtKeyT + "r": route("", rule("/", ref("app", 1)))},
		"backends":  m{"t/app:80": benchUpstream(b)},
		"secrets":   m{"cert": p.files("a", "bench.test")}})
	return benchServer(b, raw, mod), p
}

func BenchmarkTLS(b *testing.B) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		b.Run(name, func(b *testing.B) {
			s, p := benchTLSServer(b, nil)
			hammer(b, benchClient(s.Addr(8443), &tls.Config{RootCAs: p.pool, ServerName: "bench.test"}, h2), "https://bench.test/x")
		})
		b.Run(name+"-accesslog", func(b *testing.B) {
			s, p := benchTLSServer(b, func(o *Options) { o.AccessLog = io.Discard })
			hammer(b, benchClient(s.Addr(8443), &tls.Config{RootCAs: p.pool, ServerName: "bench.test"}, h2), "https://bench.test/x")
		})
	}
}

// BenchmarkTLSHandshake measures new connections: one full handshake per op.
func BenchmarkTLSHandshake(b *testing.B) {
	s, p := benchTLSServer(b, func(o *Options) { o.ConnHistory = -1 })
	cfg := &tls.Config{RootCAs: p.pool, ServerName: "bench.test"}
	addr := s.Addr(8443)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c, err := tls.Dial("tcp", addr, cfg)
			if err != nil {
				b.Error(err)
				return
			}
			c.Close()
		}
	})
}

func BenchmarkGRPCUnary(b *testing.B) {
	for _, tc := range []struct {
		name string
		mod  func(*Options)
	}{{"default", nil}, {"accesslog", func(o *Options) { o.AccessLog = io.Discard }}} {
		b.Run(tc.name, func(b *testing.B) {
			var p http.Protocols
			p.SetHTTP1(true)
			p.SetUnencryptedHTTP2(true)
			up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { grpcOK(w, r, "b") }))
			up.Config.Protocols = &p
			up.Start()
			b.Cleanup(up.Close)
			s := benchServer(b, grpcSnap(grpcGateway(), grpcOneRoute(grule(nil, gref("b", 1))), map[string]any{"b": saddr(up)}, nil), tc.mod)
			c := h2cClient(s.Addr(8080))
			frame := grpcFrame("hello")
			b.ReportAllocs()
			b.SetParallelism(4)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					resp, err := grpcRequest(c, "http", "svc.test", "/p.S/M", bytes.NewReader(frame))
					if err != nil {
						b.Error(err)
						return
					}
					if _, err := readGRPCFrame(resp.Body); err != nil {
						b.Error(err)
						return
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					if resp.Trailer.Get("Grpc-Status") != "0" {
						b.Errorf("grpc-status %q", resp.Trailer.Get("Grpc-Status"))
						return
					}
				}
			})
		})
	}
}

// wsEchoUpstream switches protocols and echoes lines until the peer closes.
func wsEchoUpstream(b testing.TB) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		rw.Flush()
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			rw.WriteString(line)
			rw.Flush()
		}
	}))
	b.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func wsDial(b *testing.B, addr string) (net.Conn, *bufio.Reader) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		b.Fatal(err)
	}
	io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: bench.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != 101 {
		b.Fatalf("upgrade: %v %v", resp, err)
	}
	return c, br
}

// BenchmarkStatsRecord is the per-request counter update every request pays,
// from all cores at once.
func BenchmarkStatsRecord(b *testing.B) {
	s := newStats()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.record("t/r", "t/app", 200)
		}
	})
}

// BenchmarkWebSocketMessages: one upgraded tunnel per parallel worker, one echo round trip per op.
func BenchmarkWebSocketMessages(b *testing.B) {
	s := benchServer(b, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("app", 1)))}, map[string]any{"app": wsEchoUpstream(b)}), nil)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c, br := wsDial(b, s.Addr(8080))
		defer c.Close()
		for pb.Next() {
			io.WriteString(c, "ping\n")
			if _, err := br.ReadString('\n'); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
