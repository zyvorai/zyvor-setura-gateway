package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// ---- connection limits ----

// holdConn opens a keep-alive connection and completes one request on it, so
// the gateway has certainly accepted and counted it.
func holdConn(t *testing.T, s *Server) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr(8080))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("held connection: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return c, br
}

// refused reports whether the gateway closes a new connection without serving it.
func refused(t *testing.T, s *Server) bool {
	t.Helper()
	c, err := net.Dial("tcp", s.Addr(8080))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: a.test\r\nConnection: close\r\n\r\n")
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := io.ReadAll(c)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("neither served nor closed")
	}
	return len(b) == 0
}

func TestMaxConnectionsPerListener(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), func(o *Options) { o.Shape.MaxConns = 2 })
	c1, _ := holdConn(t, s)
	holdConn(t, s)
	if !refused(t, s) {
		t.Fatal("a third connection must be refused")
	}
	c1.Close() // the slot is released when the gateway notices
	deadline := time.Now().Add(3 * time.Second)
	for refused(t, s) {
		if time.Now().After(deadline) {
			t.Fatal("slot never freed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	out := obsMetricsOf(s)
	if !strings.Contains(out, `setura_gateway_conn_limit_rejected_total{port="8080",reason="total"} `) || strings.Contains(out, `reason="total"} 0`) {
		t.Errorf("rejections not counted:\n%s", out)
	}
	if !strings.Contains(out, `setura_gateway_listener_connections{port="8080"}`) {
		t.Errorf("gauge missing")
	}
}

func TestMaxConnectionsPerClientIP(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), func(o *Options) { o.Shape.MaxConnsPerIP = 1 })
	holdConn(t, s)
	if !refused(t, s) {
		t.Fatal("the same IP may hold one connection")
	}
	if !strings.Contains(obsMetricsOf(s), `reason="per_ip"} 1`) {
		t.Errorf("per-IP rejection not counted:\n%s", obsMetricsOf(s))
	}
}

func TestListenerLimitsBlockOverridesAndReloads(t *testing.T) {
	be, _ := upstreams(t, "a")
	gw := httpGateway("")
	gw["listeners"].([]any)[0].(m)["setura.zyvor.dev/limits"] = m{"maxConnections": 1}
	routes := map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}
	s := startServer(t, snap(gw, routes, be), func(o *Options) { o.Shape.MaxConns = 50 })
	holdConn(t, s)
	if !refused(t, s) {
		t.Fatal("the listener's own limit (1) applies, not the gateway's (50)")
	}
	// A reload that lifts the listener limit keeps the socket and applies the gateway value.
	cfg, err := ParseConfig(snap(httpGateway(""), routes, be), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(&Loaded{Config: cfg, Hash: "h2"}); err != nil {
		t.Fatal(err)
	}
	if refused(t, s) {
		t.Fatal("after the reload the listener falls back to the gateway limit")
	}
	if _, err := ParseListenerLimitsBlock([]byte(`{"maxConnections":-1}`)); err == nil {
		t.Error("negative limit accepted")
	}
}

func TestTCPKeepaliveSettings(t *testing.T) {
	s := New(Options{Admin: "off", Shape: ShapeOptions{KeepAlive: KeepAliveOptions{Idle: 41 * time.Second, Interval: 17 * time.Second, Count: 4}}})
	t.Cleanup(s.Close)
	ln, _, err := s.listenTCP("127.0.0.1:0", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := c.(*limitConn).NetConn().(*net.TCPConn)
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	raw.Control(func(fd uintptr) {
		for name, opt := range map[string]int{"idle": keepIdleOpt, "interval": syscall.TCP_KEEPINTVL, "count": syscall.TCP_KEEPCNT} {
			got[name], _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, opt)
		}
	})
	if got["idle"] != 41 || got["interval"] != 17 || got["count"] != 4 {
		t.Errorf("socket options on %s: %v", runtime.GOOS, got)
	}
}

func TestH2SettingsAdvertised(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), func(o *Options) {
		o.Shape.H2 = H2Options{MaxStreams: 7, InitialWindow: 123456, MaxFrameSize: 1 << 17, MaxConnWindow: 1 << 20}
	})
	c, err := net.Dial("tcp", s.Addr(8080))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	c.Write([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0}) // an empty SETTINGS frame from the client
	settings := map[uint16]uint32{}
	for len(settings) < 3 {
		var hdr [9]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			t.Fatalf("reading the server's frames: %v (got %v)", err, settings)
		}
		n := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
		payload := make([]byte, n)
		io.ReadFull(c, payload)
		if hdr[3] == 4 && hdr[4]&1 == 0 { // SETTINGS, not the ACK
			for i := 0; i+6 <= n; i += 6 {
				settings[binary.BigEndian.Uint16(payload[i:])] = binary.BigEndian.Uint32(payload[i+2:])
			}
			break
		}
	}
	if settings[3] != 7 || settings[4] != 123456 || settings[5] != 1<<17 {
		t.Errorf("SETTINGS: max streams %d (want 7), initial window %d (123456), max frame %d (131072)", settings[3], settings[4], settings[5])
	}
}

// ---- bandwidth ----

type bwClock struct {
	mu    sync.Mutex
	t     time.Time
	slept []time.Duration
}

func (c *bwClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *bwClock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.slept = append(c.slept, d)
	c.mu.Unlock()
	return nil
}
func (c *bwClock) total() (d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.slept {
		d += s
	}
	return
}

func TestBandwidthLimiterArithmetic(t *testing.T) {
	clk := &bwClock{t: time.Unix(1_700_000_000, 0)}
	s := New(Options{Admin: "off", Shape: ShapeOptions{Now: clk.now, Sleep: clk.sleep}})
	t.Cleanup(s.Close)
	b := s.newBW(1000, 100) // 1000 B/s, bucket of 100 bytes
	ctx := context.Background()
	b.take(ctx, 100) // the full bucket is free
	if clk.total() != 0 {
		t.Fatalf("a full bucket waited %s", clk.total())
	}
	b.take(ctx, 500) // 500 bytes at 1000 B/s: 500ms
	if clk.total() != 500*time.Millisecond {
		t.Fatalf("waited %s, want 500ms", clk.total())
	}
	clk.sleep(ctx, 10*time.Second) // idle: the bucket refills to its cap, not beyond
	before := clk.total()
	b.take(ctx, 100)
	b.take(ctx, 100)
	if got := clk.total() - before; got != 100*time.Millisecond {
		t.Fatalf("burst cap: waited %s, want 100ms", got)
	}
	if s.newBW(0, 0) != nil {
		t.Error("rate 0 means unlimited")
	}
	for in, want := range map[string]int64{"1MB/s": 1 << 20, "256k": 256 << 10, "4096/s": 4096, "unlimited": 0} {
		if got, err := ParseRateBytes(in); err != nil || got != want {
			t.Errorf("%q: %d %v", in, got, err)
		}
	}
	if _, err := ParseRateBytes("fast"); err == nil {
		t.Error("nonsense accepted")
	}
}

func TestBandwidthPacesResponseAndRequest(t *testing.T) {
	clk := &bwClock{t: time.Unix(1_700_000_000, 0)}
	body := bytes.Repeat([]byte("0123456789"), 2000) // 20000 bytes
	be := handlerUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Got", string(rune('0'+len(got)/1000))) // thousands of request bytes seen
		w.Write(body)
	}))
	rl := rule("/", ref("a", 1))
	rl["setura.zyvor.dev/bandwidth"] = m{"response": "10000/s", "request": "5000/s", "burst": "1000"}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rl)}, be), func(o *Options) { o.Shape.Now, o.Shape.Sleep = clk.now, clk.sleep })
	rq, _ := http.NewRequest("POST", "http://a.test/", bytes.NewReader(bytes.Repeat([]byte("r"), 5000)))
	resp, err := rawClient(s.Addr(8080)).Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, body) || resp.Header.Get("X-Got") != "5" {
		t.Fatalf("paced transfer must stay intact: %d bytes, upstream saw %q thousand", len(got), resp.Header.Get("X-Got"))
	}
	// response: (20000-1000 free) / 10000 per s = 1.9s; request: (5000-1000) / 5000 = 0.8s
	if want := 2700 * time.Millisecond; clk.total() < want-time.Millisecond || clk.total() > want+time.Millisecond {
		t.Errorf("paced for %s, want %s", clk.total(), want)
	}
	out := obsMetricsOf(s)
	for _, w := range []string{`setura_gateway_bandwidth_limited_total{route="t/r",direction="response"} 1`, `setura_gateway_bandwidth_limited_total{route="t/r",direction="request"} 1`,
		`setura_gateway_bandwidth_delay_seconds_total{route="t/r",direction="response"} 1.900`, `setura_gateway_bandwidth_delay_seconds_total{route="t/r",direction="request"} 0.800`} {
		if !strings.Contains(out, w) {
			t.Errorf("metrics lack %s\n%s", w, out)
		}
	}
}

func TestBandwidthGatewayDefaultAndRuleOverride(t *testing.T) {
	clk := &bwClock{t: time.Unix(1_700_000_000, 0)}
	be := handlerUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(bytes.Repeat([]byte("x"), 10240)) }))
	lift := rule("/free", ref("a", 1))
	lift["setura.zyvor.dev/bandwidth"] = m{"response": "unlimited"}
	routes := map[string]m{"r": route("a.test", lift, rule("/", ref("a", 1)))}
	s := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) {
		o.Shape.BandwidthOut = 2048
		o.Shape.Now, o.Shape.Sleep = clk.now, clk.sleep
	})
	if r := rawDo(t, s, "GET", "/free"); len(r.Body) != 10240 || clk.total() != 0 {
		t.Fatalf("lifted: %d bytes, paced %s", len(r.Body), clk.total())
	}
	if r := rawDo(t, s, "GET", "/paced"); len(r.Body) != 10240 || clk.total() == 0 {
		t.Fatalf("default rate: %d bytes, paced %s", len(r.Body), clk.total())
	}
	for _, bad := range []string{`{}`, `{"response":"fast"}`, `{"request":"1MB/s","burst":0}`, `{"nope":1}`} {
		if _, err := ParseBandwidthBlock([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// ---- X-Request-Id ----

func TestRequestIDModes(t *testing.T) {
	be := handlerUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Id", r.Header.Get("X-Request-Id"))
		w.Header().Set("X-Seen-Client", r.Header.Get("X-Client-Request-Id"))
		if r.URL.Path == "/own" {
			w.Header().Set("X-Request-Id", "backend-42")
		}
		io.WriteString(w, "ok")
	}))
	routes := map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}
	run := func(mode string) *Server {
		return startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.Shape.RequestID = mode; o.AccessLog = &syncBuf{} })
	}
	// preserve (and the default): a valid client id is kept end to end, a bad one is replaced
	for _, mode := range []string{"", RequestIDPreserve} {
		s := run(mode)
		r := rawDo(t, s, "GET", "/", "X-Request-Id", "client-1")
		if r.Header.Get("X-Request-Id") != "client-1" || r.Header.Get("X-Seen-Id") != "client-1" {
			t.Errorf("preserve %q: %v", mode, r.Header)
		}
		if r := rawDo(t, s, "GET", "/"); len(r.Header.Get("X-Request-Id")) != 32 {
			t.Errorf("preserve generates when absent: %v", r.Header)
		}
	}
	// generate: the client's id never enters the system, it travels as X-Client-Request-Id
	g := run(RequestIDGenerate)
	r := rawDo(t, g, "GET", "/", "X-Request-Id", "client-1")
	if id := r.Header.Get("X-Request-Id"); id == "client-1" || len(id) != 32 || r.Header.Get("X-Seen-Id") != id || r.Header.Get("X-Seen-Client") != "client-1" {
		t.Errorf("generate: %v", r.Header)
	}
	// trust-upstream: the backend's own id wins on the response and in the log
	var log syncBuf
	u := startServer(t, snap(httpGateway(""), routes, be), func(o *Options) { o.Shape.RequestID = RequestIDUpstream; o.AccessLog = &log })
	r = rawDo(t, u, "GET", "/own", "X-Request-Id", "client-1")
	if r.Header.Get("X-Request-Id") != "backend-42" || len(r.Header.Values("X-Request-Id")) != 1 || r.Header.Get("X-Seen-Id") != "client-1" {
		t.Errorf("trust-upstream: %v", r.Header)
	}
	if r := rawDo(t, u, "GET", "/", "X-Request-Id", "client-2"); r.Header.Get("X-Request-Id") != "client-2" {
		t.Errorf("trust-upstream without a backend id keeps ours: %v", r.Header)
	}
	u.FlushAccessLog()
	if !strings.Contains(log.String(), "backend-42") {
		t.Errorf("access log should carry the backend's id:\n%s", log.String())
	}
}
