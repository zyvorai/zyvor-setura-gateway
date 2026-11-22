package gateway

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// h2cServer starts an h2c test server running h.
func h2cServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &p
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func saddr(s *httptest.Server) string { return strings.TrimPrefix(s.URL, "http://") }

// grpcOK answers every message with an echo and grpc-status 0.
func grpcOK(w http.ResponseWriter, r *http.Request, name string) {
	w.Header().Set("Content-Type", "application/grpc")
	for {
		msg, err := readGRPCFrame(r.Body)
		if err != nil {
			break
		}
		w.Write(grpcFrame(name + ":" + msg))
	}
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
}

func grpcOneRoute(rl m) map[string]m { return map[string]m{grpcKeyT + "g": grpcRoute("", rl)} }

func TestGRPCTimeoutPropagatedAndShortened(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := h2cServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Grpc-Timeout"))
		mu.Unlock()
		grpcOK(w, r, "b")
	})
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(grule(nil, gref("b", 1))), map[string]any{"b": saddr(srv)}, nil), nil)
	c := h2cClient(s.Addr(8080))

	if r := grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"x"}, "Grpc-Timeout", "2S"); r.Status != "0" {
		t.Fatalf("call failed: %+v", r)
	}
	if r := grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"x"}); r.Status != "0" {
		t.Fatalf("call without a timeout failed: %+v", r)
	}
	if r := grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"x"}, "Grpc-Timeout", "garbage"); r.Status != "0" {
		t.Fatalf("an unparsable grpc-timeout must be ignored, got %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	m := regexp.MustCompile(`^(\d+)m$`).FindStringSubmatch(seen[0])
	if m == nil {
		t.Fatalf("backend saw grpc-timeout %q, want milliseconds", seen[0])
	}
	if ms, _ := strconv.Atoi(m[1]); ms < 1 || ms > 2000 {
		t.Errorf("forwarded deadline %dms, want what is left of 2s", ms)
	}
	if seen[1] != "" || seen[2] != "" {
		t.Errorf("no grpc-timeout expected without a valid client one, got %q and %q", seen[1], seen[2])
	}
}

func TestGRPCTimeoutEnforcedAsDeadlineExceeded(t *testing.T) {
	srv := h2cServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(grule(nil, gref("b", 1))), map[string]any{"b": saddr(srv)}, nil), nil)
	start := time.Now()
	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"x"}, "Grpc-Timeout", "150m")
	if r.Status != "4" || time.Since(start) > 3*time.Second {
		t.Fatalf("status %q after %v, want DEADLINE_EXCEEDED (4) at about 150ms", r.Status, time.Since(start))
	}
}

func TestGRPCBackendTimeoutBeatsLongerClientTimeout(t *testing.T) {
	srv := h2cServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	be := map[string]any{"b": m{"endpoints": l{saddr(srv)}, "timeout": "120ms"}}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(grule(nil, gref("b", 1))), be, nil), nil)
	start := time.Now()
	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"x"}, "Grpc-Timeout", "30S")
	if r.Status != "4" || time.Since(start) > 3*time.Second {
		t.Fatalf("status %q after %v, want the shorter backend timeout to win", r.Status, time.Since(start))
	}
}

func TestParseFormatGRPCTimeout(t *testing.T) {
	for in, want := range map[string]time.Duration{"1H": time.Hour, "5M": 5 * time.Minute, "30S": 30 * time.Second, "150m": 150 * time.Millisecond,
		"7u": 7 * time.Microsecond, "9n": 9, "9999H": 9999 * time.Hour} {
		if got, ok := parseGRPCTimeout(in); !ok || got != want {
			t.Errorf("parse %q = %v %v, want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "S", "5", "5x", "-5S", "123456789S", "1.5S"} {
		if _, ok := parseGRPCTimeout(bad); ok {
			t.Errorf("parse %q accepted", bad)
		}
	}
	for d, want := range map[time.Duration]string{2 * time.Second: "2000m", 1500 * time.Microsecond: "1m", 300 * time.Microsecond: "300u", 40: "40n", 0: "1n", -time.Second: "1n"} {
		if got := formatGRPCTimeout(d); got != want {
			t.Errorf("format %v = %q, want %q", d, got, want)
		}
	}
}

// flakyGRPC answers Trailers-Only with the given status for the first fails
// calls, then succeeds.
type flakyGRPC struct {
	*httptest.Server
	hits  atomic.Int32
	fails int32
	code  string
}

func newFlakyGRPC(t *testing.T, fails int, code string) *flakyGRPC {
	f := &flakyGRPC{fails: int32(fails), code: code}
	f.Server = h2cServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := f.hits.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		if n <= f.fails {
			w.Header().Set("Grpc-Status", f.code)
			w.Header().Set("Grpc-Message", "try later")
			return
		}
		w.Write(grpcFrame("ok"))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	return f
}

func retryRule(codes l, attempts int, be ...m) m {
	r := grule(nil, be...)
	rt := m{"attempts": attempts, "backoff": "0s"}
	if codes != nil {
		rt["codes"] = codes
	}
	r["retry"] = rt
	return r
}

func grpcRes(mod func(*ResilienceOptions)) func(*Options) {
	return resOpts(newClock(), &sleepRec{}, func(o *ResilienceOptions) {
		o.RetryBudgetMin = 100
		if mod != nil {
			mod(o)
		}
	})
}

func TestGRPCRetriesUnaryOnUnavailable(t *testing.T) {
	f := newFlakyGRPC(t, 2, "14")
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(nil, 2, gref("b", 1))), map[string]any{"b": saddr(f.Server)}, nil), grpcRes(nil))
	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"hello"})
	if r.Status != "0" || len(r.Msgs) != 1 || r.Msgs[0] != "ok" || f.hits.Load() != 3 {
		t.Fatalf("reply %+v hits %d, want success on the third try", r, f.hits.Load())
	}
	if r.Header.Get(RetryHeaderName) != "2" {
		t.Errorf("X-Setura-Retries = %q", r.Header.Get(RetryHeaderName))
	}
	if !strings.Contains(metricsOf(s), `setura_gateway_retries_total{backend="t/b:80"} 2`) {
		t.Errorf("retry counter:\n%s", metricsOf(s))
	}
}

func TestGRPCRetryExhaustsAndReturnsLastStatus(t *testing.T) {
	f := newFlakyGRPC(t, 100, "14")
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(l{"UNAVAILABLE"}, 1, gref("b", 1))), map[string]any{"b": saddr(f.Server)}, nil), grpcRes(nil))
	r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"hello"})
	if r.Status != "14" || f.hits.Load() != 2 {
		t.Fatalf("status %q hits %d, want UNAVAILABLE after 1+1 tries", r.Status, f.hits.Load())
	}
}

func TestGRPCRetryOnlyListedCodes(t *testing.T) {
	f := newFlakyGRPC(t, 100, "5") // NOT_FOUND is not in the default list
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(nil, 3, gref("b", 1))), map[string]any{"b": saddr(f.Server)}, nil), grpcRes(nil))
	if r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"x"}); r.Status != "5" || f.hits.Load() != 1 {
		t.Fatalf("status %q hits %d, want NOT_FOUND passed through untried", r.Status, f.hits.Load())
	}
	f2 := newFlakyGRPC(t, 1, "8") // RESOURCE_EXHAUSTED, listed by number
	s2 := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(l{8}, 1, gref("b", 1))), map[string]any{"b": saddr(f2.Server)}, nil), grpcRes(nil))
	if r := grpcCall(t, h2cClient(s2.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"x"}); r.Status != "0" || f2.hits.Load() != 2 {
		t.Fatalf("status %q hits %d, want a retry on code 8", r.Status, f2.hits.Load())
	}
}

func TestGRPCNotReplayableIsNeverRetried(t *testing.T) {
	// More than one message: a streaming call.
	f := newFlakyGRPC(t, 1, "14")
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(nil, 3, gref("b", 1))), map[string]any{"b": saddr(f.Server)}, nil), grpcRes(nil))
	if r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/M", []string{"one", "two"}); r.Status != "14" || f.hits.Load() != 1 {
		t.Fatalf("two messages: status %q hits %d, want no retry", r.Status, f.hits.Load())
	}
	// A message above the retry body limit.
	f2 := newFlakyGRPC(t, 1, "14")
	s2 := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(nil, 3, gref("b", 1))), map[string]any{"b": saddr(f2.Server)}, nil),
		grpcRes(func(o *ResilienceOptions) { o.RetryBodyLimit = 16 }))
	if r := grpcCall(t, h2cClient(s2.Addr(8080)), "http", "svc.test", "/p.S/M", []string{strings.Repeat("x", 100)}); r.Status != "14" || f2.hits.Load() != 1 {
		t.Fatalf("big message: status %q hits %d, want no retry", r.Status, f2.hits.Load())
	}
}

func TestGRPCStreamingCallsStillStreamWithRetryConfigured(t *testing.T) {
	// A bidirectional call must not be held back by the replay buffering: the
	// second message is only sent after the first answer arrives.
	srv := h2cServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		fl := w.(http.Flusher)
		for {
			msg, err := readGRPCFrame(r.Body)
			if err != nil {
				break
			}
			w.Write(grpcFrame("echo:" + msg))
			fl.Flush()
		}
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(nil, 2, gref("b", 1))), map[string]any{"b": saddr(srv)}, nil), grpcRes(nil))
	pr, pw := io.Pipe()
	go pw.Write(grpcFrame("a")) // the first message goes out before any response header can exist
	resp, err := grpcRequest(h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/Chat", pr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	for i, msg := range []string{"a", "b", "c"} {
		if i > 0 {
			pw.Write(grpcFrame(msg))
		}
		got, err := readGRPCFrame(resp.Body)
		if err != nil || got != "echo:"+msg {
			t.Fatalf("message %q: got %q, %v", msg, got, err)
		}
	}
	pw.Close()
	io.Copy(io.Discard, resp.Body)
}

func TestGRPCRetryOnConnectErrorGoesToAnotherEndpoint(t *testing.T) {
	good := newFlakyGRPC(t, 0, "0")
	be := map[string]any{"b": m{"endpoints": l{deadAddr(t), saddr(good.Server)}}}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(retryRule(nil, 2, gref("b", 1))), be, nil), grpcRes(nil))
	c := h2cClient(s.Addr(8080))
	for i := 0; i < 4; i++ {
		if r := grpcCall(t, c, "http", "svc.test", "/p.S/M", []string{"x"}); r.Status != "0" {
			t.Fatalf("call %d: %+v", i, r)
		}
	}
}

func TestGRPCMirrorsUnaryCalls(t *testing.T) {
	primary := newGRPCBackend(t, "primary")
	mirror := newGRPCBackend(t, "mirror")
	rl := grule(nil, gref("primary", 1))
	rl["filters"] = l{m{"type": "RequestMirror", "requestMirror": m{"backendRef": gref("mirror", 1)}}}
	be := map[string]any{"primary": primary.addr(), "mirror": mirror.addr()}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(rl), be, nil), nil)
	c := h2cClient(s.Addr(8080))

	r := grpcCall(t, c, "http", "svc.test", "/p.S/Unary", []string{"hello"})
	if r.Status != "0" || len(r.Msgs) != 1 || r.Msgs[0] != "primary:hello" {
		t.Fatalf("the caller must see the primary's answer, got %+v", r)
	}
	eventually(t, func() bool { return len(mirror.paths()) == 1 })
	if mirror.paths()[0] != "/p.S/Unary" {
		t.Errorf("mirror saw %v", mirror.paths())
	}

	// A streaming call (two messages) is not mirrored.
	grpcCall(t, c, "http", "svc.test", "/p.S/Stream", []string{"a", "b"})
	time.Sleep(100 * time.Millisecond)
	if len(mirror.paths()) != 1 {
		t.Errorf("streaming call was mirrored: %v", mirror.paths())
	}
	if len(primary.paths()) != 2 {
		t.Errorf("primary saw %v", primary.paths())
	}
}

func TestGRPCMirrorFailureDoesNotAffectCaller(t *testing.T) {
	primary := newGRPCBackend(t, "primary")
	rl := grule(nil, gref("primary", 1))
	rl["filters"] = l{m{"type": "RequestMirror", "requestMirror": m{"backendRef": gref("dead", 1), "percent": 100}}}
	be := map[string]any{"primary": primary.addr(), "dead": deadAddr(t)}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(rl), be, nil), nil)
	if r := grpcCall(t, h2cClient(s.Addr(8080)), "http", "svc.test", "/p.S/Unary", []string{"hello"}); r.Status != "0" {
		t.Fatalf("%+v", r)
	}
}

func eventually(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("condition not reached in time")
}

func TestGRPCExtensionRefRejectedClearly(t *testing.T) {
	be := map[string]any{"b": "127.0.0.1:1"}
	rl := grule(nil, gref("b", 1))
	rl["filters"] = l{m{"type": "ExtensionRef", "extensionRef": m{"group": "x.io", "kind": "Policy", "name": "p"}}}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(rl), be, nil), nil)
	rs := s.Status().Routes["GRPCRoute/t/g"]
	if rs == nil {
		t.Fatal("no status")
	}
	c := cond(rs.Parents[0].Conditions, "Accepted")
	if c.Status != "False" || !strings.Contains(c.Message, "ExtensionRef") || !strings.Contains(c.Message, "not supported") {
		t.Errorf("Accepted = %+v, want a clear ExtensionRef rejection", c)
	}
	// HTTPRoute says the same.
	hr := rule("/", ref("b", 1))
	hr["filters"] = l{m{"type": "ExtensionRef", "extensionRef": m{"group": "x.io", "kind": "Policy", "name": "p"}}}
	s2 := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", hr)}, map[string]any{"b": "127.0.0.1:1"}), nil)
	if c := cond(s2.Status().Routes["t/r"].Parents[0].Conditions, "Accepted"); c.Status != "False" || !strings.Contains(c.Message, "ExtensionRef") {
		t.Errorf("HTTPRoute Accepted = %+v", c)
	}
}

func TestGRPCRouteRejectsBadRetryAndShadowDiff(t *testing.T) {
	be := map[string]any{"b": "127.0.0.1:1"}
	bad := grule(nil, gref("b", 1))
	bad["retry"] = m{"codes": l{"WHATEVER"}}
	mirrorDiff := grule(nil, gref("b", 1))
	mirrorDiff["filters"] = l{m{"type": "RequestMirror", "requestMirror": m{"backendRef": gref("b", 1), "setura.zyvor.dev/shadow-diff": m{}}}}
	for name, rl := range map[string]m{"unknown code": bad, "shadow-diff": mirrorDiff} {
		func() {
			defer func() {
				if recover() != nil {
					t.Errorf("%s panicked", name)
				}
			}()
			raw := grpcSnap(grpcGateway(), grpcOneRoute(rl), be, nil)
			if _, err := ParseConfig(raw, ""); err == nil {
				s := startServer(t, raw, nil)
				if c := cond(s.Status().Routes["GRPCRoute/t/g"].Parents[0].Conditions, "Accepted"); c.Status != "False" {
					t.Errorf("%s accepted", name)
				}
			}
		}()
	}
}

// ---- gRPC health checking ----

func healthServer(t *testing.T, serving *atomic.Bool, wantService string) *httptest.Server {
	return h2cServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		if r.URL.Path != grpcHealthPath {
			w.Header().Set("Grpc-Status", "12")
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, encodeHealthRequest(wantService)) {
			w.Header().Set("Grpc-Status", "5") // NOT_FOUND: asked about another service
			return
		}
		status := byte(2) // NOT_SERVING
		if serving.Load() {
			status = 1
		}
		w.Write(append([]byte{0, 0, 0, 0, 2}, 8, status))
		w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
	})
}

func TestGRPCHealthCheckMarksEndpointsUpAndDown(t *testing.T) {
	var up, down atomic.Bool
	up.Store(true)
	a, b := healthServer(t, &up, "pkg.Orders"), healthServer(t, &down, "pkg.Orders")
	be := map[string]any{"b": m{"endpoints": l{saddr(a), saddr(b)},
		"healthCheck": m{"protocol": "grpc", "service": "pkg.Orders", "interval": "20ms", "timeout": "1s"}}}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(grule(nil, gref("b", 1))), be, nil), nil)
	gauge := func(addr string, v int) string {
		return `setura_gateway_endpoint_healthy{backend="t/b:80",endpoint="` + addr + `"} ` + strconv.Itoa(v)
	}
	eventually(t, func() bool {
		out := metricsOf(s)
		return strings.Contains(out, gauge(saddr(a), 1)) && strings.Contains(out, gauge(saddr(b), 0))
	})
	down.Store(true)
	eventually(t, func() bool { return strings.Contains(metricsOf(s), gauge(saddr(b), 1)) })
}

func TestGRPCHealthCheckWrongServiceIsUnhealthy(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	a := healthServer(t, &up, "other.Service")
	be := map[string]any{"b": m{"endpoints": l{saddr(a)}, "healthCheck": m{"protocol": "grpc", "service": "pkg.Orders", "interval": "20ms"}}}
	s := startServer(t, grpcSnap(grpcGateway(), grpcOneRoute(grule(nil, gref("b", 1))), be, nil), nil)
	eventually(t, func() bool {
		return strings.Contains(metricsOf(s), `setura_gateway_endpoint_healthy{backend="t/b:80",endpoint="`+saddr(a)+`"} 0`)
	})
}

func TestHealthFrameCodec(t *testing.T) {
	if got := encodeHealthRequest(""); !bytes.Equal(got, []byte{0, 0, 0, 0, 0}) {
		t.Errorf("empty request = %v", got)
	}
	if got := encodeHealthRequest("ab"); !bytes.Equal(got, []byte{0, 0, 0, 0, 4, 0x0a, 2, 'a', 'b'}) {
		t.Errorf("request = %v", got)
	}
	if st, err := decodeHealthStatus([]byte{0, 0, 0, 0, 2, 8, 1}); err != nil || st != 1 {
		t.Errorf("serving = %d %v", st, err)
	}
	for _, bad := range [][]byte{nil, {1, 0, 0, 0, 0}, {0, 0, 0, 0, 9, 8}, {0, 0, 0, 0, 1, 0x80}} {
		if _, err := decodeHealthStatus(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestBufferUnary(t *testing.T) {
	mk := func(body io.Reader) *http.Request {
		r := httptest.NewRequest("POST", "/", body)
		return r
	}
	one := grpcFrame("hello")
	if all, ok := bufferUnary(mk(bytes.NewReader(one)), 1024); !ok || !bytes.Equal(all, one) {
		t.Errorf("unary: %v %v", all, ok)
	}
	r := mk(bytes.NewReader(append(append([]byte(nil), one...), grpcFrame("two")...)))
	if _, ok := bufferUnary(r, 1024); ok {
		t.Error("two messages treated as unary")
	}
	if b, _ := io.ReadAll(r.Body); !bytes.Equal(b, append(append([]byte(nil), one...), grpcFrame("two")...)) {
		t.Errorf("body not restored after a refused buffering: %q", b)
	}
	r = mk(bytes.NewReader(one))
	if _, ok := bufferUnary(r, 8); ok {
		t.Error("oversized message buffered")
	}
	if b, _ := io.ReadAll(r.Body); !bytes.Equal(b, one) {
		t.Errorf("oversized body not restored: %q", b)
	}
	// A client that sent one message but keeps the stream open is a stream.
	pr, pw := io.Pipe()
	go pw.Write(one)
	r = mk(pr)
	if _, ok := bufferUnary(r, 1024); ok {
		t.Error("open stream treated as unary")
	}
	go func() { pw.Write(grpcFrame("later")); pw.Close() }()
	if b, _ := io.ReadAll(r.Body); !bytes.Equal(b, append(append([]byte(nil), one...), grpcFrame("later")...)) {
		t.Errorf("stream bytes lost or reordered: %q", b)
	}
	_ = context.Background
}
