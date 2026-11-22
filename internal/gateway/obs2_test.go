package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func mustUnmarshal(raw []byte, v any) {
	if err := json.Unmarshal(raw, v); err != nil {
		panic(err)
	}
}

// ---- OTLP retries and bounded queue ----

func TestOTLPRetriesWithBackoffThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		switch calls.Add(1) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(col.Close)
	x := newOTLPOpts(col.URL, 5*time.Millisecond, OTLPOptions{Retries: 4, Backoff: time.Millisecond})
	x.add(span{name: "a", start: time.Now(), end: time.Now(), status: 200})
	x.add(span{name: "b", start: time.Now(), end: time.Now(), status: 200})
	for deadline := time.Now().Add(5 * time.Second); x.exported.Load() < 2 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	}
	x.close()
	if x.exported.Load() != 2 || x.dropped.Load() != 0 || x.retries.Load() != 2 || calls.Load() != 3 {
		t.Errorf("exported %d dropped %d retries %d calls %d, want 2/0/2/3", x.exported.Load(), x.dropped.Load(), x.retries.Load(), calls.Load())
	}
}

func TestOTLPDoesNotRetryClientErrorsAndGivesUp(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(400)
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(col.Close)
	x := newOTLPOpts(col.URL, 5*time.Millisecond, OTLPOptions{Retries: 3, Backoff: time.Millisecond})
	x.add(span{name: "a", start: time.Now(), end: time.Now()})
	for deadline := time.Now().Add(5 * time.Second); x.dropped.Load() < 1 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	}
	if calls.Load() != 1 || x.retries.Load() != 0 {
		t.Errorf("a 400 was tried %d times with %d retries, want exactly one try", calls.Load(), x.retries.Load())
	}
	// A collector that keeps failing is retried the configured number of times, then the batch is dropped.
	status.Store(503)
	calls.Store(0)
	x.add(span{name: "b", start: time.Now(), end: time.Now()})
	for deadline := time.Now().Add(5 * time.Second); x.dropped.Load() < 2 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	}
	x.close()
	if calls.Load() != 4 || x.dropped.Load() != 2 {
		t.Errorf("calls %d dropped %d, want 1+3 tries and 2 dropped spans", calls.Load(), x.dropped.Load())
	}
}

func TestOTLPQueueIsBounded(t *testing.T) {
	gate := make(chan struct{})
	entered := make(chan struct{}, 1)
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-gate
	}))
	t.Cleanup(col.Close)
	x := newOTLPOpts(col.URL, 5*time.Millisecond, OTLPOptions{Queue: 3, Retries: -1})
	x.add(span{name: "first", start: time.Now(), end: time.Now()})
	<-entered // the exporter is now stuck inside send, so it no longer drains the queue
	for i := 0; i < 10; i++ {
		x.add(span{name: "more", start: time.Now(), end: time.Now()})
	}
	if x.dropped.Load() != 7 || len(x.ch) != 3 {
		t.Errorf("dropped %d queued %d, want 7 dropped and 3 queued", x.dropped.Load(), len(x.ch))
	}
	close(gate)
	x.close()
}

func TestOTLPShutdownDoesNotWaitForRetries(t *testing.T) {
	col := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	t.Cleanup(col.Close)
	x := newOTLPOpts(col.URL, 5*time.Millisecond, OTLPOptions{Retries: 10, Backoff: 5 * time.Second})
	x.add(span{name: "a", start: time.Now(), end: time.Now()})
	for deadline := time.Now().Add(3 * time.Second); x.failures.Load() < 1 && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
	}
	start := time.Now()
	x.close()
	if time.Since(start) > time.Second {
		t.Errorf("close took %v while a retry was waiting", time.Since(start))
	}
}

// ---- access log rotation ----

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"100": 100, "64k": 64 << 10, "10MB": 10 << 20, "1g": 1 << 30, " 2 kb ": 2 << 10, "0": 0} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v, want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ten", "-5", "1.5m", "5x"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}

func rotatedFiles(t *testing.T, path string) []string {
	t.Helper()
	m, _ := filepath.Glob(path + ".*")
	return m
}

func TestRotatingFileRotatesBySizeAndKeepsN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	now := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	f, err := newRotatingFile(path, RotateOptions{MaxSize: 20, Keep: 2, Now: func() time.Time { now = now.Add(time.Second); return now }})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := f.Write([]byte("0123456789\n")); err != nil { // 11 bytes: two lines never fit in 20
			t.Fatal(err)
		}
	}
	f.Close() // waits for pruning
	rot := rotatedFiles(t, path)
	if len(rot) != 2 {
		t.Fatalf("kept %v, want the newest 2 rotated files", rot)
	}
	if f.rotations.Load() != 5 {
		t.Errorf("rotations = %d, want 5", f.rotations.Load())
	}
	cur, _ := os.ReadFile(path)
	if string(cur) != "0123456789\n" {
		t.Errorf("current file = %q", cur)
	}
	for _, r := range rot {
		if b, _ := os.ReadFile(r); string(b) != "0123456789\n" {
			t.Errorf("%s = %q, want exactly one whole line (never split across files)", r, b)
		}
	}
}

func TestRotatingFileGzipAndOversizedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	f, err := newRotatingFile(path, RotateOptions{MaxSize: 10, Gzip: true})
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 50) + "\n"
	f.Write([]byte(big)) // larger than MaxSize but the file is empty: it must still land
	f.Write([]byte("next\n"))
	f.Close()
	rot := rotatedFiles(t, path)
	if len(rot) != 1 || !strings.HasSuffix(rot[0], ".gz") {
		t.Fatalf("rotated files = %v, want one .gz", rot)
	}
	fh, _ := os.Open(rot[0])
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if string(b) != big {
		t.Errorf("decompressed %q", b)
	}
	if cur, _ := os.ReadFile(path); string(cur) != "next\n" {
		t.Errorf("current = %q", cur)
	}
}

func TestRotatingFileReopenOnSIGHUPSemantics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.log")
	f, _ := newRotatingFile(path, RotateOptions{})
	f.Write([]byte("one\n"))
	// The file is still ours: a reopen rotates it.
	if err := f.Reopen(); err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("two\n"))
	if rot := rotatedFiles(t, path); len(rot) != 1 {
		t.Fatalf("SIGHUP on our own file should rotate it: %v", rot)
	} else if b, _ := os.ReadFile(rot[0]); string(b) != "one\n" {
		t.Errorf("rotated = %q", b)
	}
	// An external rotation (logrotate renamed it): reopen creates the path fresh and does not rotate again.
	if err := os.Rename(path, path+".external"); err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("lost-to-old-inode\n")) // still goes to the renamed file, as with any open fd
	if err := f.Reopen(); err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("three\n"))
	f.Close()
	if b, _ := os.ReadFile(path); string(b) != "three\n" {
		t.Errorf("after reopen the path holds %q", b)
	}
	if b, _ := os.ReadFile(path + ".external"); !strings.Contains(string(b), "lost-to-old-inode") {
		t.Errorf("external file = %q", b)
	}
	if len(rotatedFiles(t, path)) != 2 { // the earlier rotation and the external file
		t.Errorf("unexpected extra rotation: %v", rotatedFiles(t, path))
	}
}

func TestRotationThroughAccessLogAndMetrics(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	rf, err := newRotatingFile(path, RotateOptions{MaxSize: 600})
	if err != nil {
		t.Fatal(err)
	}
	up := newUpstream(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": up.addr()}), func(o *Options) { o.AccessLog = rf })
	for i := 0; i < 12; i++ {
		get(t, s, "x.test", "/")
	}
	s.FlushAccessLog()
	rf.Close()
	if len(rotatedFiles(t, path)) == 0 {
		t.Fatal("no rotation happened")
	}
	var total int
	files := append(rotatedFiles(t, path), path)
	for _, fn := range files {
		b, _ := os.ReadFile(fn)
		total += strings.Count(string(b), "\n")
	}
	if total != 12 {
		t.Errorf("%d lines across %d files, want 12 (none lost by rotation)", total, len(files))
	}
	var buf bytes.Buffer
	rec := httptest.NewRecorder()
	s.metrics(rec, nil)
	buf.Write(rec.Body.Bytes())
	if !strings.Contains(buf.String(), "setura_gateway_accesslog_rotations_total") {
		t.Errorf("rotation metric missing:\n%s", buf.String())
	}
}

// ---- trusted proxies ----

func mustTrusted(t *testing.T, s string) trustedNets {
	t.Helper()
	p, err := ParseTrustedProxies(s)
	if err != nil {
		t.Fatal(err)
	}
	return trustedNets(p)
}

func TestParseTrustedProxies(t *testing.T) {
	if p, err := ParseTrustedProxies("10.0.0.0/8, 192.168.1.7 ,fd00::/8"); err != nil || len(p) != 3 {
		t.Fatalf("%v %v", p, err)
	}
	if p, err := ParseTrustedProxies(""); err != nil || len(p) != 0 {
		t.Errorf("empty list = %v %v", p, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "banana", "1.2.3"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClientIPHonoursXFFOnlyFromTrustedPeers(t *testing.T) {
	tn := mustTrusted(t, "10.0.0.0/8,127.0.0.1")
	mk := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	for _, c := range []struct {
		name string
		r    *http.Request
		want string
	}{
		{"untrusted peer, spoofed XFF ignored", mk("203.0.113.9:1234", "1.1.1.1"), "203.0.113.9"},
		{"trusted peer, client in XFF", mk("10.1.1.1:80", "198.51.100.4"), "198.51.100.4"},
		{"chain of trusted hops walked right to left", mk("10.1.1.1:80", "198.51.100.4, 10.2.2.2, 10.3.3.3"), "198.51.100.4"},
		{"spoofed left part ignored behind a real hop", mk("10.1.1.1:80", "6.6.6.6, 198.51.100.4"), "198.51.100.4"},
		{"several header lines", mk("10.1.1.1:80", "6.6.6.6", "198.51.100.4"), "198.51.100.4"},
		{"trusted peer without XFF", mk("10.1.1.1:80"), "10.1.1.1"},
		{"everything trusted: leftmost", mk("10.1.1.1:80", "10.9.9.9, 10.8.8.8"), "10.9.9.9"},
		{"garbage entry stops at the last verified hop", mk("10.1.1.1:80", "198.51.100.4, nonsense"), "10.1.1.1"},
		{"ipv6 with brackets", mk("10.1.1.1:80", "[2001:db8::1]:443"), "2001:db8::1"},
		{"ipv4-mapped peer", mk("[::ffff:10.0.0.5]:80", "198.51.100.4"), "198.51.100.4"},
	} {
		if got := tn.clientIP(c.r); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got := (trustedNets)(nil).clientIP(mk("10.1.1.1:80", "198.51.100.4")); got != "10.1.1.1" {
		t.Errorf("no trusted proxies configured: %q", got)
	}
}

type memLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (m *memLog) Write(p []byte) (int, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.b.Write(p) }
func (m *memLog) String() string              { m.mu.Lock(); defer m.mu.Unlock(); return m.b.String() }

func TestTrustedProxiesEndToEnd(t *testing.T) {
	up := newUpstream(t, "a")
	raw := snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": up.addr()})
	run := func(trusted string) (*Server, *memLog) {
		lg := &memLog{}
		s := startServer(t, raw, func(o *Options) {
			o.AccessLog = lg
			if trusted != "" {
				o.Obs.TrustedProxies = mustTrusted(t, trusted)
			}
		})
		return s, lg
	}

	// Untrusted: the spoofed header is replaced, not appended to.
	s, lg := run("")
	r := get(t, s, "x.test", "/", "X-Forwarded-For", "203.0.113.50")
	if got := r.Echo.Headers["x-forwarded-for"]; got != "127.0.0.1" {
		t.Errorf("untrusted peer: upstream saw X-Forwarded-For %q, want just the peer", got)
	}
	s.FlushAccessLog()
	if !strings.Contains(lg.String(), `"client_ip":"127.0.0.1"`) {
		t.Errorf("untrusted access log: %s", lg.String())
	}

	// Trusted: the chain is honoured, the peer appended, client_ip is the real client.
	s, lg = run("127.0.0.0/8")
	r = get(t, s, "x.test", "/", "X-Forwarded-For", "203.0.113.50")
	if got := r.Echo.Headers["x-forwarded-for"]; got != "203.0.113.50, 127.0.0.1" {
		t.Errorf("trusted peer: upstream saw X-Forwarded-For %q, want the chain with the peer appended", got)
	}
	s.FlushAccessLog()
	if !strings.Contains(lg.String(), `"client_ip":"203.0.113.50"`) {
		t.Errorf("trusted access log: %s", lg.String())
	}
}

func TestRateLimitKeyUsesTrustedClientIP(t *testing.T) {
	up := newUpstream(t, "a")
	raw := snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": up.addr()})
	now := time.Unix(1_700_000_000, 0)
	mk := func(trusted string) *Server {
		return startServer(t, raw, func(o *Options) {
			o.Obs.Now = func() time.Time { return now }
			o.Obs.RateLimit = RateLimitConfig{Rate: 1, Burst: 1, Key: "ip"}
			if trusted != "" {
				o.Obs.TrustedProxies = mustTrusted(t, trusted)
			}
		})
	}
	// Behind a trusted proxy two real clients have separate buckets.
	s := mk("127.0.0.1")
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if r := get(t, s, "x.test", "/", "X-Forwarded-For", ip); r.Status != 200 {
			t.Fatalf("client %s: %d", ip, r.Status)
		}
	}
	if r := get(t, s, "x.test", "/", "X-Forwarded-For", "198.51.100.1"); r.Status != 429 {
		t.Errorf("same real client twice: %d, want 429", r.Status)
	}
	// Without trust a client cannot dodge the limit by rotating the header.
	s = mk("")
	get(t, s, "x.test", "/", "X-Forwarded-For", "198.51.100.1")
	if r := get(t, s, "x.test", "/", "X-Forwarded-For", "198.51.100.77"); r.Status != 429 {
		t.Errorf("rotating X-Forwarded-For dodged the limit: %d", r.Status)
	}
}

// ---- rate-limit share ----

func TestRateLimitShareDividesRateAndBurst(t *testing.T) {
	l := newLimiter(RateLimitConfig{Rate: 100, Per: time.Second, Share: 4}, nil)
	if l.perSec != 25 || l.burst != 25 {
		t.Errorf("rate %.1f burst %.1f, want 25 and 25 (100/s over 4 replicas)", l.perSec, l.burst)
	}
	l = newLimiter(RateLimitConfig{Rate: 100, Burst: 10, Share: 4}, nil)
	if l.burst != 3 { // ceil(10/4)
		t.Errorf("explicit burst divided to %.1f, want 3", l.burst)
	}
	l = newLimiter(RateLimitConfig{Rate: 1, Share: 8}, nil)
	if l.burst < 1 {
		t.Errorf("burst %.1f must stay at least 1", l.burst)
	}
	if err := (&RateLimitConfig{Rate: 1, Share: -1}).validate(); err == nil {
		t.Error("negative share accepted")
	}
	l = newLimiter(RateLimitConfig{Rate: 100, Share: 0}, nil)
	if l.perSec != 100 {
		t.Errorf("share 0 must mean one replica, rate %.1f", l.perSec)
	}
}

func TestRateLimitShareEnforcedPerReplica(t *testing.T) {
	up := newUpstream(t, "a")
	now := time.Unix(1_700_000_000, 0)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": up.addr()}), func(o *Options) {
		o.Obs.Now = func() time.Time { return now }
		o.Obs.RateLimit = RateLimitConfig{Rate: 8, Burst: 8, Key: "route", Share: 4}
	})
	ok := 0
	for i := 0; i < 6; i++ {
		if get(t, s, "x.test", "/").Status == 200 {
			ok++
		}
	}
	if ok != 2 {
		t.Errorf("%d requests admitted at once, want 2 (burst 8 shared by 4 replicas)", ok)
	}
}

func TestObsFlagsParse(t *testing.T) {
	var o Options
	f := obsFlags{format: "json", rate: "40/s", key: "ip", share: 4, trusted: "10.0.0.0/8", otlpRetries: 2, otlpQueue: 9, otlpBackoff: time.Second}
	if err := f.apply(&o); err != nil {
		t.Fatal(err)
	}
	if o.Obs.RateLimit.Share != 4 || len(o.Obs.TrustedProxies) != 1 || o.Obs.OTLP.Retries != 2 || o.Obs.OTLP.Queue != 9 {
		t.Errorf("options = %+v", o.Obs)
	}
	for _, bad := range []obsFlags{{format: "json", trusted: "nope"}, {format: "json", share: -1}} {
		if err := bad.apply(&Options{}); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
