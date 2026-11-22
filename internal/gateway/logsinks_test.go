package gateway

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---- a tiny protobuf reader for the fake collectors ----

type tpbField struct {
	num  int
	wire int
	v    uint64 // varint or fixed
	b    []byte // length delimited
}

func pbRead(t testing.TB, b []byte) []tpbField {
	t.Helper()
	var out []tpbField
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			t.Fatalf("bad tag in %x", b)
		}
		b = b[n:]
		f := tpbField{num: int(tag >> 3), wire: int(tag & 7)}
		switch f.wire {
		case 0:
			f.v, n = binary.Uvarint(b)
			b = b[n:]
		case 1:
			f.v, b = binary.LittleEndian.Uint64(b), b[8:]
		case 5:
			f.v, b = uint64(binary.LittleEndian.Uint32(b)), b[4:]
		case 2:
			l, n := binary.Uvarint(b)
			f.b, b = b[n:n+int(l)], b[n+int(l):]
		default:
			t.Fatalf("wire type %d", f.wire)
		}
		out = append(out, f)
	}
	return out
}

func pbFind(fs []tpbField, num int) []tpbField {
	var out []tpbField
	for _, f := range fs {
		if f.num == num {
			out = append(out, f)
		}
	}
	return out
}

// kvs decodes repeated KeyValue fields into a map of string or decimal values.
func kvs(t testing.TB, fs []tpbField, num int) map[string]string {
	out := map[string]string{}
	for _, kv := range pbFind(fs, num) {
		p := pbRead(t, kv.b)
		key := string(pbFind(p, 1)[0].b)
		v := pbRead(t, pbFind(p, 2)[0].b)
		if s := pbFind(v, 1); len(s) > 0 {
			out[key] = string(s[0].b)
		} else if n := pbFind(v, 3); len(n) > 0 {
			out[key] = itoa(int64(n[0].v))
		}
	}
	return out
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

// ---- a fake OTLP/gRPC collector on an in-process h2c server ----

type colServer struct {
	URL      string
	mu       sync.Mutex
	calls    []colCall
	statuses []string // grpc-status to answer with, one per call; "0" after the list runs out
}

type colCall struct {
	path  string
	msg   []byte
	h     http.Header
	proto int
}

func newColServer(t *testing.T, statuses ...string) *colServer {
	t.Helper()
	c := &colServer{statuses: statuses}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Protocols: &p, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) < 5 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
			http.Error(w, "bad frame", 400)
			return
		}
		c.mu.Lock()
		st := "0"
		if len(c.calls) < len(c.statuses) {
			st = c.statuses[len(c.calls)]
		}
		c.calls = append(c.calls, colCall{path: r.URL.Path, msg: body[5:], h: r.Header.Clone(), proto: r.ProtoMajor})
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write([]byte{0, 0, 0, 0, 0}) // empty ExportResponse
		w.Header().Set("Grpc-Status", st)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	c.URL = "http://" + ln.Addr().String()
	return c
}

func (c *colServer) snapshot() []colCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]colCall(nil), c.calls...)
}

func TestOTLPGRPCSpansToH2CCollector(t *testing.T) {
	col := newColServer(t)
	s, _ := obsServer(t, func(o *Options) {
		o.Obs.OTLPEndpoint = col.URL
		o.Obs.OTLP = OTLPOptions{Protocol: "grpc"}
	})
	in := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if r := get(t, s, "x.test", "/ok", "Traceparent", in); r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	s.FlushAccessLog()
	s.obs.otlp.close() // flushes the batch
	calls := col.snapshot()
	if len(calls) != 1 {
		t.Fatalf("calls %d", len(calls))
	}
	c := calls[0]
	if c.path != otlpTracePath || c.proto != 2 || c.h.Get("Content-Type") != "application/grpc" || c.h.Get("Te") != "trailers" {
		t.Errorf("call %s proto %d headers %v", c.path, c.proto, c.h)
	}
	rs := pbRead(t, pbFind(pbRead(t, c.msg), 1)[0].b)
	res := pbRead(t, pbFind(rs, 1)[0].b)
	if kvs(t, res, 1)["service.name"] != "setura-gateway" {
		t.Errorf("resource %v", kvs(t, res, 1))
	}
	ss := pbRead(t, pbFind(rs, 2)[0].b)
	sp := pbRead(t, pbFind(ss, 2)[0].b)
	if got := pbFind(sp, 1)[0].b; hexOf(got) != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("trace id %x", got)
	}
	if got := pbFind(sp, 4)[0].b; hexOf(got) != "00f067aa0ba902b7" {
		t.Errorf("parent span id %x", got)
	}
	if string(pbFind(sp, 5)[0].b) != "GET t/r" || pbFind(sp, 6)[0].v != 2 {
		t.Errorf("name %q kind %d", pbFind(sp, 5)[0].b, pbFind(sp, 6)[0].v)
	}
	if pbFind(sp, 7)[0].v == 0 || pbFind(sp, 8)[0].v < pbFind(sp, 7)[0].v {
		t.Errorf("times %d %d", pbFind(sp, 7)[0].v, pbFind(sp, 8)[0].v)
	}
	at := kvs(t, sp, 9)
	if at["http.response.status_code"] != "200" || at["setura.route"] != "t/r" || at["url.path"] != "/ok" {
		t.Errorf("attributes %v", at)
	}
	if got := s.obs.otlp.exported.Load(); got != 1 {
		t.Errorf("exported %d", got)
	}
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	var o []byte
	for _, c := range b {
		o = append(o, d[c>>4], d[c&15])
	}
	return string(o)
}

func TestOTLPGRPCRetriesUnavailableAndDropsInvalid(t *testing.T) {
	col := newColServer(t, "14", "14", "0", "3") // UNAVAILABLE twice, OK, then INVALID_ARGUMENT
	x := newOTLPOpts(col.URL, time.Hour, OTLPOptions{Protocol: "grpc", Backoff: time.Millisecond})
	sp := span{trace: traceInfo{TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7"}, name: "GET x", start: time.Unix(1, 0), end: time.Unix(2, 0), status: 200}
	x.send([]span{sp})
	if x.exported.Load() != 1 || x.retries.Load() != 2 || x.failures.Load() != 2 || x.dropped.Load() != 0 {
		t.Fatalf("exported %d retries %d failures %d dropped %d", x.exported.Load(), x.retries.Load(), x.failures.Load(), x.dropped.Load())
	}
	x.send([]span{sp}) // INVALID_ARGUMENT: no retry, dropped
	if x.exported.Load() != 1 || x.retries.Load() != 2 || x.dropped.Load() != 1 || len(col.snapshot()) != 4 {
		t.Fatalf("exported %d retries %d dropped %d calls %d", x.exported.Load(), x.retries.Load(), x.dropped.Load(), len(col.snapshot()))
	}
	x.close()
}

func TestOTLPGRPCDeadCollectorNeverBlocksRequests(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens
	s, _ := obsServer(t, func(o *Options) {
		o.Obs.OTLPEndpoint = addr
		o.Obs.OTLP = OTLPOptions{Protocol: "grpc", Queue: 2, Retries: -1}
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			get(t, s, "x.test", "/ok")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("requests stalled behind a dead OTLP/gRPC collector")
	}
}

func TestOTLPLogsOverGRPCAndHTTP(t *testing.T) {
	col := newColServer(t)
	var mu sync.Mutex
	var httpBody []byte
	hc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		httpBody = b
		mu.Unlock()
		if r.URL.Path != "/v1/logs" {
			t.Errorf("path %s", r.URL.Path)
		}
	}))
	defer hc.Close()
	g, err := newOTLPLogsSink(col.URL, "grpc", SinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := newOTLPLogsSink(hc.URL, "http", SinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	l := &logLine{Time: "2026-11-22T10:00:00.5Z", Host: "x.test", Method: "GET", Path: "/ok", Status: 503, Route: "t/r", TraceID: "4bf92f3577b34da6a3ce929d0e0e4736", SpanID: "00f067aa0ba902b7"}
	g.offer(l)
	h.offer(l)
	g.close()
	h.close()
	calls := col.snapshot()
	if len(calls) != 1 || calls[0].path != otlpLogsPath {
		t.Fatalf("grpc calls %+v", calls)
	}
	rl := pbRead(t, pbFind(pbRead(t, calls[0].msg), 1)[0].b)
	sl := pbRead(t, pbFind(rl, 2)[0].b)
	rec := pbRead(t, pbFind(sl, 2)[0].b)
	if pbFind(rec, 2)[0].v != 17 || string(pbFind(rec, 3)[0].b) != "ERROR" {
		t.Errorf("severity %d %s", pbFind(rec, 2)[0].v, pbFind(rec, 3)[0].b)
	}
	if got := time.Unix(0, int64(pbFind(rec, 1)[0].v)).UTC(); !got.Equal(time.Date(2026, 11, 22, 10, 0, 0, 500000000, time.UTC)) {
		t.Errorf("time %s", got)
	}
	body := pbRead(t, pbFind(rec, 5)[0].b)
	if !strings.Contains(string(pbFind(body, 1)[0].b), `"status":503`) {
		t.Errorf("body %s", pbFind(body, 1)[0].b)
	}
	if hexOf(pbFind(rec, 9)[0].b) != l.TraceID || kvs(t, rec, 6)["http.response.status_code"] != "503" {
		t.Errorf("trace/attrs %v", kvs(t, rec, 6))
	}
	mu.Lock()
	defer mu.Unlock()
	var doc struct {
		ResourceLogs []struct {
			ScopeLogs []struct {
				LogRecords []struct {
					SeverityNumber int    `json:"severityNumber"`
					TraceID        string `json:"traceId"`
					TimeUnixNano   string `json:"timeUnixNano"`
				} `json:"logRecords"`
			} `json:"scopeLogs"`
		} `json:"resourceLogs"`
	}
	if err := json.Unmarshal(httpBody, &doc); err != nil {
		t.Fatalf("%v: %s", err, httpBody)
	}
	r0 := doc.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
	if r0.SeverityNumber != 17 || r0.TraceID != l.TraceID || r0.TimeUnixNano != "1795341600500000000" {
		t.Errorf("json record %+v", r0)
	}
}

func TestLokiPush(t *testing.T) {
	var mu sync.Mutex
	var got []byte
	var hdr http.Header
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got, hdr, path = b, r.Header.Clone(), r.URL.Path
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer srv.Close()
	k, err := newLokiSink(srv.URL, map[string]string{"job": "gw", "env": "test"}, "tenant1", SinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	k.offer(&logLine{Time: "2026-11-22T10:00:00Z", Method: "GET", Path: "/a", Status: 200})
	k.offer(&logLine{Time: "2026-11-22T10:00:01Z", Method: "GET", Path: "/b", Status: 502})
	k.close()
	mu.Lock()
	defer mu.Unlock()
	if path != "/loki/api/v1/push" || hdr.Get("X-Scope-OrgID") != "tenant1" || hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("path %s headers %v", path, hdr)
	}
	var doc struct {
		Streams []struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("%v: %s", err, got)
	}
	if len(doc.Streams) != 2 || doc.Streams[0].Stream["level"] != "error" || doc.Streams[1].Stream["level"] != "info" {
		t.Fatalf("streams %+v", doc.Streams)
	}
	st := doc.Streams[1]
	if st.Stream["job"] != "gw" || st.Stream["env"] != "test" || st.Values[0][0] != "1795341600000000000" || !strings.Contains(st.Values[0][1], `"path":"/a"`) {
		t.Errorf("stream %+v", st)
	}
	if k.sent.Load() != 2 {
		t.Errorf("sent %d", k.sent.Load())
	}
}

func TestLokiRetriesAfter503(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	var waits []time.Duration
	var mu sync.Mutex
	after := func(d time.Duration) <-chan time.Time {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		c := make(chan time.Time, 1)
		c <- time.Now()
		return c
	}
	k, _ := newLokiSink(srv.URL, nil, "", SinkOptions{Batch: 1, After: after})
	k.offer(&logLine{Time: "2026-11-22T10:00:00Z", Status: 200})
	waitFor(t, "sink", func() bool { return k.sent.Load() == 1 })
	k.close()
	if k.retries.Load() != 2 || k.failures.Load() != 2 || k.dropped.Load() != 0 || calls.Load() != 3 {
		t.Errorf("retries %d failures %d dropped %d calls %d", k.retries.Load(), k.failures.Load(), k.dropped.Load(), calls.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	for i, w := range waits { // Retry-After: 1 wins over the 250ms backoff
		if w < time.Second || w > 1250*time.Millisecond {
			t.Errorf("wait %d = %s, want Retry-After of 1s plus jitter", i, w)
		}
	}
}

func TestSinkBackoffScheduleAndExhaustion(t *testing.T) {
	var waits []time.Duration
	var mu sync.Mutex
	after := func(d time.Duration) <-chan time.Time {
		mu.Lock()
		waits = append(waits, d)
		mu.Unlock()
		c := make(chan time.Time, 1)
		c <- time.Now()
		return c
	}
	var attempts atomic.Int64
	k := newBatchSink("t", SinkOptions{Backoff: 100 * time.Millisecond, Retries: 3, Batch: 2, After: after}, func(b []logLine) (int, error) {
		attempts.Add(1)
		return 0, &sinkErr{err: errors.New("down"), retry: true}
	}, nil)
	k.offer(&logLine{})
	k.offer(&logLine{}) // batch is full: delivered at once, no timer involved
	waitFor(t, "sink", func() bool { return k.dropped.Load() == 2 })
	if attempts.Load() != 4 || k.retries.Load() != 3 || k.failures.Load() != 4 || k.sent.Load() != 0 {
		t.Errorf("attempts %d retries %d failures %d sent %d", attempts.Load(), k.retries.Load(), k.failures.Load(), k.sent.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}
	if len(waits) != 3 {
		t.Fatalf("waits %v", waits)
	}
	for i, w := range want {
		if waits[i] < w || waits[i] > w+w/4 {
			t.Errorf("wait %d = %s, want %s plus up to 25%%", i, waits[i], w)
		}
	}
	k.close()
}

func TestSinkQueueIsBoundedAndNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	k := newBatchSink("t", SinkOptions{Queue: 4, Batch: 1}, func(b []logLine) (int, error) {
		<-release
		return len(b), nil
	}, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			k.offer(&logLine{Status: 200})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("offer blocked on a stuck sink")
	}
	if d := k.dropped.Load(); d < 990 {
		t.Errorf("dropped %d, want nearly all of 1000 with a queue of 4", d)
	}
	close(release)
	k.close()
	if k.sent.Load()+k.dropped.Load() != 1000 {
		t.Errorf("sent %d + dropped %d != 1000", k.sent.Load(), k.dropped.Load())
	}
}

func TestSinkNonRetryableDropsAtOnce(t *testing.T) {
	var attempts atomic.Int64
	k := newBatchSink("t", SinkOptions{Batch: 1}, func(b []logLine) (int, error) {
		attempts.Add(1)
		return 0, &sinkErr{err: errors.New("bad request")}
	}, nil)
	k.offer(&logLine{})
	waitFor(t, "sink", func() bool { return k.dropped.Load() == 1 })
	if attempts.Load() != 1 || k.retries.Load() != 0 {
		t.Errorf("attempts %d retries %d", attempts.Load(), k.retries.Load())
	}
	k.close()
}

// ---- syslog ----

var rfc5424 = regexp.MustCompile(`^<(\d+)>1 (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z) (\S+) setura-gateway (\d+) ACCESS - (.*)$`)

func checkSyslog(t *testing.T, msg string, pri string) {
	t.Helper()
	m := rfc5424.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("not RFC 5424: %q", msg)
	}
	if m[1] != pri || m[2] != "2026-11-22T10:00:00.500000Z" || !strings.Contains(m[5], `status=503`) || !strings.Contains(m[5], `path="/ok"`) {
		t.Errorf("fields %v", m)
	}
}

func syslogLine() *logLine {
	return &logLine{Time: "2026-11-22T10:00:00.5Z", Host: "x.test", Method: "GET", Path: "/ok", Status: 503}
}

func TestSyslogUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	k, err := newSyslogSink("udp://"+pc.LocalAddr().String(), SinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	k.offer(syslogLine())
	k.close()
	buf := make([]byte, 65535)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	checkSyslog(t, string(buf[:n]), "131") // local0 (16*8) + err (3)
}

func TestSyslogTCPOctetCounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 4)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- string(b)
	}()
	k, err := newSyslogSink("tcp://"+ln.Addr().String(), SinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	k.offer(syslogLine())
	k.offer(syslogLine())
	k.close() // closes the connection, ending the reader
	data := <-got
	for i := 0; i < 2; i++ {
		sp := strings.IndexByte(data, ' ')
		var n int
		for _, c := range data[:sp] {
			n = n*10 + int(c-'0')
		}
		checkSyslog(t, data[sp+1:sp+1+n], "131")
		data = data[sp+1+n:]
	}
	if data != "" {
		t.Errorf("leftover %q", data)
	}
	if k.sent.Load() != 2 {
		t.Errorf("sent %d", k.sent.Load())
	}
}

func TestSyslogUnixSocketsAndReconnect(t *testing.T) {
	dir, err := os.MkdirTemp("", "sl")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "log")
	pc, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	k, err := newSyslogSink("unixgram://"+sock, SinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	k.offer(syslogLine())
	k.close()
	buf := make([]byte, 65535)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	checkSyslog(t, string(buf[:n]), "131")

	// stream socket: an unreachable server fails, retries, and the lines are counted as dropped
	k2, err := newSyslogSink("unix://"+filepath.Join(dir, "nobody"), SinkOptions{Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	k2.offer(syslogLine())
	k2.close()
	if k2.dropped.Load() != 1 || k2.failures.Load() != 1 {
		t.Errorf("dropped %d failures %d", k2.dropped.Load(), k2.failures.Load())
	}
}

func TestSyslogAddrErrors(t *testing.T) {
	for _, bad := range []string{"ftp://x:1", "tcp://nohostport", "unix://"} {
		if _, _, err := parseSyslogAddr(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if n, a, err := parseSyslogAddr("127.0.0.1:514"); err != nil || n != "udp" || a != "127.0.0.1:514" {
		t.Errorf("bare address: %s %s %v", n, a, err)
	}
}

// TestSinksThroughServer wires every sink to fake collectors, sends requests
// and checks the lines arrive and the metrics count them.
func TestSinksThroughServer(t *testing.T) {
	var mu sync.Mutex
	var lokiBody []byte
	loki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		lokiBody = append(lokiBody, b...)
		mu.Unlock()
		w.WriteHeader(204)
	}))
	defer loki.Close()
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	col := newColServer(t)
	s, _ := obsServer(t, func(o *Options) {
		o.Obs.Logs = LogSinkOptions{Syslog: "udp://" + pc.LocalAddr().String(), LokiURL: loki.URL, OTLPLogs: col.URL, OTLPProtocol: "grpc"}
	})
	for i := 0; i < 3; i++ {
		get(t, s, "x.test", "/ok")
	}
	s.FlushAccessLog()
	for _, k := range s.obs.sinks {
		k.close()
	}
	if len(s.obs.sinks) != 3 {
		t.Fatalf("sinks %d", len(s.obs.sinks))
	}
	for _, k := range s.obs.sinks {
		if k.sent.Load() != 3 || k.dropped.Load() != 0 {
			t.Errorf("%s sent %d dropped %d", k.name, k.sent.Load(), k.dropped.Load())
		}
	}
	mu.Lock()
	if strings.Count(string(lokiBody), `\"path\":\"/ok\"`) != 3 {
		t.Errorf("loki body %s", lokiBody)
	}
	mu.Unlock()
	out := metricsOf(s)
	for _, want := range []string{`setura_gateway_logsink_sent_total{sink="syslog"} 3`, `setura_gateway_logsink_sent_total{sink="loki"} 3`, `setura_gateway_logsink_sent_total{sink="otlp_logs"} 3`, `setura_gateway_logsink_dropped_total{sink="loki"} 0`} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestLogSinkFlags(t *testing.T) {
	var f obsFlags
	var o Options
	f.format = "json"
	f.syslog = "bogus://x"
	if err := f.apply(&o); err == nil {
		t.Error("bad syslog address accepted")
	}
	f.syslog, f.otlpProto = "", "carrier-pigeon"
	if err := f.apply(&o); err == nil {
		t.Error("bad otlp protocol accepted")
	}
	f.otlpProto, f.lokiLabel = "grpc", "a=b,c=d"
	if err := f.apply(&o); err != nil || o.Obs.Logs.LokiLabels["c"] != "d" || o.Obs.OTLP.Protocol != "grpc" {
		t.Errorf("apply: %v %+v", err, o.Obs.Logs)
	}
}
