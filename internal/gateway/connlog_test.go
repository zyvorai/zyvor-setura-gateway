package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// history returns the connection records newest first.
func history(s *Server) []*logLine { return s.Connections(1000, 0).History }

// waitLatest waits until n records exist (they are written just after the
// response, so a client can be quicker than the log).
func waitLatest(t *testing.T, s *Server, n int64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("%d connection records", n), func() bool { return s.Connections(1, 0).Latest >= n })
}

func lastRecord(t *testing.T, s *Server) *logLine {
	t.Helper()
	// Records are written just after the response, so give them a moment.
	waitFor(t, "a connection record", func() bool { return len(history(s)) > 0 })
	return history(s)[0]
}

func TestConnRecordHTTP1(t *testing.T) {
	var buf syncBuf
	s, ups := obsServer(t, func(o *Options) { o.AccessLog = &buf })
	long := strings.Repeat("ua", 200)
	r := req(t, client(s.Addr(8080), nil), "http", "POST", "x.test", "/ok?token=secret", "hello", "User-Agent", long, "X-Forwarded-For", "9.9.9.9, 10.0.0.1")
	if r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	s.FlushAccessLog()
	rec := lastRecord(t, s)
	if rec.ClientIP != "127.0.0.1" || rec.ClientPort == 0 || rec.Remote != fmt.Sprintf("127.0.0.1:%d", rec.ClientPort) {
		t.Errorf("client %q:%d remote %q", rec.ClientIP, rec.ClientPort, rec.Remote)
	}
	if rec.ListenerPort != portOf(s.Addr(8080)) || rec.Listener != "t/gw/web" {
		t.Errorf("listener %q port %d, want %d", rec.Listener, rec.ListenerPort, portOf(s.Addr(8080)))
	}
	if rec.Protocol != "HTTP/1.1" || rec.HTTPVersion != "HTTP/1.1" || rec.TLSVersion != "" {
		t.Errorf("protocol %q http %q tls %q", rec.Protocol, rec.HTTPVersion, rec.TLSVersion)
	}
	if rec.UpstreamAddr != ups["a"].addr() || rec.UpstreamProto != "http/1.1" || rec.UpstreamStatus != 200 {
		t.Errorf("upstream %q %q %d, want %s", rec.UpstreamAddr, rec.UpstreamProto, rec.UpstreamStatus, ups["a"].addr())
	}
	if rec.UpstreamTLS == nil || *rec.UpstreamTLS || rec.UpstreamReused == nil || *rec.UpstreamReused {
		t.Errorf("tls/reused %v %v, want false false", rec.UpstreamTLS, rec.UpstreamReused)
	}
	if rec.UpstreamConnectMS <= 0 || rec.UpstreamTTFBMS <= 0 {
		t.Errorf("connect %v ttfb %v, want > 0", rec.UpstreamConnectMS, rec.UpstreamTTFBMS)
	}
	if rec.UpstreamHealth != "healthy" || rec.BackendWeight != 1 || rec.Match == nil || *rec.Match != 0 || rec.Rule == nil {
		t.Errorf("health %q weight %d match %v", rec.UpstreamHealth, rec.BackendWeight, rec.Match)
	}
	if rec.RequestBytes != 5 || rec.ResponseBytes != rec.Bytes || rec.Bytes == 0 {
		t.Errorf("bytes in %d out %d/%d", rec.RequestBytes, rec.ResponseBytes, rec.Bytes)
	}
	if len(rec.UserAgent) != 200 || rec.XFF != "9.9.9.9, 10.0.0.1" {
		t.Errorf("ua len %d xff %q", len(rec.UserAgent), rec.XFF)
	}
	if rec.Path != "/ok" {
		t.Errorf("path %q, want the query stripped", rec.Path)
	}
	if rec.Retries != 0 || rec.Attempts != nil || rec.RateLimited {
		t.Errorf("retries %d attempts %v", rec.Retries, rec.Attempts)
	}
	// The same fields reach the JSON log, and no secret does.
	ls := logLines(t, &buf)
	if len(ls) != 1 {
		t.Fatalf("log lines %v", ls)
	}
	for _, k := range []string{"client_ip", "client_port", "listener_port", "protocol", "upstream_addr", "upstream_protocol", "upstream_status",
		"upstream_connect_ms", "upstream_ttfb_ms", "upstream_tls", "upstream_reused", "request_bytes", "response_bytes", "user_agent", "x_forwarded_for", "backend_weight", "match", "http_version"} {
		if _, ok := ls[0][k]; !ok {
			t.Errorf("log lacks %q: %v", k, ls[0])
		}
	}
	if _, ok := ls[0]["id"]; ok {
		t.Error("history id leaked into the log line")
	}
	if strings.Contains(buf.String(), "secret") {
		t.Errorf("query leaked into the log: %s", buf.String())
	}
	for _, k := range []string{"tls_version", "retries", "attempts", "rate_limited", "grpc_status", "tls_sni"} {
		if _, ok := ls[0][k]; ok {
			t.Errorf("unknown field %q should be omitted", k)
		}
	}
}

func TestConnRecordReuseAndText(t *testing.T) {
	var buf syncBuf
	s, _ := obsServer(t, func(o *Options) { o.AccessLog = &buf; o.Obs.AccessLogFormat = "text" })
	kc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{}}
	for i := 0; i < 2; i++ {
		resp, err := kc.Get("http://" + s.Addr(8080) + "/ok")
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	s.FlushAccessLog()
	waitFor(t, "two records", func() bool { return len(history(s)) == 2 })
	h := history(s)
	if len(h) != 2 {
		t.Fatalf("records %d", len(h))
	}
	if h[1].UpstreamReused == nil || *h[1].UpstreamReused || h[0].UpstreamReused == nil || !*h[0].UpstreamReused {
		t.Errorf("first reused=%v second reused=%v, want false then true", h[1].UpstreamReused, h[0].UpstreamReused)
	}
	if h[0].UpstreamConnectMS != 0 {
		t.Errorf("reused connect_ms = %v, want 0", h[0].UpstreamConnectMS)
	}
	out := buf.String()
	for _, want := range []string{"client_ip=\"127.0.0.1\"", "protocol=\"HTTP/1.1\"", "upstream_addr=\"", "upstream_reused=true", "upstream_status=200", "backend_weight=1", "listener_port="} {
		if !strings.Contains(out, want) {
			t.Errorf("text log lacks %s:\n%s", want, out)
		}
	}
}

func TestLogQueryOption(t *testing.T) {
	s, _ := obsServer(t, func(o *Options) { o.Obs.LogQuery = true })
	get(t, s, "x.test", "/ok?q=1")
	if p := lastRecord(t, s).Path; p != "/ok?q=1" {
		t.Errorf("path %q with --log-query", p)
	}
	s2, _ := obsServer(t, nil)
	get(t, s2, "x.test", "/ok?q=1&token=abc")
	if p := lastRecord(t, s2).Path; p != "/ok" {
		t.Errorf("path %q, want query stripped", p)
	}
}

func TestConnHistoryDisabled(t *testing.T) {
	s, _ := obsServer(t, func(o *Options) { o.ConnHistory = -1 })
	get(t, s, "x.test", "/ok")
	if snap := s.Connections(10, 0); snap.Enabled || len(snap.History) != 0 {
		t.Errorf("snapshot %+v, want disabled", snap)
	}
}

func TestConnRingBounds(t *testing.T) {
	s, _ := obsServer(t, func(o *Options) { o.ConnHistory = 5 })
	for i := 0; i < 12; i++ {
		get(t, s, "x.test", fmt.Sprintf("/ok/%d", i))
	}
	waitLatest(t, s, 12)
	snap := s.Connections(100, 0)
	if snap.Capacity != 5 || len(snap.History) != 5 || snap.Latest != 12 {
		t.Fatalf("cap %d len %d latest %d", snap.Capacity, len(snap.History), snap.Latest)
	}
	for i, l := range snap.History {
		if want := int64(12 - i); l.ID != want {
			t.Errorf("history[%d].id = %d, want %d (newest first)", i, l.ID, want)
		}
	}
	if got := s.Connections(2, 0).History; len(got) != 2 || got[0].ID != 12 {
		t.Errorf("limit 2 -> %d records, first %d", len(got), got[0].ID)
	}
	if got := s.Connections(100, 10).History; len(got) != 2 || got[0].ID != 12 || got[1].ID != 11 {
		t.Errorf("since 10 -> %v", got)
	}
	if got := s.Connections(100, 12).History; len(got) != 0 {
		t.Errorf("since latest -> %d records", len(got))
	}
}

func TestConnectionsEndpoint(t *testing.T) {
	s, _ := obsServer(t, nil)
	get(t, s, "x.test", "/ok")
	get(t, s, "x.test", "/missing")
	waitLatest(t, s, 2)
	srv := httptest.NewServer(http.HandlerFunc(s.connectionsHandler))
	t.Cleanup(srv.Close)
	var doc struct {
		Enabled  bool             `json:"enabled"`
		Capacity int              `json:"capacity"`
		Latest   int64            `json:"latest"`
		History  []map[string]any `json:"history"`
		Open     []any            `json:"open"`
	}
	fetch := func(q string) int {
		resp, err := http.Get(srv.URL + "/connections" + q)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			doc.History = nil
			if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode
	}
	if fetch("") != 200 || !doc.Enabled || doc.Capacity != DefaultConnHistory || len(doc.History) != 2 || doc.Latest != 2 || doc.Open == nil {
		t.Fatalf("doc %+v", doc)
	}
	if doc.History[0]["status"].(float64) != 404 || doc.History[1]["id"].(float64) != 1 {
		t.Errorf("order %v", doc.History)
	}
	if fetch("?since=1") != 200 || len(doc.History) != 1 {
		t.Errorf("since=1 -> %d records", len(doc.History))
	}
	if fetch("?limit=1") != 200 || len(doc.History) != 1 {
		t.Errorf("limit=1 -> %d records", len(doc.History))
	}
	for _, q := range []string{"?limit=0", "?limit=x", "?since=-1", "?since=abc"} {
		if code := fetch(q); code != 400 {
			t.Errorf("%s -> %d, want 400", q, code)
		}
	}
	resp, err := http.Post(srv.URL+"/connections", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST -> %d", resp.StatusCode)
	}
}

func TestConnAdminRoute(t *testing.T) {
	be, _ := upstreams(t, "a")
	path := t.TempDir() + "/gw.json"
	writeFile(t, path, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, be))
	s, _, _ := startFile(t, path, nil)
	get(t, s, "x.test", "/")
	resp, err := http.Get("http://" + s.AdminAddr() + "/connections?limit=5")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var snap ConnSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil || len(snap.History) != 1 {
		t.Fatalf("admin /connections: %v %+v", err, snap)
	}
}

func TestConnRetryAttempts(t *testing.T) {
	bad, good := newFlaky(t, 503), newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute([]int{503}, 2, "0s")}, svcBackend(bad.addr(), good.addr())), resOpts(newClock(), &sleepRec{}, nil))
	if r := get(t, s, "x.test", "/"); r.Status != 200 {
		t.Fatalf("status %d", r.Status)
	}
	rec := lastRecord(t, s)
	if rec.Retries != 1 || len(rec.Attempts) != 2 {
		t.Fatalf("retries %d attempts %+v", rec.Retries, rec.Attempts)
	}
	if rec.Attempts[0].Addr != bad.addr() || rec.Attempts[0].Status != 503 || rec.Attempts[1].Addr != good.addr() || rec.Attempts[1].Status != 200 {
		t.Errorf("attempts %+v", rec.Attempts)
	}
	if rec.UpstreamAddr != good.addr() || rec.UpstreamStatus != 200 {
		t.Errorf("final upstream %q %d", rec.UpstreamAddr, rec.UpstreamStatus)
	}
}

func TestConnRetryConnectError(t *testing.T) {
	good := newFlaky(t, 200)
	dead := deadAddr(t)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": retryRoute(nil, 1, "0s")}, svcBackend(dead, good.addr())), resOpts(newClock(), &sleepRec{}, nil))
	req(t, client(s.Addr(8080), nil), "http", "POST", "x.test", "/", "payload")
	rec := lastRecord(t, s)
	if len(rec.Attempts) != 2 || rec.Attempts[0].Error == "" || rec.Attempts[0].Status != 0 || rec.Attempts[1].Status != 200 {
		t.Errorf("attempts %+v", rec.Attempts)
	}
}

func TestConnEjectedHealth(t *testing.T) {
	bad := newFlaky(t, 503)
	good := newFlaky(t, 200)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("svc", 1)))}, svcBackend(bad.addr(), good.addr())),
		func(o *Options) { o.Resilience.OutlierFailures = 1; o.Resilience.OutlierBaseEject = time.Hour })
	for i := 0; i < 6; i++ {
		get(t, s, "x.test", "/")
	}
	waitLatest(t, s, 6)
	for _, rec := range history(s) {
		if rec.UpstreamAddr == bad.addr() && rec.UpstreamHealth == "ejected" {
			t.Fatal("a request was sent to an ejected endpoint although another was healthy")
		}
	}
	b := s.Table().Backends["t/svc:80"]
	var badEp *Endpoint
	for _, e := range b.Eps {
		if strings.HasSuffix(e.URL.Host, bad.addr()) {
			badEp = e
		}
	}
	if badEp == nil || b.state(badEp, time.Now()) != "ejected" {
		t.Fatalf("bad endpoint state %q", b.state(badEp, time.Now()))
	}
}

func TestConnRateLimited(t *testing.T) {
	s, _ := obsServer(t, func(o *Options) { o.Obs.RateLimit = RateLimitConfig{Rate: 1, Per: time.Hour, Burst: 1, Key: "route"} })
	get(t, s, "x.test", "/ok")
	r := get(t, s, "x.test", "/ok")
	if r.Status != 429 {
		t.Fatalf("status %d", r.Status)
	}
	waitLatest(t, s, 2)
	rec := lastRecord(t, s)
	if !rec.RateLimited || rec.Status != 429 || rec.UpstreamAddr != "" {
		t.Errorf("rate limited %v status %d upstream %q", rec.RateLimited, rec.Status, rec.UpstreamAddr)
	}
}

func TestConnUnmatchedOmitsUpstream(t *testing.T) {
	s, _ := obsServer(t, nil)
	get(t, s, "x.test", "/nothing")
	rec := lastRecord(t, s)
	if rec.Status != 404 || rec.Route != "" || rec.UpstreamAddr != "" || rec.Match != nil || rec.UpstreamTLS != nil {
		t.Errorf("record %+v", rec)
	}
}

func TestConnTLSDetails(t *testing.T) {
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	gw := httpsGateway(tlsListener("a", "a.mactra.test", "a-cert"))
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": gw, rtKeyT + "a": m{"parentRefs": l{m{"name": "gw", "sectionName": "a"}}, "rules": l{rule("/", ref("a", 1))}}},
		"backends":  m{"t/a:80": be["a"]},
		"secrets":   m{"a-cert": p.files("a", "a.mactra.test")}})
	s := startServer(t, raw, nil)
	c := tlsClient(s.Addr(8443), p, "a.mactra.test")
	resp, err := c.Get("https://a.mactra.test/x?y=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rec := lastRecord(t, s)
	if rec.Protocol != "HTTP/2" || rec.TLSALPN != "h2" || rec.TLSSNI != "a.mactra.test" {
		t.Errorf("protocol %q alpn %q sni %q", rec.Protocol, rec.TLSALPN, rec.TLSSNI)
	}
	if rec.TLSVersion != "TLS 1.3" || rec.TLSCipher == "" || !strings.HasPrefix(rec.TLSCipher, "TLS_") {
		t.Errorf("tls %q cipher %q", rec.TLSVersion, rec.TLSCipher)
	}
	if rec.ListenerPort != portOf(s.Addr(8443)) || rec.Path != "/x" {
		t.Errorf("listener port %d path %q", rec.ListenerPort, rec.Path)
	}
	// HTTP/1.1 over TLS with a different SNI-less client.
	c1 := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.pool, ServerName: "a.mactra.test", NextProtos: []string{"http/1.1"}},
		DialContext: func(ctx_ context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx_, n, s.Addr(8443))
		}}}
	resp, err = c1.Get("https://a.mactra.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The record is pushed just after the response; wait for the second one (a flake found by -count=3).
	waitFor(t, "the second connection record", func() bool { return len(history(s)) > 1 })
	if rec := lastRecord(t, s); rec.Protocol != "HTTP/1.1" || rec.TLSALPN != "http/1.1" {
		t.Errorf("protocol %q alpn %q", rec.Protocol, rec.TLSALPN)
	}
}

func TestConnGRPC(t *testing.T) {
	be, _ := grpcBackends(t, "a")
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": grpcRoute("", grule([]any{gmethod("Exact", "pkg.Orders", "Get")}, gref("a", 1)))}, be, nil), nil)
	c := h2cClient(s.Addr(8080))
	r := grpcCall(t, c, "http", "svc.test", "/pkg.Orders/Get", []string{"ping", "pong"})
	if r.Status != "0" {
		t.Fatalf("reply %+v", r)
	}
	waitLatest(t, s, 1)
	rec := lastRecord(t, s)
	if rec.Protocol != "gRPC" || rec.HTTPVersion != "HTTP/2.0" {
		t.Errorf("protocol %q http %q", rec.Protocol, rec.HTTPVersion)
	}
	if rec.GRPCService != "pkg.Orders" || rec.GRPCMethod != "Get" || rec.GRPCStatus == nil || *rec.GRPCStatus != 0 {
		t.Errorf("grpc %q %q %v", rec.GRPCService, rec.GRPCMethod, rec.GRPCStatus)
	}
	if rec.UpstreamProto != "h2c" || rec.UpstreamAddr == "" || rec.UpstreamTLS == nil || *rec.UpstreamTLS {
		t.Errorf("upstream %q %q", rec.UpstreamProto, rec.UpstreamAddr)
	}
	if rec.RequestBytes != int64(len(grpcFrame("ping"))+len(grpcFrame("pong"))) || rec.ResponseBytes == 0 {
		t.Errorf("bytes in %d out %d", rec.RequestBytes, rec.ResponseBytes)
	}
	// A Trailers-Only failure reports its status too.
	r = grpcCall(t, c, "http", "svc.test", "/pkg.Nope/Missing", []string{"x"})
	if r.Status != "12" {
		t.Fatalf("unmatched reply %+v", r)
	}
	waitLatest(t, s, 2)
	rec = lastRecord(t, s)
	if rec.GRPCStatus == nil || *rec.GRPCStatus != 12 || rec.GRPCService != "pkg.Nope" || rec.Match != nil {
		t.Errorf("unmatched grpc record %+v status %v", rec, rec.GRPCStatus)
	}
}

func TestConnGRPCOpenStream(t *testing.T) {
	be, _ := grpcBackends(t, "a")
	s := startServer(t, grpcSnap(grpcGateway(), map[string]m{grpcKeyT + "g": grpcRoute("", grule(nil, gref("a", 1)))}, be, nil), nil)
	pr, pw := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := grpcRequest(h2cClient(s.Addr(8080)), "http", "x.test", "/pkg.S/Chat", pr)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		for {
			if _, err := readGRPCFrame(resp.Body); err != nil {
				return
			}
		}
	}()
	pw.Write(grpcFrame("hello"))
	waitFor(t, "open grpc stream with counters", func() bool {
		o := s.Connections(10, 0).Open
		return len(o) == 1 && o[0].BytesIn > 0 && o[0].BytesOut > 0
	})
	o := s.Connections(10, 0).Open[0]
	if o.Kind != "grpc" || o.Protocol != "gRPC" || o.Path != "/pkg.S/Chat" || o.Route != "GRPCRoute/t/g" || o.UpstreamAddr == "" || o.AgeMS < 0 || o.ClientIP != "127.0.0.1" {
		t.Errorf("open %+v", o)
	}
	pw.Close()
	<-done
	waitFor(t, "stream to close", func() bool { return len(s.Connections(10, 0).Open) == 0 })
	if rec := lastRecord(t, s); rec.GRPCStatus == nil || *rec.GRPCStatus != 0 {
		t.Errorf("final record %+v", rec)
	}
}

func TestConnWebSocketOpen(t *testing.T) {
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Cleanup(back.Close)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": strings.TrimPrefix(back.URL, "http://")}), nil)
	c, err := net.Dial("tcp", s.Addr(8080))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET /chat?k=v HTTP/1.1\r\nHost: x.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	br := bufio.NewReader(c)
	if line, _ := br.ReadString('\n'); !strings.Contains(line, "101") {
		t.Fatalf("status line %q", line)
	}
	for {
		if line, _ := br.ReadString('\n'); line == "\r\n" || line == "" {
			break
		}
	}
	io.WriteString(c, "ping\n")
	if line, _ := br.ReadString('\n'); line != "ping\n" {
		t.Fatalf("echo %q", line)
	}
	waitFor(t, "websocket in the open list", func() bool {
		o := s.Connections(10, 0).Open
		return len(o) == 1 && o[0].BytesIn >= 5 && o[0].BytesOut >= 5
	})
	o := s.Connections(10, 0).Open[0]
	if o.Kind != "websocket" || o.Protocol != "WebSocket" || o.Path != "/chat" || o.Backend != "t/a:80" || o.UpstreamAddr == "" {
		t.Errorf("open %+v", o)
	}
	c.Close()
	waitFor(t, "websocket record", func() bool { return len(s.Connections(10, 0).History) == 1 && len(s.Connections(10, 0).Open) == 0 })
	rec := lastRecord(t, s)
	if rec.Protocol != "WebSocket" || rec.Status != 101 || rec.RequestBytes < 5 || rec.ResponseBytes < 5 || rec.Path != "/chat" {
		t.Errorf("record %+v", rec)
	}
}

func TestConnPassthrough(t *testing.T) {
	p := newPKI(t)
	be := newTLSBackend(t, p, "a", "a.test")
	routes := map[string]m{tlsKeyT + "a": tlsRoute("", []string{"a.test"}, tref("a", 3))}
	var buf syncBuf
	s := startServer(t, tlsSnap(passGateway(), routes, map[string]string{"a": be.addr()}, nil), func(o *Options) { o.AccessLog = &buf })
	c, err := dialTLS(s.Addr(8443), p, "a.test")
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "ping\n")
	bufio.NewReader(c).ReadString('\n')
	waitFor(t, "passthrough in the open list", func() bool {
		o := s.Connections(10, 0).Open
		return len(o) == 1 && o[0].BytesIn > 0 && o[0].BytesOut > 0
	})
	o := s.Connections(10, 0).Open[0]
	if o.Kind != "passthrough" || o.Protocol != "TLS-passthrough" || o.SNI != "a.test" || o.UpstreamAddr != be.addr() || o.Route != "TLSRoute/t/a" || o.ListenerPort != portOf(s.Addr(8443)) {
		t.Errorf("open %+v", o)
	}
	c.Close()
	waitFor(t, "passthrough record", func() bool { return len(s.Connections(10, 0).History) == 1 })
	s.FlushAccessLog()
	rec := lastRecord(t, s)
	if rec.Protocol != "TLS-passthrough" || rec.TLSSNI != "a.test" || rec.UpstreamAddr != be.addr() || rec.ClientIP != "127.0.0.1" || rec.ClientPort == 0 ||
		rec.RequestBytes == 0 || rec.ResponseBytes == 0 || rec.Bytes != rec.RequestBytes+rec.ResponseBytes || rec.BackendWeight != 3 || rec.Millis <= 0 || rec.UpstreamConnectMS <= 0 {
		t.Errorf("record %+v", rec)
	}
	ls := logLines(t, &buf)
	if len(ls) != 1 || ls[0]["tls_sni"] != "a.test" || ls[0]["upstream_addr"] != be.addr() || ls[0]["client_ip"] != "127.0.0.1" || ls[0]["listener_port"] == nil {
		t.Errorf("log %v", ls)
	}
}

func TestConnPassthroughDialAttempts(t *testing.T) {
	p := newPKI(t)
	be := newTLSBackend(t, p, "a", "a.test")
	routes := map[string]m{tlsKeyT + "a": tlsRoute("", []string{"a.test"}, tref("a", 1))}
	s := startServer(t, mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": passGateway(), tlsKeyT + "a": routes[tlsKeyT+"a"]},
		"backends":  m{"t/a:443": m{"endpoints": l{deadAddr(t), be.addr()}}}}), nil)
	for i := 0; i < 2; i++ {
		askTLS(t, s.Addr(8443), p, "a.test")
	}
	waitFor(t, "two records", func() bool { return len(history(s)) == 2 })
	var retried bool
	for _, rec := range history(s) {
		if rec.Retries == 1 && len(rec.Attempts) == 2 && rec.Attempts[0].Error != "" && rec.UpstreamAddr == be.addr() {
			retried = true
		}
	}
	if !retried {
		t.Errorf("no record shows the failed dial: %+v %+v", history(s)[0], history(s)[1])
	}
}

func TestConnConcurrent(t *testing.T) {
	s, _ := obsServer(t, func(o *Options) { o.ConnHistory = 64; o.AccessLog = io.Discard })
	var wg sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				snap := s.PublicConnections(50, 0)
				for _, l := range snap.History {
					_ = l.Path
				}
				json.Marshal(snap)
			}
		}
	}()
	const workers, each = 16, 25
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &http.Client{Timeout: 5 * time.Second}
			for i := 0; i < each; i++ {
				resp, err := c.Post("http://"+s.Addr(8080)+"/ok", "text/plain", strings.NewReader("body"))
				if err != nil {
					t.Error(err)
					return
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	close(stop)
	waitLatest(t, s, workers*each)
	snap := s.Connections(1000, 0)
	if snap.Latest != workers*each || len(snap.History) != 64 {
		t.Errorf("latest %d history %d", snap.Latest, len(snap.History))
	}
	seen := map[int64]bool{}
	for _, l := range snap.History {
		if seen[l.ID] || l.UpstreamStatus != 200 || l.RequestBytes != 4 {
			t.Fatalf("bad or duplicate record %+v", l)
		}
		seen[l.ID] = true
	}
}

func TestPublicConnectionsHideHeaders(t *testing.T) {
	s, _ := obsServer(t, nil)
	req(t, client(s.Addr(8080), nil), "http", "GET", "x.test", "/ok", "", "User-Agent", "secret-agent", "X-Forwarded-For", "1.2.3.4")
	if rec := lastRecord(t, s); rec.UserAgent == "" || rec.XFF == "" {
		t.Fatal("admin records should keep header values like the access log")
	}
	b, _ := json.Marshal(s.PublicConnections(10, 0))
	if strings.Contains(string(b), "secret-agent") || strings.Contains(string(b), "1.2.3.4") || strings.Contains(string(b), "x_forwarded_for") {
		t.Errorf("dashboard document leaks header values: %s", b)
	}
}

func TestTruncUTF8(t *testing.T) {
	s := strings.Repeat("é", 150) // 300 bytes
	got := truncUTF8(s, 199)
	if len(got) != 198 || !strings.HasSuffix(got, "é") {
		t.Errorf("len %d", len(got))
	}
	if truncUTF8("short", 200) != "short" {
		t.Error("short string changed")
	}
}
