package gateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// DefaultConnHistory is the number of recent request records kept for the
// /connections endpoint and the dashboard.
const DefaultConnHistory = 500

const (
	maxHeaderLog = 200 // user agent and X-Forwarded-For are cut to this many bytes
	// Protocol labels used in logs and the dashboard.
	protoHTTP1 = "HTTP/1.1"
	protoHTTP2 = "HTTP/2"
	protoH2C   = "h2c"
	protoWS    = "WebSocket"
	protoGRPC  = "gRPC"
	protoTLSPT = "TLS-passthrough"
)

var (
	vTrue  = true
	vFalse = false
)

func boolp(b bool) *bool {
	if b {
		return &vTrue
	}
	return &vFalse
}

// attemptRec is one upstream attempt, listed when a request was retried.
type attemptRec struct {
	Addr      string  `json:"addr"`
	Status    int     `json:"status,omitempty"`
	Error     string  `json:"error,omitempty"`
	ConnectMS float64 `json:"connect_ms,omitempty"`
	TTFBMS    float64 `json:"ttfb_ms,omitempty"`
	Health    string  `json:"health,omitempty"`
}

// attemptTrace gathers httptrace timings for one upstream attempt. Callbacks
// run on transport goroutines, hence the mutex.
type attemptTrace struct {
	mu                  sync.Mutex
	t0, gotConn         time.Time
	connect, ttfb       time.Duration
	reused, got, gotRsp bool
	remote              string
}

func (a *attemptTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(string) { a.mu.Lock(); a.t0 = time.Now(); a.mu.Unlock() },
		GotConn: func(i httptrace.GotConnInfo) {
			now := time.Now()
			a.mu.Lock()
			a.got, a.reused, a.gotConn = true, i.Reused, now
			if !i.Reused {
				a.connect = now.Sub(a.t0)
			}
			if i.Conn != nil {
				a.remote = i.Conn.RemoteAddr().String()
			}
			a.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			now := time.Now()
			a.mu.Lock()
			if !a.gotRsp && a.got {
				a.gotRsp, a.ttfb = true, now.Sub(a.gotConn)
			}
			a.mu.Unlock()
		},
	}
}

// upInfo is what the proxy learned about the upstream side of one request.
type upInfo struct {
	have      bool
	addr      string
	proto     string
	health    string
	tls       bool
	reused    bool
	connectMS float64
	ttfbMS    float64
	status    int
	n         int // attempts made
	first     attemptRec
	more      []attemptRec
}

// begin returns a context that reports upstream timings to the returned
// trace.
func (u *upInfo) begin(ctx context.Context) (context.Context, *attemptTrace) {
	a := &attemptTrace{}
	return httptrace.WithClientTrace(ctx, a.clientTrace()), a
}

// end records the outcome of an attempt made against ep.
func (u *upInfo) end(a *attemptTrace, ep *Endpoint, health string, resp *http.Response, err error) {
	a.mu.Lock()
	rec := attemptRec{Addr: a.remote, Health: health}
	rec.ConnectMS, rec.TTFBMS = ms(a.connect), ms(a.ttfb)
	reused := a.reused
	a.mu.Unlock()
	if rec.Addr == "" {
		rec.Addr = ep.URL.Host
	}
	if err != nil {
		rec.Error = err.Error()
	} else {
		rec.Status = resp.StatusCode
	}
	u.have, u.addr, u.health, u.reused = true, rec.Addr, health, reused
	u.tls = ep.URL.Scheme == "https"
	u.connectMS, u.ttfbMS, u.status = rec.ConnectMS, rec.TTFBMS, rec.Status
	u.proto = ""
	if err == nil {
		switch {
		case resp.ProtoMajor == 2 && u.tls:
			u.proto = "h2"
		case resp.ProtoMajor == 2:
			u.proto = "h2c"
		default:
			u.proto = "http/1.1"
		}
	}
	if u.n == 0 {
		u.first = rec
	} else {
		u.more = append(u.more, rec)
	}
	u.n++
}

// attempts lists every attempt, or nil when the request was not retried.
func (u *upInfo) attempts() []attemptRec {
	if u.n < 2 {
		return nil
	}
	return append([]attemptRec{u.first}, u.more...)
}

// state names the health of one endpoint: healthy, ejected or unhealthy.
func (b *Backend) state(ep *Endpoint, now time.Time) string {
	b.hmu.Lock()
	defer b.hmu.Unlock()
	switch {
	case now.Before(ep.st.until):
		return "ejected"
	case !ep.healthy.Load():
		return "unhealthy"
	}
	return "healthy"
}

// countReader counts the bytes a request body delivers.
type countReader struct {
	rc interface {
		Read([]byte) (int, error)
		Close() error
	}
	n atomic.Int64
	// mirror is an optional second counter (open connection table).
	mirror *atomic.Int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.n.Add(int64(n))
		if c.mirror != nil {
			c.mirror.Add(int64(n))
		}
	}
	return n, err
}

func (c *countReader) Close() error { return c.rc.Close() }

// countConn counts bytes moved over a hijacked (upgraded) connection.
type countConn struct {
	net.Conn
	in, out *atomic.Int64
}

func (c *countConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.in.Add(int64(n))
	}
	return n, err
}

func (c *countConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.out.Add(int64(n))
	}
	return n, err
}

// Hijack lets WebSocket upgrades through while counting their bytes.
func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := http.NewResponseController(r.ResponseWriter).Hijack()
	if err == nil && r.status == 0 {
		r.status = http.StatusSwitchingProtocols // the handler writes the 101 itself
	}
	if err == nil && r.open != nil {
		c = &countConn{Conn: c, in: &r.open.in, out: &r.open.out}
	}
	return c, brw, err
}

// ---------------------------------------------------------------- records

func truncUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for i := 0; i < utf8.UTFMax && len(s) > 0; i++ { // drop a rune cut in half
		if r, size := utf8.DecodeLastRuneInString(s); r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

func protocolOf(r *http.Request) string {
	switch {
	case isGRPC(r):
		return protoGRPC
	case strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
		return protoWS
	case r.ProtoMajor == 2 && r.TLS == nil:
		return protoH2C
	case r.ProtoMajor == 2:
		return protoHTTP2
	}
	return r.Proto
}

func localPort(r *http.Request) int {
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

func splitRemote(remote string) (ip string, port int) {
	h, p, err := net.SplitHostPort(remote)
	if err != nil {
		return remote, 0
	}
	n, _ := strconv.Atoi(p)
	return h, n
}

func (s *Server) logPath(r *http.Request) string {
	p := r.URL.RequestURI()
	if i := strings.IndexByte(p, '?'); i >= 0 {
		if !s.opts.Obs.LogQuery {
			return p[:i]
		}
		var extra []string
		if q := s.authQ.Load(); q != nil {
			extra = *q
		}
		return p[:i+1] + redactQuery(p[i+1:], extra...)
	}
	return p
}

// buildLine turns a finished request into its log and history record.
func (s *Server) buildLine(rec *recorder, r *http.Request, st *reqState, start, end time.Time, status int) *logLine {
	l := &logLine{Time: start.UTC().Format(time.RFC3339Nano), Listener: st.listener, ListenerPort: localPort(r), Host: r.Host, Method: r.Method,
		Path: s.logPath(r), Status: status, Bytes: rec.bytesOut(), Millis: ms(end.Sub(start)), Route: st.route, Rule: st.rule,
		Backend: st.backend, BackendWeight: st.weight, Remote: r.RemoteAddr, RequestID: st.reqID, TraceID: st.trace.TraceID,
		SpanID: st.trace.SpanID, Error: st.errMsg, Protocol: protocolOf(r), HTTPVersion: r.Proto, RateLimited: st.rateLimited,
		AuthProtected: st.authed, Contract: st.contract, ContractMode: st.contractMode}
	l.ClientIP, l.ClientPort = splitRemote(r.RemoteAddr)
	if c := s.trusted.clientIP(r); len(s.trusted) > 0 && c != l.ClientIP {
		l.ClientIP, l.ClientPort = c, 0 // the real client behind a trusted proxy: its port is unknown
	}
	if st.matched {
		m := st.match
		l.Match = &m
	}
	if t := r.TLS; t != nil {
		l.TLSVersion, l.TLSCipher, l.TLSSNI, l.TLSALPN = tls.VersionName(t.Version), tls.CipherSuiteName(t.CipherSuite), t.ServerName, t.NegotiatedProtocol
		if len(t.PeerCertificates) > 0 {
			l.TLSClientCert = t.PeerCertificates[0].Subject.String()
		}
	}
	l.UserAgent = truncUTF8(r.Header.Get("User-Agent"), maxHeaderLog)
	l.XFF = truncUTF8(strings.Join(r.Header.Values("X-Forwarded-For"), ", "), maxHeaderLog)
	if st.in != nil {
		l.RequestBytes = st.in.n.Load()
	}
	if rec.open != nil && l.Protocol == protoWS { // upgraded streams bypass the recorder
		l.Bytes, l.RequestBytes = rec.open.out.Load(), rec.open.in.Load()
	}
	l.ResponseBytes = l.Bytes
	if st.grpcSvc != "" || st.grpcMethod != "" {
		l.GRPCService, l.GRPCMethod = st.grpcSvc, st.grpcMethod
	}
	if l.Protocol == protoGRPC {
		h := rec.Header()
		g := h.Get("Grpc-Status")
		if v := h.Get(http.TrailerPrefix + "Grpc-Status"); v != "" {
			g = v
		}
		if n, err := strconv.Atoi(g); err == nil {
			l.GRPCStatus = &n
		}
	}
	u := &st.up
	if u.have {
		l.UpstreamAddr, l.UpstreamProto, l.UpstreamTLS, l.UpstreamReused = u.addr, u.proto, boolp(u.tls), boolp(u.reused)
		l.UpstreamConnectMS, l.UpstreamTTFBMS, l.UpstreamStatus, l.UpstreamHealth = u.connectMS, u.ttfbMS, u.status, u.health
		l.Retries = u.n - 1
		l.Attempts = u.attempts()
	}
	return l
}

// ---------------------------------------------------------------- tables

// openConn is a connection or stream that is still running.
type openConn struct {
	id    int64
	start time.Time
	in    atomic.Int64 // bytes from the client
	out   atomic.Int64 // bytes to the client

	mu sync.Mutex
	v  OpenView
}

// OpenView is the JSON form of a currently open connection.
type OpenView struct {
	ID           int64   `json:"id"`
	Since        string  `json:"since"`
	AgeMS        float64 `json:"age_ms"`
	Kind         string  `json:"kind"` // passthrough, websocket or grpc
	ClientIP     string  `json:"client_ip,omitempty"`
	ClientPort   int     `json:"client_port,omitempty"`
	Listener     string  `json:"listener,omitempty"`
	ListenerPort int     `json:"listener_port,omitempty"`
	Protocol     string  `json:"protocol"`
	SNI          string  `json:"tls_sni,omitempty"`
	Host         string  `json:"host,omitempty"`
	Path         string  `json:"path,omitempty"`
	Route        string  `json:"route,omitempty"`
	Backend      string  `json:"backend,omitempty"`
	UpstreamAddr string  `json:"upstream_addr,omitempty"`
	BytesIn      int64   `json:"bytes_in"`
	BytesOut     int64   `json:"bytes_out"`
}

func (o *openConn) set(f func(v *OpenView)) {
	if o == nil {
		return
	}
	o.mu.Lock()
	f(&o.v)
	o.mu.Unlock()
}

// connTable is the bounded history ring plus the open-connection list.
type connTable struct {
	cap  int
	mu   sync.Mutex
	ring []*logLine
	seq  int64
	open map[int64]*openConn
	oseq int64
}

func newConnTable(capacity int) *connTable {
	if capacity <= 0 {
		return nil
	}
	return &connTable{cap: capacity, ring: make([]*logLine, capacity), open: map[int64]*openConn{}}
}

// push stores a finished record and assigns its sequence id.
func (c *connTable) push(l *logLine) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.seq++
	l.ID = c.seq
	c.ring[int(c.seq%int64(c.cap))] = l
	c.mu.Unlock()
}

// register adds an open connection; the returned func removes it.
func (c *connTable) register(v OpenView) (*openConn, func()) {
	if c == nil {
		return nil, func() {}
	}
	o := &openConn{start: time.Now(), v: v}
	c.mu.Lock()
	c.oseq++
	o.id = c.oseq
	c.open[o.id] = o
	c.mu.Unlock()
	return o, func() { c.mu.Lock(); delete(c.open, o.id); c.mu.Unlock() }
}

// ConnSnapshot is the /connections document.
type ConnSnapshot struct {
	Enabled  bool        `json:"enabled"`
	Capacity int         `json:"capacity"`
	Latest   int64       `json:"latest"` // id of the newest record, pass as since to poll
	History  []*logLine  `json:"history"`
	Open     []*OpenView `json:"open"`
}

// snapshot returns up to limit records with id > since, newest first.
func (c *connTable) snapshot(limit int, since int64) *ConnSnapshot {
	out := &ConnSnapshot{History: []*logLine{}, Open: []*OpenView{}}
	if c == nil {
		return out
	}
	out.Enabled, out.Capacity = true, c.cap
	c.mu.Lock()
	out.Latest = c.seq
	lo := c.seq - int64(c.cap) + 1
	if lo < 1 {
		lo = 1
	}
	if since+1 > lo {
		lo = since + 1
	}
	for id := c.seq; id >= lo && len(out.History) < limit; id-- {
		if l := c.ring[int(id%int64(c.cap))]; l != nil && l.ID == id {
			out.History = append(out.History, l)
		}
	}
	opens := make([]*openConn, 0, len(c.open))
	for _, o := range c.open {
		opens = append(opens, o)
	}
	c.mu.Unlock()
	now := time.Now()
	for _, o := range opens {
		o.mu.Lock()
		v := o.v
		o.mu.Unlock()
		v.ID, v.Since, v.AgeMS = o.id, o.start.UTC().Format(time.RFC3339Nano), ms(now.Sub(o.start))
		v.BytesIn, v.BytesOut = o.in.Load(), o.out.Load()
		out.Open = append(out.Open, &v)
	}
	sortOpen(out.Open)
	return out
}

func sortOpen(o []*OpenView) {
	for i := 1; i < len(o); i++ { // insertion sort: lists are short, oldest first
		for j := i; j > 0 && o[j].ID < o[j-1].ID; j-- {
			o[j], o[j-1] = o[j-1], o[j]
		}
	}
}

// Connections returns the recent records and open connections.
func (s *Server) Connections(limit int, since int64) *ConnSnapshot {
	if limit <= 0 {
		limit = 100
	}
	return s.conns.snapshot(limit, since)
}

// Public returns a copy without header values (user agent, X-Forwarded-For),
// which the dashboard never shows.
func (l *logLine) public() *logLine {
	c := *l
	c.UserAgent, c.XFF = "", ""
	return &c
}

// PublicConnections is Connections for the dashboard: header values removed.
func (s *Server) PublicConnections(limit int, since int64) *ConnSnapshot {
	snap := s.Connections(limit, since)
	for i, l := range snap.History {
		snap.History[i] = l.public()
	}
	return snap
}

// connectionsHandler serves /connections?limit=&since= read-only.
func (s *Server) connectionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		plain(w, http.StatusMethodNotAllowed, "read-only endpoint")
		return
	}
	limit, since := 100, int64(0)
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			plain(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			plain(w, http.StatusBadRequest, "since must be a record id (a non-negative integer)")
			return
		}
		since = n
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(s.Connections(limit, since))
}
