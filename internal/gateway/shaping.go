package gateway

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Traffic shaping and protocol limits: connection limits, TCP keepalive,
// HTTP/2 settings, bandwidth limits and the X-Request-Id policy. Every
// setting is off (or Go's own default) unless a flag or a block asks for it.

// Rule extension keys of this file and compress.go and grpcweb.go.
const (
	BandwidthKey = "setura.zyvor.dev/bandwidth"
	GRPCWebKey   = "setura.zyvor.dev/grpc-web"
)

// ShapingKeys are the annotation keys of the traffic shaping rule extensions.
var ShapingKeys = []string{CompressKey, GRPCWebKey, BandwidthKey}

// Request id modes (--request-id).
const (
	RequestIDPreserve = "preserve"       // keep a valid client id, generate one otherwise (default)
	RequestIDGenerate = "generate"       // always generate; the client's id is forwarded as X-Client-Request-Id
	RequestIDUpstream = "trust-upstream" // like preserve, but a valid id the backend returns wins on the response
)

// KeepAliveOptions are the TCP keepalive settings of accepted connections
// (zero keeps Go's default of 15s idle and interval).
type KeepAliveOptions struct {
	Disable  bool
	Idle     time.Duration
	Interval time.Duration
	Count    int
}

func (k KeepAliveOptions) active() bool {
	return k.Disable || k.Idle != 0 || k.Interval != 0 || k.Count != 0
}

// H2Options are the HTTP/2 server settings (zero keeps Go's default).
type H2Options struct {
	MaxStreams    int // SETTINGS_MAX_CONCURRENT_STREAMS
	InitialWindow int // per stream flow control window (SETTINGS_INITIAL_WINDOW_SIZE)
	MaxFrameSize  int // SETTINGS_MAX_FRAME_SIZE the server accepts
	MaxConnWindow int // flow control window of the whole connection
}

func (h H2Options) active() bool {
	return h.MaxStreams != 0 || h.InitialWindow != 0 || h.MaxFrameSize != 0 || h.MaxConnWindow != 0
}

func (h H2Options) config() *http.HTTP2Config {
	return &http.HTTP2Config{MaxConcurrentStreams: h.MaxStreams, MaxReceiveBufferPerStream: h.InitialWindow,
		MaxReadFrameSize: h.MaxFrameSize, MaxReceiveBufferPerConnection: h.MaxConnWindow}
}

// ShapeOptions groups the gateway wide traffic shaping settings.
type ShapeOptions struct {
	MaxConns      int // per listener port (a listener's limits block overrides it); 0 = unlimited
	MaxConnsPerIP int
	KeepAlive     KeepAliveOptions
	H2            H2Options
	Compress      CompressOptions
	BandwidthIn   int64 // bytes per second per request body, 0 = unlimited
	BandwidthOut  int64 // bytes per second per response body
	RequestID     string
	// Now and Sleep replace the clock and the wait of bandwidth limits (tests).
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// ---- connection limits ----

// connLimiter bounds the accepted connections of one listener port, in total
// and per peer IP. The limits can change on a reload.
type connLimiter struct {
	port   int
	max    atomic.Int64
	perIP  atomic.Int64
	mu     sync.Mutex
	n      int
	byIP   map[string]int
	rejTot atomic.Int64
	rejIP  atomic.Int64
}

func newConnLimiter(port, max, perIP int) *connLimiter {
	c := &connLimiter{port: port, byIP: map[string]int{}}
	c.set(max, perIP)
	return c
}

func (c *connLimiter) set(max, perIP int) {
	c.max.Store(int64(max))
	c.perIP.Store(int64(perIP))
}

func (c *connLimiter) acquire(ip string) (release func(), reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if m := c.max.Load(); m > 0 && int64(c.n) >= m {
		c.rejTot.Add(1)
		return nil, "total"
	}
	if m := c.perIP.Load(); m > 0 && int64(c.byIP[ip]) >= m {
		c.rejIP.Add(1)
		return nil, "per_ip"
	}
	c.n++
	c.byIP[ip]++
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.n--
			if c.byIP[ip]--; c.byIP[ip] <= 0 {
				delete(c.byIP, ip)
			}
			c.mu.Unlock()
		})
	}, ""
}

func (c *connLimiter) active() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// limitListener refuses connections over the limits by closing them at once.
// (There is no way to say why on a TLS or raw TCP connection; the refusal is
// counted in setura_gateway_conn_limit_rejected_total.)
type limitListener struct {
	net.Listener
	cl *connLimiter
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, _, serr := net.SplitHostPort(c.RemoteAddr().String())
		if serr != nil {
			ip = c.RemoteAddr().String()
		}
		release, reason := l.cl.acquire(ip)
		if reason != "" {
			c.Close()
			continue
		}
		return &limitConn{Conn: c, release: release}, nil
	}
}

type limitConn struct {
	net.Conn
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

// NetConn lets callers that need the TCP connection (a RST on abort) see through the wrapper.
func (c *limitConn) NetConn() net.Conn { return c.Conn }

// CloseWrite and CloseRead keep half-close working for the raw TCP proxies.
func (c *limitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("not a half-closable connection")
}

func (c *limitConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return errors.New("not a half-closable connection")
}

// listen binds addr with the keepalive settings and the connection limiter.
func (s *Server) listenTCP(addr string, spec int) (net.Listener, *connLimiter, error) {
	lc := net.ListenConfig{}
	if k := s.opts.Shape.KeepAlive; k.active() {
		lc.KeepAliveConfig = net.KeepAliveConfig{Enable: !k.Disable, Idle: k.Idle, Interval: k.Interval, Count: k.Count}
		if k.Disable {
			lc.KeepAlive = -1
		}
	}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	cl := newConnLimiter(spec, s.opts.Shape.MaxConns, s.opts.Shape.MaxConnsPerIP)
	return &limitListener{Listener: ln, cl: cl}, cl, nil
}

// applyConnLimits sets the limits of every bound port: the gateway default,
// lowered by the listeners that declare their own (the lowest wins on a
// shared port).
func (s *Server) applyConnLimits(t *Table) {
	for p, bp := range s.ports {
		if bp.cl == nil {
			continue
		}
		max, perIP := s.opts.Shape.MaxConns, s.opts.Shape.MaxConnsPerIP
		if pg := t.Ports[p]; pg != nil {
			lowest := func(cur, v int) int {
				if v > 0 && (cur == 0 || v < cur) {
					return v
				}
				return cur
			}
			var lm, lp int
			for _, l := range pg.Listeners {
				lm, lp = lowest(lm, l.MaxConns), lowest(lp, l.MaxConnsPerIP)
			}
			if lm > 0 {
				max = lm
			}
			if lp > 0 {
				perIP = lp
			}
		}
		bp.cl.set(max, perIP)
	}
}

// ---- bandwidth ----

// BandwidthConfig is the setura.zyvor.dev/bandwidth block of a rule: a token
// bucket per request on the request body and per response on the response
// body, rates in bytes per second ("1MB/s", "256k", 0 or "unlimited" lifts
// the gateway default).
type BandwidthConfig struct {
	Request  flexString `json:"request,omitempty"`
	Response flexString `json:"response,omitempty"`
	Burst    flexString `json:"burst,omitempty"` // bucket size in bytes (default: 50ms of the rate, at least 1KB)
}

type bwSpec struct {
	in, out *int64
	burst   int64
}

// ParseRateBytes reads a rate such as 1MB/s, 256k/s or 4096 (bytes per second).
func ParseRateBytes(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if strings.EqualFold(v, "unlimited") {
		return 0, nil
	}
	v = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(v), "/sec"), "/s")
	n, err := ParseSize(v)
	if err != nil {
		return 0, fmt.Errorf("rate %q: want bytes per second such as 1MB/s, 256k or unlimited", v)
	}
	return n, nil
}

func (b *BandwidthConfig) compile() (*bwSpec, error) {
	sp := &bwSpec{}
	for _, f := range []struct {
		name string
		v    flexString
		dst  **int64
	}{{"request", b.Request, &sp.in}, {"response", b.Response, &sp.out}} {
		if f.v == "" {
			continue
		}
		n, err := ParseRateBytes(string(f.v))
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", BandwidthKey, f.name, err)
		}
		*f.dst = &n
	}
	if b.Burst != "" {
		n, err := parseBodyLimit(string(b.Burst))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("%s: burst %q: want a size of at least 1 byte", BandwidthKey, b.Burst)
		}
		sp.burst = n
	}
	if sp.in == nil && sp.out == nil {
		return nil, fmt.Errorf("%s: give a request and/or a response rate", BandwidthKey)
	}
	return sp, nil
}

// ParseBandwidthBlock decodes and validates a bandwidth block.
func ParseBandwidthBlock(raw []byte) (*BandwidthConfig, error) {
	var b BandwidthConfig
	if err := strictDecode(BandwidthKey, raw, &b); err != nil {
		return nil, err
	}
	if _, err := b.compile(); err != nil {
		return nil, err
	}
	return &b, nil
}

// bwLimiter is a token bucket in bytes. take reserves n bytes and waits until
// the reservation is covered, so a write of any size is paced.
type bwLimiter struct {
	rate, burst float64
	mu          sync.Mutex
	tokens      float64
	last        time.Time
	now         func() time.Time
	sleep       func(ctx context.Context, d time.Duration) error
	waits       int64
	waited      time.Duration
}

func (s *Server) newBW(rate, burst int64) *bwLimiter {
	if rate <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = rate / 20
		if burst < 1024 {
			burst = 1024
		}
	}
	now, sleep := s.opts.Shape.Now, s.opts.Shape.Sleep
	if now == nil {
		now = time.Now
	}
	if sleep == nil {
		sleep = bwSleep
	}
	return &bwLimiter{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: now(), now: now, sleep: sleep}
}

func bwSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (b *bwLimiter) take(ctx context.Context, n int) error {
	b.mu.Lock()
	now := b.now()
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens += el * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.last = now
	}
	b.tokens -= float64(n)
	var wait time.Duration
	if b.tokens < 0 {
		wait = time.Duration(math.Round(-b.tokens / b.rate * float64(time.Second)))
		b.waits++
		b.waited += wait
	}
	b.mu.Unlock()
	if wait > 0 {
		return b.sleep(ctx, wait)
	}
	return nil
}

func (b *bwLimiter) delayed() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.waited
}

// chunk is the largest piece written or read at once.
func (b *bwLimiter) chunk() int { return int(b.burst) }

// bwReader paces reads of a request body.
type bwReader struct {
	rc  io.ReadCloser
	b   *bwLimiter
	ctx context.Context
}

func (r *bwReader) Read(p []byte) (int, error) {
	if c := r.b.chunk(); len(p) > c {
		p = p[:c]
	}
	n, err := r.rc.Read(p)
	if n > 0 {
		if werr := r.b.take(r.ctx, n); werr != nil && err == nil {
			err = werr
		}
	}
	return n, err
}

func (r *bwReader) Close() error { return r.rc.Close() }

// bwWriter paces writes of a response body.
type bwWriter struct {
	http.ResponseWriter
	b   *bwLimiter
	ctx context.Context
}

func (w *bwWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *bwWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *bwWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if c := w.b.chunk(); n > c {
			n = c
		}
		if err := w.b.take(w.ctx, n); err != nil {
			return total, err
		}
		m, err := w.ResponseWriter.Write(p[:n])
		total += m
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

// bandwidthFor resolves the byte rates of a rule: its block over the gateway flags.
func (s *Server) bandwidthFor(rule *CRule) (in, out, burst int64) {
	return ExplainServer{Shape: s.opts.Shape}.bandwidthFor(rule)
}

// installShaping puts bandwidth pacing and compression on the response and
// bandwidth pacing on the request body of an HTTP rule. The returned func
// ends the compressed stream and must run before the handler returns.
func (s *Server) installShaping(rec *recorder, r *http.Request, l *RTListener, rule *CRule) (*http.Request, func()) {
	in, out, burst := s.bandwidthFor(rule)
	route := esc(rule.RouteKey)
	var inBW, outBW *bwLimiter
	if inBW = s.newBW(in, burst); inBW != nil && r.Body != nil && r.Body != http.NoBody {
		r.Body = &bwReader{rc: r.Body, b: inBW, ctx: r.Context()}
		s.shape.add("bandwidth_limited", fmt.Sprintf(`route="%s",direction="request"`, route), 1)
	} else {
		inBW = nil
	}
	if outBW = s.newBW(out, burst); outBW != nil {
		rec.ResponseWriter = &bwWriter{ResponseWriter: rec.ResponseWriter, b: outBW, ctx: r.Context()}
		s.shape.add("bandwidth_limited", fmt.Sprintf(`route="%s",direction="response"`, route), 1)
	}
	var cw *compressWriter
	if pol := s.compressFor(l, rule); pol.enabled {
		if cw = newCompressWriter(rec.ResponseWriter, r, pol, rule.RouteKey, &s.shape); cw != nil {
			rec.ResponseWriter = cw
		}
	}
	return r, func() {
		if cw != nil {
			cw.Close()
		}
		for dir, bw := range map[string]*bwLimiter{"request": inBW, "response": outBW} {
			if bw == nil {
				continue
			}
			if d := bw.delayed(); d > 0 {
				s.shape.add("bandwidth_delay_ms", fmt.Sprintf(`route="%s",direction="%s"`, route, dir), (d + 500*time.Microsecond).Milliseconds())
			}
		}
	}
}

// compressFor resolves the compression policy of a request.
func (s *Server) compressFor(l *RTListener, rule *CRule) compressPolicy {
	return ExplainServer{Shape: s.opts.Shape}.compressFor(l, rule)
}

// ---- request id ----

// requestID picks the id of a request under the --request-id mode.
func (s *Server) requestID(h http.Header) (id, client string) {
	in := h.Get(RequestIDHeader)
	if s.opts.Shape.RequestID == RequestIDGenerate {
		if validRequestID(in) {
			client = in
		}
		return randHex(16), client
	}
	if validRequestID(in) {
		return in, ""
	}
	return randHex(16), ""
}

// responseRequestID applies trust-upstream: a valid id the backend sent
// replaces the gateway's on the response and in the log.
func (s *Server) responseRequestID(resp http.Header, st *reqState) {
	if s.opts.Shape.RequestID == RequestIDUpstream {
		if up := resp.Get(RequestIDHeader); validRequestID(up) {
			st.reqID = up
		}
	}
	resp.Set(RequestIDHeader, st.reqID)
}

// ---- flags ----

type shapeFlags struct {
	maxConns, maxPerIP              int
	kaIdle, kaInterval              time.Duration
	kaCount                         int
	kaOff                           bool
	h2Streams                       int
	h2Window, h2Frame, h2ConnWindow string
	bwIn, bwOut                     string
	reqID                           string
	compress                        bool
	compressTypes, compressEnc      string
	compressMin                     string
	compressLevel                   int
	redis                           stringList
	redisPassFile                   string
	redisTLS                        bool
	redisCA                         string
	redisTimeout, redisDial         time.Duration
	redisPool                       int
}

func addShapeFlags(fs *flag.FlagSet, f *shapeFlags) {
	fs.IntVar(&f.maxConns, "max-connections", 0, "most simultaneous client connections per listener port, extra ones are closed (default no limit; a listener limits block overrides it)")
	fs.IntVar(&f.maxPerIP, "max-connections-per-ip", 0, "most simultaneous connections per client IP per listener port (default no limit)")
	fs.DurationVar(&f.kaIdle, "tcp-keepalive-idle", 0, "idle time before the first TCP keepalive probe on client connections (default 15s)")
	fs.DurationVar(&f.kaInterval, "tcp-keepalive-interval", 0, "time between TCP keepalive probes (default 15s)")
	fs.IntVar(&f.kaCount, "tcp-keepalive-count", 0, "unanswered keepalive probes before a connection is dropped (default: the OS setting)")
	fs.BoolVar(&f.kaOff, "tcp-keepalive-off", false, "disable TCP keepalive on client connections")
	fs.IntVar(&f.h2Streams, "h2-max-streams", 0, "HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS per client connection (default Go's, 250)")
	fs.StringVar(&f.h2Window, "h2-initial-window", "", "HTTP/2 flow control window per stream (64k, 1MB; default Go's)")
	fs.StringVar(&f.h2Frame, "h2-max-frame-size", "", "largest HTTP/2 frame accepted, 16k to 16MB minus 1 (default 16k)")
	fs.StringVar(&f.h2ConnWindow, "h2-max-conn-window", "", "HTTP/2 flow control window of a whole connection (default Go's)")
	fs.StringVar(&f.bwIn, "bandwidth-request", "", "limit each request body to RATE bytes per second (1MB/s, 256k; default no limit; a rule's bandwidth block overrides it)")
	fs.StringVar(&f.bwOut, "bandwidth-response", "", "limit each response body to RATE bytes per second (default no limit)")
	fs.StringVar(&f.reqID, "request-id", RequestIDPreserve, "X-Request-Id policy: preserve (keep a valid client id), generate (always a new one) or trust-upstream (a valid backend id wins on the response)")
	fs.BoolVar(&f.compress, "compress", false, "compress responses with gzip or deflate on every route (default off; a rule or listener compress block overrides it)")
	fs.StringVar(&f.compressTypes, "compress-types", "", "content types to compress, comma separated (text/*, application/json, */*+json; default text, JSON, XML, JavaScript, SVG)")
	fs.StringVar(&f.compressEnc, "compress-encodings", "", "encodings offered, in order of preference: gzip,deflate (default both)")
	fs.StringVar(&f.compressMin, "compress-min-size", "", "smallest response worth compressing (default 1KB)")
	fs.IntVar(&f.compressLevel, "compress-level", 0, "compression level 1 (fast) to 9 (small) (default 6)")
	fs.Var(&f.redis, "redis", "Redis server for shared rate limits, [NAME=]HOST:PORT or redis[s]://[user:password@]HOST:PORT[/DB]; repeatable (NAME is what a block's shared.redis says, default \"default\")")
	fs.StringVar(&f.redisPassFile, "redis-password-file", "", "file holding the Redis password (or SETURA_REDIS_PASSWORD); used for servers whose address has none")
	fs.BoolVar(&f.redisTLS, "redis-tls", false, "connect to every --redis server over TLS")
	fs.StringVar(&f.redisCA, "redis-ca", "", "CA bundle that signed the Redis server certificates (default: system roots)")
	fs.DurationVar(&f.redisTimeout, "redis-timeout", 0, "deadline of one Redis round trip (default 250ms)")
	fs.DurationVar(&f.redisDial, "redis-dial-timeout", 0, "deadline to connect to Redis (default 1s)")
	fs.IntVar(&f.redisPool, "redis-pool", 0, "most open connections per Redis server (default 16)")
}

func (f *shapeFlags) apply(o *Options) error {
	neg := func(name string, v int) error {
		if v < 0 {
			return fmt.Errorf("%s %d: must not be negative", name, v)
		}
		return nil
	}
	for name, v := range map[string]int{"--max-connections": f.maxConns, "--max-connections-per-ip": f.maxPerIP, "--tcp-keepalive-count": f.kaCount,
		"--h2-max-streams": f.h2Streams, "--redis-pool": f.redisPool, "--compress-level": f.compressLevel} {
		if err := neg(name, v); err != nil {
			return err
		}
	}
	for name, d := range map[string]time.Duration{"--tcp-keepalive-idle": f.kaIdle, "--tcp-keepalive-interval": f.kaInterval, "--redis-timeout": f.redisTimeout, "--redis-dial-timeout": f.redisDial} {
		if d < 0 {
			return fmt.Errorf("%s %s: must not be negative", name, d)
		}
	}
	sh := &o.Shape
	sh.MaxConns, sh.MaxConnsPerIP = f.maxConns, f.maxPerIP
	sh.KeepAlive = KeepAliveOptions{Disable: f.kaOff, Idle: f.kaIdle, Interval: f.kaInterval, Count: f.kaCount}
	if f.kaOff && (f.kaIdle != 0 || f.kaInterval != 0 || f.kaCount != 0) {
		return errors.New("--tcp-keepalive-off cannot be combined with the other --tcp-keepalive flags")
	}
	size := func(name, v string, min, max int64) (int, error) {
		if v == "" {
			return 0, nil
		}
		n, err := ParseSize(v)
		if err != nil || n < min || n > max {
			return 0, fmt.Errorf("%s %q: want a size from %d to %d bytes", name, v, min, max)
		}
		return int(n), nil
	}
	var err error
	if sh.H2.InitialWindow, err = size("--h2-initial-window", f.h2Window, 1, 1<<31-1); err != nil {
		return err
	}
	if sh.H2.MaxFrameSize, err = size("--h2-max-frame-size", f.h2Frame, 1<<14, 1<<24-1); err != nil {
		return err
	}
	if sh.H2.MaxConnWindow, err = size("--h2-max-conn-window", f.h2ConnWindow, 1, 1<<31-1); err != nil {
		return err
	}
	sh.H2.MaxStreams = f.h2Streams
	if f.bwIn != "" {
		if sh.BandwidthIn, err = ParseRateBytes(f.bwIn); err != nil || sh.BandwidthIn <= 0 {
			return fmt.Errorf("--bandwidth-request %q: want a positive rate such as 1MB/s", f.bwIn)
		}
	}
	if f.bwOut != "" {
		if sh.BandwidthOut, err = ParseRateBytes(f.bwOut); err != nil || sh.BandwidthOut <= 0 {
			return fmt.Errorf("--bandwidth-response %q: want a positive rate such as 1MB/s", f.bwOut)
		}
	}
	switch f.reqID {
	case "", RequestIDPreserve:
		sh.RequestID = RequestIDPreserve
	case RequestIDGenerate, RequestIDUpstream:
		sh.RequestID = f.reqID
	default:
		return fmt.Errorf("--request-id %q: want preserve, generate or trust-upstream", f.reqID)
	}
	if f.compress {
		sh.Compress.Enabled = true
	}
	for _, t := range splitList(f.compressTypes) {
		if !validMediaPattern(t) {
			return fmt.Errorf("--compress-types %q: want type/subtype, type/* or */*+suffix", t)
		}
		sh.Compress.Types = append(sh.Compress.Types, t)
	}
	for _, e := range splitList(f.compressEnc) {
		if !inList(supportedEncodings, strings.ToLower(e)) {
			return fmt.Errorf("--compress-encodings %q: the standard library offers gzip and deflate (brotli and zstd are not available)", e)
		}
		sh.Compress.Encodings = append(sh.Compress.Encodings, strings.ToLower(e))
	}
	if f.compressMin != "" {
		if sh.Compress.MinSize, err = parseBodyLimit(f.compressMin); err != nil {
			return fmt.Errorf("--compress-min-size: %w", err)
		}
	}
	if f.compressLevel != 0 {
		if f.compressLevel > 9 {
			return fmt.Errorf("--compress-level %d: want 1 to 9", f.compressLevel)
		}
		sh.Compress.Level = f.compressLevel
	}
	if !f.compress && (f.compressTypes != "" || f.compressEnc != "" || f.compressMin != "" || f.compressLevel != 0) {
		return errors.New("--compress-types, --compress-encodings, --compress-min-size and --compress-level need --compress")
	}
	return f.applyRedis(o)
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (f *shapeFlags) applyRedis(o *Options) error {
	if len(f.redis) == 0 {
		if f.redisTLS || f.redisCA != "" || f.redisPassFile != "" || f.redisTimeout != 0 || f.redisPool != 0 || f.redisDial != 0 {
			return errors.New("the --redis-* flags need --redis")
		}
		return nil
	}
	pass := os.Getenv("SETURA_REDIS_PASSWORD")
	if f.redisPassFile != "" {
		raw, err := os.ReadFile(f.redisPassFile)
		if err != nil {
			return fmt.Errorf("--redis-password-file: %w", err)
		}
		pass = strings.TrimRight(string(raw), "\r\n")
	}
	seen := map[string]bool{}
	for _, v := range f.redis {
		ro, err := ParseRedisFlag(v)
		if err != nil {
			return fmt.Errorf("--redis: %w", err)
		}
		if seen[ro.Name] {
			return fmt.Errorf("--redis: the name %q is used twice", ro.Name)
		}
		seen[ro.Name] = true
		if ro.Password == "" {
			ro.Password = pass
		}
		ro.TLS = ro.TLS || f.redisTLS
		ro.CAFile, ro.IOTimeout, ro.DialTimeout, ro.PoolSize = f.redisCA, f.redisTimeout, f.redisDial, f.redisPool
		if _, err := NewRedisClient(ro); err != nil {
			return fmt.Errorf("--redis: %w", err)
		}
		o.Redis = append(o.Redis, ro)
	}
	return nil
}

// ---- metrics ----

// shapingMetrics writes the connection limit, bandwidth, compression and
// gRPC-web families. Their labels are bounded: route and port come from the
// configuration, the rest from fixed sets.
func (s *Server) shapingMetrics(b *strings.Builder) {
	fam := func(name, typ, help, key string, scale func(int64) string) {
		keys, vals := s.shape.snapshot(key)
		if len(keys) == 0 {
			return
		}
		fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, k := range keys {
			v := strconv.FormatInt(vals[k], 10)
			if scale != nil {
				v = scale(vals[k])
			}
			fmt.Fprintf(b, "%s{%s} %s\n", name, k, v)
		}
	}
	fam("setura_gateway_compress_responses_total", "counter", "Responses compressed, per route and encoding.", "compress_responses", nil)
	fam("setura_gateway_compress_bytes_total", "counter", "Body bytes before (in) and after (out) compression, per route.", "compress_bytes", nil)
	fam("setura_gateway_bandwidth_limited_total", "counter", "Requests whose body or response was paced by a bandwidth limit.", "bandwidth_limited", nil)
	fam("setura_gateway_bandwidth_delay_seconds_total", "counter", "Time spent waiting for bandwidth tokens, per route and direction.", "bandwidth_delay_ms",
		func(ms int64) string { return strconv.FormatFloat(float64(ms)/1000, 'f', 3, 64) })
	fam("setura_gateway_grpcweb_requests_total", "counter", "gRPC-web requests bridged to gRPC, per route, mode (binary or text) and result (ok or error).", "grpcweb", nil)
	s.mu.Lock()
	ports := make([]int, 0, len(s.ports))
	for p, bp := range s.ports {
		if bp.cl != nil && (bp.cl.max.Load() > 0 || bp.cl.perIP.Load() > 0) {
			ports = append(ports, p)
		}
	}
	s.mu.Unlock()
	if len(ports) == 0 {
		return
	}
	sortInts(ports)
	fmt.Fprint(b, "# HELP setura_gateway_conn_limit_rejected_total Client connections closed at accept for exceeding a connection limit (reason total or per_ip).\n# TYPE setura_gateway_conn_limit_rejected_total counter\n")
	s.mu.Lock()
	for _, p := range ports {
		cl := s.ports[p].cl
		fmt.Fprintf(b, "setura_gateway_conn_limit_rejected_total{port=\"%d\",reason=\"total\"} %d\n", p, cl.rejTot.Load())
		fmt.Fprintf(b, "setura_gateway_conn_limit_rejected_total{port=\"%d\",reason=\"per_ip\"} %d\n", p, cl.rejIP.Load())
	}
	fmt.Fprint(b, "# HELP setura_gateway_listener_connections Client connections currently open on a listener port with a connection limit.\n# TYPE setura_gateway_listener_connections gauge\n")
	for _, p := range ports {
		fmt.Fprintf(b, "setura_gateway_listener_connections{port=\"%d\"} %d\n", p, s.ports[p].cl.active())
	}
	s.mu.Unlock()
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}
