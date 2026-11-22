package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultAdmin is the admin listen address.
const DefaultAdmin = "127.0.0.1:19000"

// Options configures a Server.
type Options struct {
	Bind        string      // listener bind address, default 127.0.0.1
	PortMap     map[int]int // spec port -> bound port (0 asks the OS for a free port)
	PortOffset  int         // added to spec ports below 1024 that PortMap does not name
	Admin       string      // admin address; "off" disables, empty means DefaultAdmin
	Force       bool        // apply configs that have lint errors
	AccessLog   io.Writer   // JSON-lines access log, nil to disable
	Diag        io.Writer   // human diagnostics, nil to discard
	Rand        func(n int) int
	ConnHistory int               // recent request records kept for /connections (0 = 500, negative disables)
	Obs         ObsOptions        // access log format, tracing export, rate limiting
	ShadowDiff  int               // default shadow comparison sample percent (0 = only annotated mirrors compare)
	Resilience  ResilienceOptions // retries, outlier ejection, default health checks
	// Lint inspects a snapshot and reports whether it has no lint errors.
	Lint func(snapshot []byte) (ok bool, report string)
}

// Loaded is one configuration read from a Source.
type Loaded struct {
	Config   *Config
	Hash     string
	Snapshot []byte // raw snapshot JSON when the source is lintable
}

// Source produces configurations; the server polls it for changes.
type Source interface {
	Load(ctx context.Context) (*Loaded, error)
}

// StatusWriter is implemented by sources that publish status elsewhere.
type StatusWriter interface {
	WriteStatus(ctx context.Context, doc *StatusDoc) error
}

type boundPort struct {
	ln  net.Listener
	srv *http.Server
	tls bool
	raw *rawListener // TLS passthrough listener; srv is nil then
}

// Server is the built-in gateway data plane.
type Server struct {
	opts  Options
	table atomic.Pointer[Table]
	stats *Stats
	obs   *obs
	conns *connTable // nil when connection history is disabled

	mu       sync.Mutex
	ports    map[int]*boundPort
	seq      int64
	hash     string
	rejected string
	status   atomic.Pointer[StatusDoc]
	health   context.CancelFunc
	mirrorWG sync.WaitGroup
	shadow   shadowState

	res            *resilience
	tr, trInsecure *http.Transport
	grpcTr         grpcTransports
	ready          atomic.Bool

	adminLn  net.Listener
	adminSrv *http.Server
}

// New creates a Server. Nothing listens until Apply or Run.
func New(opts Options) *Server {
	if opts.Bind == "" {
		opts.Bind = "127.0.0.1"
	}
	mk := func(insecure bool) *http.Transport {
		return &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			MaxIdleConns: 256, MaxIdleConnsPerHost: 64, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}}
	}
	hist := opts.ConnHistory
	if hist == 0 {
		hist = DefaultConnHistory
	}
	return &Server{opts: opts, stats: newStats(), conns: newConnTable(hist), obs: newObs(&opts), res: newResilience(opts.Resilience), ports: map[int]*boundPort{}, tr: mk(false), trInsecure: mk(true)}
}

func (s *Server) transport(insecure bool) http.RoundTripper {
	if insecure {
		return s.trInsecure
	}
	return s.tr
}

func (s *Server) diag(format string, a ...any) {
	if s.opts.Diag != nil {
		fmt.Fprintf(s.opts.Diag, format+"\n", a...)
	}
}

func (s *Server) actualPort(p int) int {
	if v, ok := s.opts.PortMap[p]; ok {
		return v
	}
	if p < 1024 {
		return p + s.opts.PortOffset
	}
	return p
}

// Addr returns the bound address for a spec port, or "".
func (s *Server) Addr(specPort int) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bp := s.ports[specPort]; bp != nil {
		return bp.ln.Addr().String()
	}
	return ""
}

// AdminAddr returns the admin listener address.
func (s *Server) AdminAddr() string {
	if s.adminLn == nil {
		return ""
	}
	return s.adminLn.Addr().String()
}

// Ready reports whether a table has been applied.
func (s *Server) Ready() bool { return s.ready.Load() }

// Table returns the current routing table.
func (s *Server) Table() *Table { return s.table.Load() }

// Status returns the latest status document.
func (s *Server) Status() *StatusDoc { return s.status.Load() }

// Stats returns the counters.
func (s *Server) Stats() *Stats { return s.stats }

func (s *Server) startPort(spec int, pg *PortGroup) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(s.opts.Bind, strconv.Itoa(s.actualPort(spec))))
	if err != nil {
		return err
	}
	if pg.Passthrough {
		s.ports[spec] = &boundPort{ln: ln, raw: s.startPassthrough(ln, spec)}
		return nil
	}
	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveHTTP(w, r, spec) })}
	enableH2C(srv, pg.TLS)
	bp := &boundPort{ln: ln, srv: srv, tls: pg.TLS}
	s.ports[spec] = bp
	if pg.TLS {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"},
			GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return s.certFor(spec, h.ServerName) }}
		go srv.ServeTLS(ln, "", "")
	} else {
		go srv.Serve(ln)
	}
	return nil
}

// certFor picks the certificate for an SNI name on a port.
func (s *Server) certFor(port int, sni string) (*tls.Certificate, error) {
	t := s.table.Load()
	if t == nil || t.Ports[port] == nil {
		return nil, errors.New("no listener")
	}
	pg := t.Ports[port]
	sni = strings.ToLower(sni)
	var l *RTListener
	if sni != "" {
		l = pg.pickListener(sni)
	}
	if l == nil || len(l.Certs) == 0 {
		l = nil
		for _, c := range pg.Listeners {
			if len(c.Certs) > 0 && (l == nil || c.Host == "") {
				l = c
			}
		}
	}
	if l == nil {
		return nil, errors.New("no certificate")
	}
	for i := range l.Certs {
		if sni != "" && l.Certs[i].Leaf != nil && l.Certs[i].Leaf.VerifyHostname(sni) == nil {
			return &l.Certs[i], nil
		}
	}
	return &l.Certs[0], nil
}

func (s *Server) closePort(bp *boundPort) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		bp.shutdown(ctx)
	}()
}

// Apply builds a table from the config and swaps it in atomically. Listeners
// whose ports are unchanged keep their sockets, so no connection is dropped.
func (s *Server) Apply(ld *Loaded) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	cfg := ld.Config
	for _, g := range cfg.Gateways {
		if g.Generation == 0 {
			g.Generation = s.seq
		}
	}
	for _, r := range cfg.Routes {
		if r.Generation == 0 {
			r.Generation = s.seq
		}
	}
	t := BuildTable(cfg)
	bindErr := map[string]string{}
	specPorts := make([]int, 0, len(t.Ports))
	for p := range t.Ports {
		specPorts = append(specPorts, p)
	}
	sort.Ints(specPorts)
	for _, p := range specPorts {
		pg := t.Ports[p]
		if bp := s.ports[p]; bp != nil && (bp.tls != pg.TLS || (bp.raw != nil) != pg.Passthrough) {
			s.closePort(bp)
			delete(s.ports, p)
		}
		if s.ports[p] == nil {
			if err := s.startPort(p, pg); err != nil {
				for _, l := range pg.Listeners {
					bindErr[l.Key] = err.Error()
				}
			}
		}
	}
	s.table.Store(t)
	for p, bp := range s.ports {
		if t.Ports[p] == nil {
			s.closePort(bp)
			delete(s.ports, p)
		}
	}
	if s.health != nil {
		s.health()
	}
	hctx, cancel := context.WithCancel(context.Background())
	s.health = cancel
	for _, b := range t.Backends {
		s.startHealth(hctx, b) // no-op without a healthCheck or default path
	}
	now := time.Now()
	doc := BuildStatus(t, bindErr, now, s.status.Load())
	doc.Generation, doc.ConfigHash = s.seq, ld.Hash
	doc.LastReload = ReloadInfo{OK: true, Time: now.UTC().Format(time.RFC3339)}
	s.status.Store(doc)
	s.hash, s.rejected = ld.Hash, ""
	s.ready.Store(true)
	return nil
}

// recordFailure notes a rejected reload while the old table keeps serving.
func (s *Server) recordFailure(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.status.Load()
	doc := &StatusDoc{Schema: StatusSchema, Gateways: map[string]*GatewayStatus{}, Routes: map[string]*RouteStatus{}}
	if old != nil {
		cp := *old
		doc = &cp
	}
	doc.LastReload = ReloadInfo{OK: false, Time: time.Now().UTC().Format(time.RFC3339), Error: err.Error()}
	s.status.Store(doc)
}

// markReloadOK clears a recorded failure once the source loads cleanly again
// with a configuration identical to the one being served.
func (s *Server) markReloadOK() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.status.Load(); old != nil && !old.LastReload.OK {
		cp := *old
		cp.LastReload = ReloadInfo{OK: true, Time: time.Now().UTC().Format(time.RFC3339)}
		s.status.Store(&cp)
	}
}

// Listening describes bound listeners for the operator.
func (s *Server) Listening() []string {
	t := s.table.Load()
	if t == nil {
		return nil
	}
	var out []string
	for _, l := range t.Listeners {
		if !l.Serving {
			continue
		}
		scheme := "http"
		switch l.L.Protocol {
		case "HTTPS":
			scheme = "https"
		case "TLS":
			scheme = "tls-passthrough"
		}
		host := l.Host
		if host == "" {
			host = "*"
		}
		out = append(out, fmt.Sprintf("%s %s://%s (listening on %s)", l.Key, scheme, host, s.Addr(l.L.Port)))
	}
	return out
}

func (s *Server) lintGate(ld *Loaded) error {
	if ld.Snapshot == nil || s.opts.Lint == nil || s.opts.Force {
		return nil
	}
	if ok, report := s.opts.Lint(ld.Snapshot); !ok {
		return fmt.Errorf("refusing configuration with lint errors (use --force to override):\n%s", strings.TrimRight(report, "\n"))
	}
	return nil
}

// Reload loads from src and applies when the content changed. It returns
// whether a new table was applied.
func (s *Server) Reload(ctx context.Context, src Source) (bool, error) {
	ld, err := src.Load(ctx)
	if err != nil {
		s.recordFailure(err)
		return false, err
	}
	s.mu.Lock()
	same := s.ready.Load() && ld.Hash == s.hash
	rejected := ld.Hash == s.rejected
	s.mu.Unlock()
	if rejected {
		return false, nil // already refused and reported; wait for the file to change
	}
	if same {
		s.markReloadOK()
		return false, nil
	}
	if err := s.lintGate(ld); err != nil {
		s.mu.Lock()
		s.rejected = ld.Hash
		s.mu.Unlock()
		s.recordFailure(err)
		return false, err
	}
	return true, s.Apply(ld)
}

// Run serves until ctx ends: it applies the first configuration (failing if
// it is invalid), starts the admin endpoint and polls src every interval.
func (s *Server) Run(ctx context.Context, src Source, interval time.Duration) error {
	defer s.Close()
	if interval <= 0 {
		interval = time.Second
	}
	ld, err := src.Load(ctx)
	if err != nil {
		return err
	}
	if err := s.lintGate(ld); err != nil {
		return err
	}
	if err := s.startAdmin(); err != nil {
		return err
	}
	if err := s.Apply(ld); err != nil {
		return err
	}
	for _, l := range s.Listening() {
		s.diag("serving %s", l)
	}
	if a := s.AdminAddr(); a != "" {
		s.diag("admin http://%s (/ready /config /stats /status /shadow)", a)
	}
	write := func() {
		if sw, ok := src.(StatusWriter); ok {
			if err := sw.WriteStatus(ctx, s.Status()); err != nil && ctx.Err() == nil {
				s.diag("status write: %v", err)
			}
		}
	}
	write()
	wake := make(chan struct{}, 1)
	if bg, ok := src.(Background); ok {
		if resync := bg.Start(ctx, func() {
			select {
			case wake <- struct{}{}:
			default:
			}
		}); resync > 0 {
			interval = resync // events drive reloads; the ticker is only a safety net
		}
		defer bg.Wait() // runs before s.Close; releases a held lease
	}
	tick := func() {
		switch changed, err := s.Reload(ctx, src); {
		case err != nil:
			if ctx.Err() == nil {
				s.diag("reload rejected, keeping previous configuration: %v", err)
			}
		case changed:
			s.diag("configuration applied (generation %d)", s.Status().Generation)
		}
		write()
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tk.C:
			tick()
		case <-wake:
			select { // coalesce a burst of events into one reload
			case <-time.After(50 * time.Millisecond):
			case <-ctx.Done():
				return nil
			}
			select {
			case <-wake:
			default:
			}
			tick()
		}
	}
}

// Close stops every listener and background task.
func (s *Server) Close() {
	s.mu.Lock()
	for p, bp := range s.ports {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		bp.shutdown(ctx)
		cancel()
		delete(s.ports, p)
	}
	if s.health != nil {
		s.health()
		s.health = nil
	}
	s.mu.Unlock()
	if s.adminSrv != nil {
		s.adminSrv.Close()
	}
	s.mirrorWG.Wait()
	s.tr.CloseIdleConnections()
	s.trInsecure.CloseIdleConnections()
	s.obs.close()
	s.grpcTr.closeIdle()
}

func (s *Server) startAdmin() error {
	addr := s.opts.Admin
	if addr == "off" {
		return nil
	}
	if addr == "" {
		addr = DefaultAdmin
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin listener: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if s.Ready() {
			io.WriteString(w, "ready\n")
			return
		}
		plain(w, http.StatusServiceUnavailable, "not ready")
	})
	jsonOut := func(f func() any) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			v := f()
			if v == nil {
				plain(w, http.StatusServiceUnavailable, "not ready")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			enc.Encode(v)
		}
	}
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { s.metrics(w, r); s.WriteMetrics(w) })
	mux.HandleFunc("/connections", s.connectionsHandler)
	mux.HandleFunc("/shadow", jsonOut(func() any { return s.shadow.Summary() }))
	mux.HandleFunc("/stats", jsonOut(func() any { return s.stats.Snapshot() }))
	mux.HandleFunc("/status", jsonOut(func() any {
		if d := s.Status(); d != nil {
			return d
		}
		return nil
	}))
	mux.HandleFunc("/config", jsonOut(func() any {
		if t := s.Table(); t != nil {
			return t.Cfg.Dump()
		}
		return nil
	}))
	mux.HandleFunc("/why", s.handleWhy)
	s.adminLn = ln
	s.adminSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go s.adminSrv.Serve(ln)
	return nil
}

// Dump is the /config document. Secret material is never included.
func (c *Config) Dump() map[string]any {
	gws, routes := []any{}, []any{}
	for _, g := range c.Gateways {
		gws = append(gws, map[string]any{"namespace": g.NS, "name": g.Name, "generation": g.Generation, "gatewayClassName": g.ClassName, "listeners": g.Listeners})
	}
	for _, r := range c.Routes {
		routes = append(routes, map[string]any{"namespace": r.NS, "name": r.Name, "generation": r.Generation,
			"parentRefs": r.Parents, "hostnames": r.Hostnames, "rules": r.Rules})
	}
	out := map[string]any{"namespace": c.Namespace, "gateways": gws, "httproutes": routes, "backends": c.Backends, "secrets": sortedKeys(c.Secrets)}
	c.dumpExtra(out)
	return out
}
