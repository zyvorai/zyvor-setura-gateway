package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// TCPRoute and UDPRoute (gateway.networking.k8s.io/v1): plain layer 4
// forwarding. A TCP or UDP listener carries exactly the matching route kind;
// there is nothing to match on, so a listener sends every connection (TCP) or
// every client (UDP) to the weighted backendRefs of the oldest route attached
// to it. TCP connections are spliced with half-close; UDP uses a session table
// keyed by client address with an idle timeout.

// L4Route is a TCPRoute or UDPRoute.
type L4Route struct {
	Kind       string // "TCPRoute" or "UDPRoute"
	NS, Name   string
	Generation int64
	Created    time.Time
	Parents    []ParentRef
	Rules      []L4Rule
}

// L4Rule is one rule of a TCPRoute or UDPRoute.
type L4Rule struct {
	Name        string       `json:"name,omitempty"`
	BackendRefs []BackendRef `json:"backendRefs,omitempty"`
}

type l4Spec struct {
	creationMeta
	ParentRefs []ParentRef `json:"parentRefs"`
	Rules      []L4Rule    `json:"rules"`
}

func (r *L4Route) stub() *Route {
	return &Route{Kind: r.Kind, NS: r.NS, Name: r.Name, Generation: r.Generation, Created: r.Created, Parents: r.Parents}
}

// L4Entry is one rule of a route on one listener.
type L4Entry struct {
	RouteKey string
	Rule     int
	Name     string
	Refs     []*CRef
	Total    int
}

func (c *Config) parseL4Route(kind, ns, name string, raw json.RawMessage) error {
	var spec l4Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return err
	}
	created, err := spec.created()
	if err != nil {
		return err
	}
	r := &L4Route{NS: ns, Name: name, Created: created, Parents: spec.ParentRefs, Rules: spec.Rules}
	if kind == tcpRouteKey {
		r.Kind = "TCPRoute"
		c.TCPRoutes = append(c.TCPRoutes, r)
	} else {
		r.Kind = "UDPRoute"
		c.UDPRoutes = append(c.UDPRoutes, r)
	}
	return nil
}

// attachL4 attaches TCPRoutes and UDPRoutes, oldest first.
func (t *Table) attachL4() {
	rs := append(append([]*L4Route(nil), t.Cfg.TCPRoutes...), t.Cfg.UDPRoutes...)
	sort.SliceStable(rs, func(i, j int) bool {
		if !rs[i].Created.Equal(rs[j].Created) {
			return rs[i].Created.Before(rs[j].Created)
		}
		return rs[i].stub().StatusKey() < rs[j].stub().StatusKey()
	})
	for _, r := range rs {
		stub := r.stub()
		res := &routeResult{Route: stub, Refs: fact{true, "ResolvedRefs", "all references resolved"}}
		t.addRoute(res)
		var entries []*L4Entry
		for i, rule := range r.Rules {
			e := &L4Entry{RouteKey: stub.StatusKey(), Rule: i, Name: rule.Name}
			for _, ref := range rule.BackendRefs {
				w := refWeight(ref)
				b, fc := t.backendFor(r.Kind, r.NS, ref)
				if !fc.OK && res.Refs.OK {
					res.Refs = fc
				}
				e.Refs = append(e.Refs, &CRef{Name: ref.Name, B: b, Weight: w})
				e.Total += w
			}
			entries = append(entries, e)
		}
		res.Parents = t.attachParents(r.Kind, r.NS, r.Parents, nil, nil, func(l *RTListener, _ []string) {
			l.L4Entries = append(l.L4Entries, entries...)
		})
	}
}

// pick returns the entry a listener sends traffic to: the first rule, of the
// oldest route, that has a backend.
func (l *RTListener) l4Pick() *L4Entry {
	for _, e := range l.L4Entries {
		if len(e.Refs) > 0 {
			return e
		}
	}
	return nil
}

// l4Stats are the layer 4 counters served on /metrics.
type l4Stats struct {
	mu       sync.Mutex
	conns    map[string]int64 // protocol|route|backend -> accepted connections or sessions
	failures map[string]int64
	bytesIn  map[string]int64
	bytesOut map[string]int64
	udpOpen  atomic.Int64
}

func (l *l4Stats) bump(m *map[string]int64, key string, n int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[key] += n
}

func l4Key(proto, route, backend string) string { return proto + "|" + route + "|" + backend }

func (s *Server) writeL4Metrics(w io.Writer) {
	l := &s.l4
	l.mu.Lock()
	defer l.mu.Unlock()
	emit := func(name, help string, m map[string]int64) {
		if len(m) == 0 {
			return
		}
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		for _, k := range sortedKeys(m) {
			var p, r, b string
			parts := splitN(k, 3)
			p, r, b = parts[0], parts[1], parts[2]
			fmt.Fprintf(w, "%s{protocol=\"%s\",route=\"%s\",backend=\"%s\"} %d\n", name, promLabel(p), promLabel(r), promLabel(b), m[k])
		}
	}
	emit("setura_gateway_l4_connections_total", "TCP connections and UDP sessions accepted, by route and backend.", l.conns)
	emit("setura_gateway_l4_failures_total", "TCP connections and UDP sessions that could not reach a backend.", l.failures)
	emit("setura_gateway_l4_bytes_in_total", "Bytes from clients to backends on TCP and UDP listeners.", l.bytesIn)
	emit("setura_gateway_l4_bytes_out_total", "Bytes from backends to clients on TCP and UDP listeners.", l.bytesOut)
	fmt.Fprintf(w, "# HELP setura_gateway_udp_sessions_open UDP sessions currently in the session table.\n# TYPE setura_gateway_udp_sessions_open gauge\nsetura_gateway_udp_sessions_open %d\n", l.udpOpen.Load())
}

func splitN(s string, n int) []string {
	out := make([]string, 0, n)
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == '|' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// dialBackend connects to one endpoint of b, moving to the next on failure,
// and feeds the outcomes to outlier detection.
func (s *Server) dialBackend(b *Backend, network string) (net.Conn, *Endpoint, []attemptRec, time.Duration, error) {
	var attempts []attemptRec
	tried := map[*Endpoint]bool{}
	var lastErr error
	for range b.Eps {
		ep := b.choose(s.res.now(), tried)
		if ep == nil || tried[ep] {
			break
		}
		tried[ep] = true
		t0 := time.Now()
		c, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial(network, ep.URL.Host)
		d := time.Since(t0)
		rec := attemptRec{Addr: ep.URL.Host, ConnectMS: ms(d)}
		if err != nil {
			rec.Error = err.Error()
		}
		attempts = append(attempts, rec)
		if network == "tcp" {
			s.res.observe(b, ep, err != nil, s.res.now())
		}
		if err == nil {
			return c, ep, attempts, d, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no endpoints")
	}
	return nil, nil, attempts, 0, lastErr
}

// ---- TCP ----

func (s *Server) startTCP(ln net.Listener, port int) *rawListener {
	rl := &rawListener{ln: ln, conns: map[net.Conn]struct{}{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !rl.track(c) {
				c.Close()
				continue
			}
			rl.wg.Add(1)
			go func() {
				defer rl.wg.Done()
				defer rl.untrack(c)
				s.tcpProxy(rl, c, port)
			}()
		}
	}()
	return rl
}

const protoTCP = "TCP"

// tcpProxy forwards one TCP connection to a weighted backend and splices the
// two directions, half-closing so a one-way FIN reaches the peer.
func (s *Server) tcpProxy(rl *rawListener, c net.Conn, port int) {
	defer c.Close()
	start := time.Now()
	ip, cport := splitRemote(c.RemoteAddr().String())
	line := logLine{Method: protoTCP, Remote: c.RemoteAddr().String(), ClientIP: ip, ClientPort: cport, ListenerPort: port, Protocol: protoTCP}
	open, unregister := s.conns.register(OpenView{Kind: "tcp", ClientIP: ip, ClientPort: cport, ListenerPort: port, Protocol: protoTCP})
	defer unregister()
	var local openConn
	var status int
	var routeKey, backendKey string
	defer func() {
		s.stats.record(routeKey, backendKey, status)
		line.Status, line.Route, line.Backend = status, routeKey, backendKey
		s.logConn(&line, start)
		s.l4.bump(&s.l4.conns, l4Key(protoTCP, routeKey, backendKey), 1)
		if status >= 500 {
			s.l4.bump(&s.l4.failures, l4Key(protoTCP, routeKey, backendKey), 1)
		}
		s.l4.bump(&s.l4.bytesIn, l4Key(protoTCP, routeKey, backendKey), line.RequestBytes)
		s.l4.bump(&s.l4.bytesOut, l4Key(protoTCP, routeKey, backendKey), line.ResponseBytes)
	}()
	t := s.table.Load()
	var pg *PortGroup
	if t != nil {
		pg = t.Ports[port]
	}
	if pg == nil || len(pg.Listeners) == 0 {
		status, line.Error = http.StatusServiceUnavailable, "gateway not ready"
		return
	}
	l := pg.Listeners[0]
	line.Listener = l.Key
	e := l.l4Pick()
	if e == nil {
		status, line.Error = http.StatusServiceUnavailable, "no TCPRoute attached to this listener"
		return
	}
	routeKey = e.RouteKey
	ref := s.pickWeighted(e.Refs, e.Total)
	if ref == nil || ref.B == nil {
		status, line.Error = http.StatusInternalServerError, "no valid backend"
		return
	}
	backendKey, line.BackendWeight = ref.B.Key, ref.Weight
	open.set(func(v *OpenView) { v.Listener, v.Route, v.Backend = l.Key, routeKey, backendKey })
	up, ep, attempts, dialTime, err := s.dialBackend(ref.B, "tcp")
	if len(attempts) > 1 {
		line.Attempts = attempts
	}
	line.Retries = len(attempts) - 1
	if err != nil {
		status, line.Error = http.StatusBadGateway, "dialing backend: "+err.Error()
		return
	}
	defer up.Close()
	line.UpstreamAddr, line.UpstreamConnectMS = ep.URL.Host, ms(dialTime)
	line.UpstreamProto, line.UpstreamTLS, line.UpstreamReused = "tcp", boolp(false), boolp(false)
	open.set(func(v *OpenView) { v.UpstreamAddr = line.UpstreamAddr })
	if !rl.track(up) {
		return
	}
	defer rl.untrack(up)
	in, out := &local.in, &local.out
	if open != nil {
		in, out = &open.in, &open.out
	}
	status = http.StatusOK
	splice(c, up, &line, in, out)
}

// ---- UDP ----

const (
	defaultUDPIdle   = 30 * time.Second
	maxUDPSessions   = 65536
	maxUDPDatagram   = 65535
	protoUDP         = "UDP"
	udpSessionReason = "udp session"
)

type udpSession struct {
	client  net.Addr
	up      net.Conn
	last    atomic.Int64 // unix nanoseconds of the latest client datagram
	route   string
	backend string
	in, out atomic.Int64
	once    sync.Once
}

type udpProxy struct {
	s        *Server
	pc       net.PacketConn
	port     int
	idle     time.Duration
	mu       sync.Mutex
	sessions map[string]*udpSession
	wg       sync.WaitGroup
	closed   bool
}

func (s *Server) startUDP(pc net.PacketConn, port int) *udpProxy {
	idle := s.opts.UDPIdle
	if idle <= 0 {
		idle = defaultUDPIdle
	}
	u := &udpProxy{s: s, pc: pc, port: port, idle: idle, sessions: map[string]*udpSession{}}
	u.wg.Add(1)
	go u.serve()
	return u
}

func (u *udpProxy) serve() {
	defer u.wg.Done()
	buf := make([]byte, maxUDPDatagram)
	for {
		n, addr, err := u.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		sess := u.session(addr)
		if sess == nil {
			continue
		}
		sess.last.Store(time.Now().UnixNano())
		if w, err := sess.up.Write(buf[:n]); err == nil {
			sess.in.Add(int64(w))
		}
	}
}

// session finds or creates the session of a client address. A new session
// picks its backend once; every later datagram of that client follows it.
func (u *udpProxy) session(addr net.Addr) *udpSession {
	key := addr.String()
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	if sess := u.sessions[key]; sess != nil {
		return sess
	}
	if len(u.sessions) >= maxUDPSessions {
		u.s.l4.bump(&u.s.l4.failures, l4Key(protoUDP, "", ""), 1)
		return nil
	}
	s := u.s
	t := s.table.Load()
	var pg *PortGroup
	if t != nil {
		pg = t.Ports[u.port]
	}
	if pg == nil || len(pg.Listeners) == 0 {
		return nil
	}
	l := pg.Listeners[0]
	e := l.l4Pick()
	if e == nil {
		return nil
	}
	ref := s.pickWeighted(e.Refs, e.Total)
	if ref == nil || ref.B == nil {
		s.stats.record(e.RouteKey, "", http.StatusInternalServerError)
		s.l4.bump(&s.l4.failures, l4Key(protoUDP, e.RouteKey, ""), 1)
		return nil
	}
	up, _, _, _, err := s.dialBackend(ref.B, "udp")
	if err != nil {
		s.stats.record(e.RouteKey, ref.B.Key, http.StatusBadGateway)
		s.l4.bump(&s.l4.failures, l4Key(protoUDP, e.RouteKey, ref.B.Key), 1)
		return nil
	}
	sess := &udpSession{client: addr, up: up, route: e.RouteKey, backend: ref.B.Key}
	sess.last.Store(time.Now().UnixNano())
	u.sessions[key] = sess
	s.l4.udpOpen.Add(1)
	s.l4.bump(&s.l4.conns, l4Key(protoUDP, sess.route, sess.backend), 1)
	u.wg.Add(1)
	go u.relay(key, sess)
	return sess
}

// relay copies backend datagrams to the client until the session is idle.
func (u *udpProxy) relay(key string, sess *udpSession) {
	defer u.wg.Done()
	buf := make([]byte, maxUDPDatagram)
	for {
		sess.up.SetReadDeadline(time.Unix(0, sess.last.Load()).Add(u.idle))
		n, err := sess.up.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() && time.Since(time.Unix(0, sess.last.Load())) < u.idle {
				continue // the client spoke meanwhile: extend the deadline
			}
			break
		}
		if _, werr := u.pc.WriteTo(buf[:n], sess.client); werr == nil {
			sess.out.Add(int64(n))
		}
	}
	u.end(key, sess)
}

func (u *udpProxy) end(key string, sess *udpSession) {
	sess.once.Do(func() {
		sess.up.Close()
		u.mu.Lock()
		delete(u.sessions, key)
		u.mu.Unlock()
		s := u.s
		s.l4.udpOpen.Add(-1)
		s.stats.record(sess.route, sess.backend, http.StatusOK)
		k := l4Key(protoUDP, sess.route, sess.backend)
		s.l4.bump(&s.l4.bytesIn, k, sess.in.Load())
		s.l4.bump(&s.l4.bytesOut, k, sess.out.Load())
	})
}

// sessionCount is the number of live sessions (tests and /stats).
func (u *udpProxy) sessionCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.sessions)
}

func (u *udpProxy) shutdown(ctx context.Context) {
	u.mu.Lock()
	u.closed = true
	for _, sess := range u.sessions {
		sess.up.Close() // the relay goroutine notices and ends the session
	}
	u.mu.Unlock()
	u.pc.Close()
	done := make(chan struct{})
	go func() { u.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
