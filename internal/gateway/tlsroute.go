package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TLSRoute is a Gateway API TLSRoute (SNI routing for TLS passthrough).
type TLSRoute struct {
	NS, Name   string
	Generation int64
	Created    time.Time
	Parents    []ParentRef
	Hostnames  []string
	Rules      []TLSRule
}

// TLSRule is one TLSRoute rule.
type TLSRule struct {
	BackendRefs []BackendRef `json:"backendRefs,omitempty"`
	// ALPN restricts the rule to connections whose client offers (passthrough)
	// or negotiates (Terminate) one of these protocols, for example ["h2"].
	// It is a Setura extension: TLSRoute has no ALPN field. Among rules whose
	// hostnames match equally well, one with a matching ALPN wins over one
	// without; a rule whose ALPN does not match is skipped.
	ALPN []string `json:"setura.zyvor.dev/alpn,omitempty"`
}

type tlsRouteSpec struct {
	creationMeta
	ParentRefs []ParentRef `json:"parentRefs"`
	Hostnames  []string    `json:"hostnames"`
	Rules      []TLSRule   `json:"rules"`
}

func (r *TLSRoute) stub() *Route {
	return &Route{Kind: "TLSRoute", NS: r.NS, Name: r.Name, Generation: r.Generation, Created: r.Created, Parents: r.Parents, Hostnames: r.Hostnames}
}

// TLSEntry is one TLSRoute rule on one passthrough listener.
type TLSEntry struct {
	RouteKey string
	Hosts    []string
	Refs     []*CRef
	Total    int
	ALPN     []string
}

func (t *Table) attachTLS(r *TLSRoute) {
	stub := r.stub()
	res := &routeResult{Route: stub, Refs: fact{true, "ResolvedRefs", "all references resolved"}}
	t.addRoute(res)
	var entries []*TLSEntry
	for i := range r.Rules {
		e := &TLSEntry{RouteKey: stub.StatusKey(), ALPN: r.Rules[i].ALPN}
		for _, ref := range r.Rules[i].BackendRefs {
			w := refWeight(ref)
			b, fc := t.backendFor("TLSRoute", r.NS, ref)
			if !fc.OK && res.Refs.OK {
				res.Refs = fc
			}
			e.Refs = append(e.Refs, &CRef{Name: ref.Name, B: b, Weight: w})
			e.Total += w
		}
		entries = append(entries, e)
	}
	res.Parents = t.attachParents("TLSRoute", r.NS, r.Parents, r.Hostnames, nil, func(l *RTListener, hosts []string) {
		for _, e := range entries {
			cp := *e
			cp.Hosts = hosts
			l.TLSEntries = append(l.TLSEntries, &cp)
		}
	})
}

// selectTLS finds the entry with the most specific hostname for an SNI name.
func (l *RTListener) selectTLS(host string) *TLSEntry { return l.selectTLST(host, nil) }

// selectTLST is selectTLS recording every entry considered on tr (nil on the
// data path).
func (l *RTListener) selectTLST(host string, tr *Trace) *TLSEntry {
	var best *TLSEntry
	bestRank := -1
	for _, e := range l.TLSEntries {
		matched, rank := false, -1
		for _, h := range e.Hosts {
			if hostMatches(h, host) {
				matched = true
				if hostRank(h) > rank {
					rank = hostRank(h)
				}
			}
			if hostMatches(h, host) && hostRank(h) > bestRank {
				best, bestRank = e, hostRank(h)
			}
		}
		if tr != nil {
			tr.noteTLS(e, matched, rank)
		}
	}
	return best
}

// selectTLSALPN is selectTLS that also takes the client's ALPN protocols into
// account (offered for passthrough, negotiated for Terminate).
func (l *RTListener) selectTLSALPN(host string, alpn []string) *TLSEntry {
	var best *TLSEntry
	bestRank, bestALPN := -1, false
	for _, e := range l.TLSEntries {
		withALPN := false
		if len(e.ALPN) > 0 {
			for _, want := range e.ALPN {
				for _, got := range alpn {
					withALPN = withALPN || want == got
				}
			}
			if !withALPN {
				continue
			}
		}
		for _, h := range e.Hosts {
			if !hostMatches(h, host) {
				continue
			}
			if r := hostRank(h); r > bestRank || (r == bestRank && withALPN && !bestALPN) {
				best, bestRank, bestALPN = e, r, withALPN
			}
		}
	}
	return best
}

// parseClientHello extracts the server_name from a ClientHello handshake
// message (hs starts at the handshake type byte). It reports whether hs holds
// the complete message; sni is empty when the extension is absent.
func parseClientHello(hs []byte) (sni string, complete bool, err error) {
	sni, _, complete, err = parseClientHelloALPN(hs)
	return
}

// parseClientHelloALPN is parseClientHello that also returns the protocols
// from the ALPN extension (empty when the client offers none).
func parseClientHelloALPN(hs []byte) (sni string, alpn []string, complete bool, err error) {
	if len(hs) < 4 {
		return "", nil, false, nil
	}
	if hs[0] != 1 {
		return "", nil, false, errors.New("not a ClientHello")
	}
	n := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if len(hs) < 4+n {
		return "", nil, false, nil
	}
	b := hs[4 : 4+n]
	bad := errors.New("malformed ClientHello")
	skip := func(k int) bool {
		if k > len(b) {
			return false
		}
		b = b[k:]
		return true
	}
	vec := func(lenBytes int) ([]byte, bool) {
		if len(b) < lenBytes {
			return nil, false
		}
		k := 0
		for i := 0; i < lenBytes; i++ {
			k = k<<8 | int(b[i])
		}
		if len(b) < lenBytes+k {
			return nil, false
		}
		v := b[lenBytes : lenBytes+k]
		b = b[lenBytes+k:]
		return v, true
	}
	if !skip(2 + 32) { // version, random
		return "", nil, true, bad
	}
	for _, lb := range []int{1, 2, 1} { // session id, cipher suites, compression
		if _, ok := vec(lb); !ok {
			return "", nil, true, bad
		}
	}
	if len(b) == 0 {
		return "", nil, true, nil // no extensions
	}
	exts, ok := vec(2)
	if !ok {
		return "", nil, true, bad
	}
	for len(exts) >= 4 {
		typ := int(exts[0])<<8 | int(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		if len(exts) < 4+l {
			return "", nil, true, bad
		}
		data := exts[4 : 4+l]
		exts = exts[4+l:]
		switch typ {
		case 0: // server_name
			if len(data) < 2 {
				return "", nil, true, bad
			}
			list := data[2:]
			for sni == "" && len(list) >= 3 {
				nt, nl := list[0], int(list[1])<<8|int(list[2])
				if len(list) < 3+nl {
					return "", nil, true, bad
				}
				if nt == 0 {
					sni = strings.TrimSuffix(strings.ToLower(string(list[3:3+nl])), ".")
				}
				list = list[3+nl:]
			}
		case 16: // application_layer_protocol_negotiation
			if len(data) < 2 {
				return "", nil, true, bad
			}
			list := data[2:]
			for len(list) >= 1 {
				pl := int(list[0])
				if len(list) < 1+pl {
					return "", nil, true, bad
				}
				alpn = append(alpn, string(list[1:1+pl]))
				list = list[1+pl:]
			}
		}
	}
	return sni, alpn, true, nil
}

const maxHelloBytes = 64 << 10

// readClientHello reads TLS records up to the end of the ClientHello without
// consuming anything beyond it. raw is every byte read, to be replayed to the
// backend.
func readClientHello(c io.Reader) (raw []byte, sni string, err error) {
	raw, sni, _, err = readClientHelloALPN(c)
	return
}

// readClientHelloALPN is readClientHello that also returns the ALPN protocols
// the client offered.
func readClientHelloALPN(c io.Reader) (raw []byte, sni string, alpn []string, err error) {
	var hs []byte
	for len(raw) < maxHelloBytes {
		var hdr [5]byte
		if _, err = io.ReadFull(c, hdr[:]); err != nil {
			return raw, "", nil, err
		}
		if hdr[0] != 22 || hdr[1] != 3 {
			return raw, "", nil, errors.New("not a TLS handshake")
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > 1<<14+256 {
			return raw, "", nil, errors.New("bad TLS record length")
		}
		rec := make([]byte, n)
		raw = append(raw, hdr[:]...)
		if _, err = io.ReadFull(c, rec); err != nil {
			return raw, "", nil, err
		}
		raw = append(raw, rec...)
		hs = append(hs, rec...)
		sni, alpn, done, perr := parseClientHelloALPN(hs)
		if perr != nil {
			return raw, "", nil, perr
		}
		if done {
			return raw, sni, alpn, nil
		}
	}
	return raw, "", nil, errors.New("ClientHello too large")
}

// rawListener serves a TLS passthrough port.
type rawListener struct {
	ln     net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
	closed bool
}

func (rl *rawListener) track(c net.Conn) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.closed {
		return false
	}
	rl.conns[c] = struct{}{}
	return true
}

func (rl *rawListener) untrack(c net.Conn) {
	rl.mu.Lock()
	delete(rl.conns, c)
	rl.mu.Unlock()
}

// shutdown stops accepting, waits for open connections until ctx ends, then
// closes whatever is left.
func (rl *rawListener) shutdown(ctx context.Context) {
	rl.mu.Lock()
	rl.closed = true
	rl.mu.Unlock()
	rl.ln.Close()
	done := make(chan struct{})
	go func() { rl.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		rl.mu.Lock()
		for c := range rl.conns {
			c.Close()
		}
		rl.mu.Unlock()
		<-done
	}
}

// shutdown stops the port whatever its kind.
func (bp *boundPort) shutdown(ctx context.Context) {
	if bp.udp != nil {
		bp.udp.shutdown(ctx)
		return
	}
	if bp.raw != nil {
		bp.raw.shutdown(ctx)
		return
	}
	if bp.srv.Shutdown(ctx) != nil {
		bp.srv.Close()
	}
}

func (s *Server) startPassthrough(ln net.Listener, port int) *rawListener {
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
				s.passthrough(rl, c, port)
			}()
		}
	}()
	return rl
}

// passthrough routes one connection by SNI and splices it to a backend
// without terminating TLS.
func (s *Server) passthrough(rl *rawListener, c net.Conn, port int) {
	defer c.Close()
	start := time.Now()
	ip, cport := splitRemote(c.RemoteAddr().String())
	lport := 0
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok {
		lport = a.Port
	}
	line := logLine{Method: "TLS", Remote: c.RemoteAddr().String(), ClientIP: ip, ClientPort: cport, ListenerPort: lport, Protocol: protoTLSPT}
	open, unregister := s.conns.register(OpenView{Kind: "passthrough", ClientIP: ip, ClientPort: cport, ListenerPort: lport, Protocol: protoTLSPT})
	defer unregister()
	var local openConn // counters when the open list is disabled
	var status int
	var routeKey, backendKey string
	defer func() {
		s.stats.record(routeKey, backendKey, status)
		line.Status, line.Route, line.Backend = status, routeKey, backendKey
		s.logConn(&line, start)
	}()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	raw, sni, alpn, err := readClientHelloALPN(c)
	line.Host, line.TLSSNI = sni, sni
	open.set(func(v *OpenView) { v.SNI, v.Host = sni, sni })
	if err != nil {
		status, line.Error = http.StatusBadRequest, "reading ClientHello: "+err.Error()
		return
	}
	c.SetReadDeadline(time.Time{})
	t := s.table.Load()
	var pg *PortGroup
	if t != nil {
		pg = t.Ports[port]
	}
	if pg == nil {
		status, line.Error = http.StatusServiceUnavailable, "gateway not ready"
		return
	}
	l := pg.pickListener(sni)
	if l == nil {
		status, line.Error = http.StatusNotFound, "no listener serves this server name"
		return
	}
	line.Listener = l.Key
	var client net.Conn = c
	replay := raw
	if l.Terminate {
		tc, neg, err := s.terminateTLS(c, raw, port, l)
		if err != nil {
			status, line.Error = http.StatusBadRequest, "TLS handshake: "+err.Error()
			return
		}
		defer tc.Close()
		client, replay, alpn = tc, nil, nil
		if neg != "" {
			alpn = []string{neg}
		}
	}
	e := l.selectTLSALPN(sni, alpn)
	if e == nil {
		status, line.Error = http.StatusNotFound, "no TLSRoute matched"
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
	var up net.Conn
	var attempts []attemptRec
	var dialTime time.Duration
	for range ref.B.Eps {
		ep := ref.B.pick()
		t0 := time.Now()
		up, err = (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", ep.URL.Host)
		d := time.Since(t0)
		rec := attemptRec{Addr: ep.URL.Host, ConnectMS: ms(d)}
		if err != nil {
			rec.Error = err.Error()
		}
		attempts = append(attempts, rec)
		if err == nil {
			dialTime = d
			break
		}
	}
	if up != nil && err == nil {
		if err = writeProxyTo(up, ref.B, c); err != nil {
			up.Close()
		}
	}
	if len(attempts) > 1 {
		line.Attempts = attempts
	}
	line.Retries = len(attempts) - 1
	if up == nil || err != nil {
		status, line.Error = http.StatusBadGateway, fmt.Sprint("dialing backend: ", err)
		return
	}
	line.UpstreamAddr, line.UpstreamConnectMS = up.RemoteAddr().String(), ms(dialTime)
	line.UpstreamProto, line.UpstreamTLS, line.UpstreamReused = "tcp", boolp(false), boolp(false)
	open.set(func(v *OpenView) { v.UpstreamAddr = line.UpstreamAddr })
	defer up.Close()
	if !rl.track(up) {
		return
	}
	defer rl.untrack(up)
	if replay != nil {
		if _, err := up.Write(replay); err != nil {
			status, line.Error = http.StatusBadGateway, "writing to backend: "+err.Error()
			return
		}
	}
	in, out := &local.in, &local.out
	if open != nil {
		in, out = &open.in, &open.out
	}
	in.Add(int64(len(raw)))
	status = http.StatusOK
	splice(client, up, &line, in, out)
}

// splice copies both directions until each side finishes, half-closing so
// that a one-way FIN reaches the peer. in and out count bytes as they move,
// so the open connection list stays live.
func splice(a, b net.Conn, line *logLine, in, out *atomic.Int64) {
	var wg sync.WaitGroup
	cp := func(dst, src net.Conn, n *atomic.Int64) {
		defer wg.Done()
		io.Copy(dst, &tally{r: src, n: n})
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go cp(b, a, in)
	go cp(a, b, out)
	wg.Wait()
	line.RequestBytes, line.ResponseBytes = in.Load(), out.Load()
	line.Bytes = line.RequestBytes + line.ResponseBytes
}

// tally counts bytes read from r.
type tally struct {
	r io.Reader
	n *atomic.Int64
}

func (t *tally) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if n > 0 {
		t.n.Add(int64(n))
	}
	return n, err
}

func (s *Server) logConn(line *logLine, start time.Time) {
	a := s.obs.access
	if a == nil && s.conns == nil {
		return
	}
	line.Time = start.UTC().Format(time.RFC3339Nano)
	line.Millis = float64(time.Since(start).Microseconds()) / 1000
	if a != nil {
		a.log(line)
	}
	s.conns.push(line)
}

func newTLSH2Transport(skipVerify bool) *http.Transport {
	return &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 256, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}}
}
