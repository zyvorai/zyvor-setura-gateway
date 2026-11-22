package gateway

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// tcpEcho is a plain TCP backend answering each line with "<name>:<line>".
type tcpEcho struct {
	net.Listener
	mu    sync.Mutex
	conns int
}

func newTCPEcho(t *testing.T, name string) *tcpEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e := &tcpEcho{Listener: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			e.mu.Lock()
			e.conns++
			e.mu.Unlock()
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					io.WriteString(c, name+":"+line)
				}
			}()
		}
	}()
	return e
}

func (e *tcpEcho) addr() string { return e.Addr().String() }

func termGateway(port int, alsoPass bool) m {
	ls := l{m{"name": "term", "protocol": "TLS", "port": port, "tls": m{"mode": "Terminate", "certificateRefs": l{m{"name": "c"}}}}}
	if alsoPass {
		ls = append(ls, m{"name": "pass", "protocol": "TLS", "port": port, "hostname": "pass.test", "tls": m{"mode": "Passthrough"}})
	}
	return m{"gatewayClassName": "setura", "listeners": ls}
}

func alpnRoute(hosts []string, rules ...m) m {
	r := m{"parentRefs": l{m{"name": "gw"}}, "rules": toList(rules)}
	if hosts != nil {
		hs := l{}
		for _, h := range hosts {
			hs = append(hs, h)
		}
		r["hostnames"] = hs
	}
	return r
}

func alpnRule(backend m, alpn ...string) m {
	r := m{"backendRefs": l{backend}}
	if len(alpn) > 0 {
		a := l{}
		for _, p := range alpn {
			a = append(a, p)
		}
		r["setura.zyvor.dev/alpn"] = a
	}
	return r
}

func dialTLSALPN(addr string, p *pki, sni string, protos ...string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	return tls.DialWithDialer(d, "tcp", addr, &tls.Config{RootCAs: p.pool, ServerName: sni, NextProtos: protos})
}

func askConn(t *testing.T, c *tls.Conn, line string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, line+"\n")
	got, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return strings.TrimSpace(got)
}

func TestTLSTerminateForwardsPlainTCP(t *testing.T) {
	p := newPKI(t)
	be := newTCPEcho(t, "plain")
	routes := map[string]m{tlsKeyT + "r": tlsRoute("term", []string{"term.test"}, tref("plain", 1))}
	extra := m{"secrets": m{"c": p.files("c", "term.test")}}
	logs := &syncBuf{}
	s := startServer(t, tlsSnap(termGateway(8444, false), routes, map[string]string{"plain": be.addr()}, extra),
		func(o *Options) { o.PortMap = map[int]int{8444: 0}; o.AccessLog = logs })

	// The client verifies the gateway's certificate, not the backend's (which has none).
	c, err := dialTLSALPN(s.Addr(8444), p, "term.test")
	if err != nil {
		t.Fatalf("handshake with the gateway: %v", err)
	}
	if got := askConn(t, c, "ping"); got != "plain:ping" {
		t.Errorf("got %q", got)
	}
	c.Close()
	// A wrong server name is refused: the certificate selection is the HTTPS one, so
	// the client sees the only certificate and rejects its name.
	if c, err := dialTLSALPN(s.Addr(8444), p, "other.test"); err == nil {
		c.Close()
		t.Error("a certificate for term.test was accepted for other.test")
	}
	if !strings.Contains(strings.Join(s.Listening(), "\n"), "tls-terminate") {
		t.Errorf("Listening: %v", s.Listening())
	}
	st := s.Status().Gateways["t/gw"].Listeners[0]
	if c := cond(st.Conditions, "Accepted"); c.Status != "True" {
		t.Errorf("listener Accepted = %+v", c)
	}
	if c := cond(st.Conditions, "ResolvedRefs"); c.Status != "True" {
		t.Errorf("listener ResolvedRefs = %+v", c)
	}
	s.Close()
	if out := logs.String(); !strings.Contains(out, `"route":"TLSRoute/t/r"`) || !strings.Contains(out, `"backend":"t/plain:443"`) {
		t.Errorf("access log:\n%s", out)
	}
}

func TestTLSTerminateALPNRouting(t *testing.T) {
	p := newPKI(t)
	h2, h1, any := newTCPEcho(t, "h2"), newTCPEcho(t, "h1"), newTCPEcho(t, "any")
	routes := map[string]m{tlsKeyT + "r": alpnRoute(nil,
		alpnRule(tref("h2", 1), "h2"), alpnRule(tref("h1", 1), "http/1.1"), alpnRule(tref("any", 1)))}
	be := map[string]string{"h2": h2.addr(), "h1": h1.addr(), "any": any.addr()}
	extra := m{"secrets": m{"c": p.files("c", "term.test")}}
	s := startServer(t, tlsSnap(termGateway(8444, false), routes, be, extra), func(o *Options) { o.PortMap = map[int]int{8444: 0} })

	for _, c := range []struct {
		protos []string
		want   string
		neg    string
	}{{[]string{"h2"}, "h2", "h2"}, {[]string{"http/1.1"}, "h1", "http/1.1"}, {[]string{"http/1.1", "h2"}, "h2", "h2"}, {nil, "any", ""}} {
		conn, err := dialTLSALPN(s.Addr(8444), p, "term.test", c.protos...)
		if err != nil {
			t.Fatalf("offer %v: %v", c.protos, err)
		}
		if got := conn.ConnectionState().NegotiatedProtocol; got != c.neg {
			t.Errorf("offer %v negotiated %q, want %q", c.protos, got, c.neg)
		}
		if got := askConn(t, conn, "x"); got != c.want+":x" {
			t.Errorf("offer %v routed to %q, want %s", c.protos, got, c.want)
		}
		conn.Close()
	}
	// A client that offers only protocols nobody serves is refused by the handshake.
	if c, err := dialTLSALPN(s.Addr(8444), p, "term.test", "spdy/3"); err == nil {
		c.Close()
		t.Error("handshake succeeded without a common ALPN protocol")
	}
}

func TestTLSTerminateAndPassthroughShareAPort(t *testing.T) {
	p := newPKI(t)
	plain := newTCPEcho(t, "plain")
	tlsBe := newTLSBackend(t, p, "own", "pass.test")
	routes := map[string]m{
		tlsKeyT + "t": tlsRoute("term", []string{"term.test"}, tref("plain", 1)),
		tlsKeyT + "p": tlsRoute("pass", []string{"pass.test"}, tref("own", 1)),
	}
	be := map[string]string{"plain": plain.addr(), "own": tlsBe.addr()}
	extra := m{"secrets": m{"c": p.files("c", "term.test")}}
	s := startServer(t, tlsSnap(termGateway(8444, true), routes, be, extra), func(o *Options) { o.PortMap = map[int]int{8444: 0} })

	c, err := dialTLSALPN(s.Addr(8444), p, "term.test")
	if err != nil {
		t.Fatal(err)
	}
	if got := askConn(t, c, "a"); got != "plain:a" {
		t.Errorf("terminated: %q", got)
	}
	c.Close()
	if got := askTLS(t, s.Addr(8444), p, "pass.test"); got != "own:ping" {
		t.Errorf("passthrough on the same port: %q", got)
	}
	if tlsBe.count() != 1 || tlsBe.snis[0] != "pass.test" {
		t.Errorf("passthrough backend saw %v", tlsBe.snis)
	}
}

func TestTLSPassthroughALPNRouting(t *testing.T) {
	p := newPKI(t)
	h2, h1, any := newTLSBackend(t, p, "h2", "a.test"), newTLSBackend(t, p, "h1", "a.test"), newTLSBackend(t, p, "any", "a.test")
	routes := map[string]m{tlsKeyT + "r": alpnRoute([]string{"a.test"},
		alpnRule(tref("h2", 1), "h2"), alpnRule(tref("h1", 1), "http/1.1"))}
	be := map[string]string{"h2": h2.addr(), "h1": h1.addr(), "any": any.addr()}
	s := startServer(t, tlsSnap(passGateway(), routes, be, nil), nil)
	for _, c := range []struct {
		protos []string
		want   string
	}{{[]string{"h2"}, "h2"}, {[]string{"http/1.1"}, "h1"}, {[]string{"h3", "h2"}, "h2"}} {
		conn, err := dialTLSALPN(s.Addr(8443), p, "a.test", c.protos...)
		if err != nil {
			t.Fatalf("offer %v: %v", c.protos, err)
		}
		if got := askConn(t, conn, "x"); got != c.want+":x" {
			t.Errorf("offer %v routed to %q, want %s", c.protos, got, c.want)
		}
		conn.Close()
	}
	// Nothing matches a client with no ALPN or unknown protocols, as every rule demands one.
	for _, protos := range [][]string{nil, {"spdy/3"}} {
		if conn, err := dialTLSALPN(s.Addr(8443), p, "a.test", protos...); err == nil {
			conn.Close()
			t.Errorf("offer %v was routed although no rule matches its ALPN", protos)
		}
	}
	if any.count() != 0 {
		t.Error("unrouted backend got a connection")
	}
	// Equal hostname, one rule with ALPN and one without: the ALPN rule wins for h2, the other takes the rest.
	routes = map[string]m{tlsKeyT + "r": alpnRoute([]string{"a.test"}, alpnRule(tref("any", 1)), alpnRule(tref("h2", 1), "h2"))}
	s2 := startServer(t, tlsSnap(passGateway(), routes, be, nil), nil)
	for _, c := range []struct {
		protos []string
		want   string
	}{{[]string{"h2"}, "h2"}, {[]string{"http/1.1"}, "any"}, {nil, "any"}} {
		conn, err := dialTLSALPN(s2.Addr(8443), p, "a.test", c.protos...)
		if err != nil {
			t.Fatal(err)
		}
		if got := askConn(t, conn, "x"); got != c.want+":x" {
			t.Errorf("preference: offer %v routed to %q, want %s", c.protos, got, c.want)
		}
		conn.Close()
	}
}

func TestParseClientHelloALPN(t *testing.T) {
	for _, protos := range [][]string{nil, {"h2"}, {"h2", "http/1.1", "acme-tls/1"}} {
		c, srv := net.Pipe()
		go func() {
			tls.Client(c, &tls.Config{ServerName: "Example.Test", NextProtos: protos, InsecureSkipVerify: true}).Handshake()
			c.Close()
		}()
		srv.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, sni, alpn, err := readClientHelloALPN(srv)
		srv.Close()
		if err != nil || sni != "example.test" || strings.Join(alpn, ",") != strings.Join(protos, ",") {
			t.Errorf("offer %v: sni %q alpn %v err %v", protos, sni, alpn, err)
		}
	}
}

func TestSelectTLSALPNPreferences(t *testing.T) {
	mk := func(alpn ...string) *TLSEntry { return &TLSEntry{Hosts: []string{"a.test"}, ALPN: alpn} }
	any, h2, wild := mk(), mk("h2"), &TLSEntry{Hosts: []string{"*.test"}, ALPN: []string{"h2"}}
	l := &RTListener{TLSEntries: []*TLSEntry{any, h2, wild}}
	if got := l.selectTLSALPN("a.test", []string{"h2"}); got != h2 {
		t.Error("ALPN match must beat no ALPN at equal hostname rank")
	}
	if got := l.selectTLSALPN("a.test", []string{"http/1.1"}); got != any {
		t.Error("a rule whose ALPN does not match is skipped")
	}
	if got := l.selectTLSALPN("b.test", []string{"h2"}); got != wild {
		t.Error("wildcard hostname")
	}
	if got := l.selectTLSALPN("b.test", nil); got != nil {
		t.Error("nothing should match")
	}
	// A more specific hostname beats an ALPN match on a wildcard.
	exactAny := mk()
	l2 := &RTListener{TLSEntries: []*TLSEntry{wild, exactAny}}
	if got := l2.selectTLSALPN("a.test", []string{"h2"}); got != exactAny {
		t.Error("hostname specificity comes before ALPN")
	}
}
