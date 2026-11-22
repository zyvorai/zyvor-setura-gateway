package gateway

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var loopbackNet = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

func parseHeader(t *testing.T, raw []byte) (proxyAddrs, error) {
	t.Helper()
	return readProxyHeader(bufio.NewReader(bytes.NewReader(raw)))
}

func TestProxyProtocolParsing(t *testing.T) {
	v2 := func(cmd, fam byte, body []byte) []byte {
		b := append([]byte(ppV2Sig), cmd, fam, byte(len(body)>>8), byte(len(body)))
		return append(b, body...)
	}
	v4body := []byte{192, 0, 2, 1, 10, 0, 0, 9, 0xc8, 0x1f, 0x01, 0xbb} // 192.0.2.1:51231 -> 10.0.0.9:443
	for _, c := range []struct {
		name    string
		raw     []byte
		src     string
		wantErr string
	}{
		{"v1 tcp4", []byte("PROXY TCP4 192.0.2.1 10.0.0.9 51231 443\r\nGET"), "192.0.2.1:51231", ""},
		{"v1 tcp6", []byte("PROXY TCP6 2001:db8::1 2001:db8::2 4000 443\r\n"), "[2001:db8::1]:4000", ""},
		{"v1 unknown keeps the transport address", []byte("PROXY UNKNOWN\r\n"), "", ""},
		{"v1 family mismatch", []byte("PROXY TCP4 2001:db8::1 10.0.0.9 1 2\r\n"), "", "bad address"},
		{"v1 bad port", []byte("PROXY TCP4 192.0.2.1 10.0.0.9 99999 443\r\n"), "", "bad address"},
		{"v1 no CRLF", []byte("PROXY TCP4 192.0.2.1 10.0.0.9 1 2\n"), "", "CRLF"},
		{"v1 too long", append([]byte("PROXY TCP4 "), bytes.Repeat([]byte("1"), 200)...), "", "107"},
		{"v2 proxy ipv4", v2(0x21, 0x11, v4body), "192.0.2.1:51231", ""},
		{"v2 local", v2(0x20, 0x00, nil), "", ""},
		{"v2 tlv ignored", v2(0x21, 0x11, append(append([]byte{}, v4body...), 0x04, 0x00, 0x01, 0xff)), "192.0.2.1:51231", ""},
		{"v2 short block", v2(0x21, 0x11, v4body[:6]), "", "short"},
		{"v2 bad version", append([]byte(ppV2Sig), 0x11, 0x11, 0, 0), "", "version"},
		{"v2 truncated", append([]byte(ppV2Sig), 0x21, 0x11, 0, 12, 1), "", "EOF"},
		{"no header", []byte("GET / HTTP/1.1\r\n\r\n"), "", "no PROXY header"},
		{"empty", nil, "", "EOF"},
	} {
		h, err := parseHeader(t, c.raw)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: error %v, want %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		got := ""
		if h.src != nil {
			got = h.src.String()
		}
		if got != c.src {
			t.Errorf("%s: source %q, want %q", c.name, got, c.src)
		}
	}
}

func TestProxyProtocolEncodeRoundTrip(t *testing.T) {
	v4s, v4d := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 40000}, &net.TCPAddr{IP: net.ParseIP("10.0.0.9"), Port: 443}
	v6s, v6d := &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40001}, &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 8443}
	for _, ver := range []string{"v1", "v2"} {
		for _, p := range [][2]*net.TCPAddr{{v4s, v4d}, {v6s, v6d}} {
			h, err := parseHeader(t, append(encodeProxyHeader(ver, p[0], p[1]), "payload"...))
			if err != nil || h.src.String() != p[0].String() || h.dst.String() != p[1].String() {
				t.Errorf("%s %s -> %s: got %+v %v", ver, p[0], p[1], h, err)
			}
		}
		// No client (a health check): the form that says "no client here".
		h, err := parseHeader(t, encodeProxyHeader(ver, nil, nil))
		if err != nil || h.src != nil {
			t.Errorf("%s without a client: %+v %v", ver, h, err)
		}
		// Mixed families cannot be expressed: fall back to the no-client form.
		if h, err := parseHeader(t, encodeProxyHeader(ver, v4s, v6d)); err != nil || h.src != nil {
			t.Errorf("%s mixed families: %+v %v", ver, h, err)
		}
	}
	if got := string(encodeProxyHeader("v1", v4s, v4d)); got != "PROXY TCP4 192.0.2.1 10.0.0.9 40000 443\r\n" {
		t.Errorf("v1 wire form %q", got)
	}
}

func TestProxyProtocolFlagParsing(t *testing.T) {
	got, err := parseProxyProtocolFlags([]string{"80=10.0.0.0/8,192.168.1.5", "443=127.0.0.1"})
	if err != nil || len(got[80]) != 2 || len(got[443]) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"80", "80=", "x=10.0.0.0/8", "0=10.0.0.0/8", "80=nonsense", "70000=10.0.0.0/8"} {
		if _, err := parseProxyProtocolFlags([]string{bad}); err == nil {
			t.Errorf("%q must be refused: trusted sources are mandatory", bad)
		}
	}
}

// rawGet sends pre (a PROXY header, maybe empty) and one request on a fresh
// connection and returns the response, its echo and the connection's local address.
func rawGet(t *testing.T, addr string, pre []byte, host string, hdr ...string) (*http.Response, echo, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var sb strings.Builder
	sb.Write(pre)
	fmt.Fprintf(&sb, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n", host)
	for i := 0; i+1 < len(hdr); i += 2 {
		fmt.Fprintf(&sb, "%s: %s\r\n", hdr[i], hdr[i+1])
	}
	sb.WriteString("\r\n")
	if _, err := io.WriteString(c, sb.String()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var e echo
	jsonUnmarshal(string(b), &e)
	return resp, e, c.LocalAddr().String()
}

func ppServer(t *testing.T, mod func(*Options)) (*Server, map[string]*upstream) {
	be, ups := upstreams(t, "a")
	raw := snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("a", 1)))}, be)
	s := startServer(t, raw, func(o *Options) {
		o.Cert.ProxyProtocol = map[int][]netip.Prefix{8080: loopbackNet}
		if mod != nil {
			mod(o)
		}
	})
	return s, ups
}

func TestProxyProtocolInboundSetsClientAddress(t *testing.T) {
	s, _ := ppServer(t, nil)
	v1 := []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 80\r\n")
	if resp, e, _ := rawGet(t, s.Addr(8080), v1, "x.test"); resp.StatusCode != 200 || e.Headers["x-forwarded-for"] != "203.0.113.7" {
		t.Fatalf("v1: status %d, backend saw X-Forwarded-For %q", resp.StatusCode, e.Headers["x-forwarded-for"])
	}
	waitLatest(t, s, 1)
	if rec := lastRecord(t, s); rec.ClientIP != "203.0.113.7" || rec.ClientPort != 51000 || rec.Remote != "203.0.113.7:51000" {
		t.Errorf("connections history records %q:%d (%q), want the PROXY source", rec.ClientIP, rec.ClientPort, rec.Remote)
	}

	v6 := encodeProxyHeader("v2", &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4242}, &net.TCPAddr{IP: net.ParseIP("2001:db8::99"), Port: 80})
	if resp, e, _ := rawGet(t, s.Addr(8080), v6, "x.test"); resp.StatusCode != 200 || e.Headers["x-forwarded-for"] != "2001:db8::1" {
		t.Fatalf("v2 ipv6: status %d XFF %q", resp.StatusCode, e.Headers["x-forwarded-for"])
	}
	waitLatest(t, s, 2)
	if rec := lastRecord(t, s); rec.ClientIP != "2001:db8::1" || rec.ClientPort != 4242 {
		t.Errorf("v2 record %q:%d", rec.ClientIP, rec.ClientPort)
	}

	// LOCAL (a health check of the load balancer): the transport address stays.
	local := []byte(ppV2Sig + "\x20\x00\x00\x00")
	if _, e, laddr := rawGet(t, s.Addr(8080), local, "x.test"); e.Headers["x-forwarded-for"] != strings.Split(laddr, ":")[0] {
		t.Errorf("v2 LOCAL: XFF %q, want the connection's own address %s", e.Headers["x-forwarded-for"], laddr)
	}
}

func TestProxyProtocolTrustBoundaries(t *testing.T) {
	// A trusted source must send the header; one that does not is dropped.
	s, _ := ppServer(t, nil)
	c, err := net.Dial("tcp", s.Addr(8080))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x.test\r\n\r\n")
	if b, _ := io.ReadAll(c); len(b) != 0 {
		t.Errorf("a trusted peer without a PROXY header got a response: %q", b)
	}
	c.Close()

	// A source outside the allowed networks cannot forge a client address: the
	// header is not honoured and the stray bytes are just a bad request.
	s2, _ := ppServer(t, func(o *Options) {
		o.Cert.ProxyProtocol = map[int][]netip.Prefix{8080: {netip.MustParsePrefix("203.0.113.0/24")}}
	})
	resp, _, _ := rawGet(t, s2.Addr(8080), []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 80\r\n"), "x.test")
	if resp.StatusCode != 400 {
		t.Errorf("a PROXY header from an untrusted source got %d, want 400", resp.StatusCode)
	}
	resp, e, laddr := rawGet(t, s2.Addr(8080), nil, "x.test")
	if resp.StatusCode != 200 || e.Headers["x-forwarded-for"] != strings.Split(laddr, ":")[0] {
		t.Errorf("a plain request from an untrusted source: %d XFF %q", resp.StatusCode, e.Headers["x-forwarded-for"])
	}

	// A listener that was not named has no PROXY handling at all.
	s3, _ := ppServer(t, func(o *Options) { o.Cert.ProxyProtocol = nil })
	if resp, _, _ := rawGet(t, s3.Addr(8080), []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 80\r\n"), "x.test"); resp.StatusCode != 400 {
		t.Errorf("without --proxy-protocol the header is garbage, got %d", resp.StatusCode)
	}
}

func TestProxyProtocolWithTrustedProxies(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	s, _ := ppServer(t, func(o *Options) { o.Obs.TrustedProxies = trusted })

	// The PROXY source is itself a trusted proxy: its X-Forwarded-For is believed,
	// appended to rather than replaced.
	pre := []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 80\r\n")
	_, e, _ := rawGet(t, s.Addr(8080), pre, "x.test", "X-Forwarded-For", "198.51.100.9")
	if e.Headers["x-forwarded-for"] != "198.51.100.9, 203.0.113.7" {
		t.Errorf("trusted PROXY source: backend XFF %q", e.Headers["x-forwarded-for"])
	}
	waitLatest(t, s, 1)
	if rec := lastRecord(t, s); rec.ClientIP != "198.51.100.9" {
		t.Errorf("client IP %q, want the X-Forwarded-For client behind the trusted PROXY source", rec.ClientIP)
	}

	// An untrusted PROXY source: a forged X-Forwarded-For is ignored.
	pre = []byte("PROXY TCP4 192.0.2.4 10.0.0.1 51000 80\r\n")
	_, e, _ = rawGet(t, s.Addr(8080), pre, "x.test", "X-Forwarded-For", "198.51.100.9")
	if e.Headers["x-forwarded-for"] != "192.0.2.4" {
		t.Errorf("untrusted PROXY source: backend XFF %q", e.Headers["x-forwarded-for"])
	}
	waitLatest(t, s, 2)
	if rec := lastRecord(t, s); rec.ClientIP != "192.0.2.4" {
		t.Errorf("client IP %q", rec.ClientIP)
	}
}

func TestProxyProtocolInboundTCPRouteAndPassthrough(t *testing.T) {
	// TCPRoute.
	back := tcpBackend(t, "B")
	res := m{gwKeyT + "gw": l4Gateway("TCP", 9000), tcpKeyT + "r": l4Route("", 0, ref("b", 1))}
	s := startServer(t, snapRes(res, map[string]any{"b": back}, nil), func(o *Options) {
		o.PortMap[9000] = 0
		o.Cert.ProxyProtocol = map[int][]netip.Prefix{9000: loopbackNet}
	})
	c, err := net.Dial("tcp", s.Addr(9000))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "PROXY TCP4 203.0.113.7 10.0.0.1 51000 9000\r\nhello")
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if got, err := io.ReadAll(c); err != nil || string(got) != "B:hello" {
		t.Fatalf("TCPRoute with PROXY protocol: %q %v (the header is consumed by the gateway)", got, err)
	}
	c.Close()
	waitFor(t, "the TCP connection record", func() bool { h := history(s); return len(h) > 0 })
	if rec := history(s)[0]; rec.ClientIP != "203.0.113.7" || rec.ClientPort != 51000 {
		t.Errorf("TCP record client %q:%d", rec.ClientIP, rec.ClientPort)
	}

	// TLS passthrough: the handshake that follows the header reaches the backend untouched.
	p := newPKI(t)
	be := newTLSBackend(t, p, "pt", "a.test")
	routes := map[string]m{tlsKeyT + "a": tlsRoute("", []string{"a.test"}, tref("pt", 1))}
	s2 := startServer(t, tlsSnap(passGateway(), routes, map[string]string{"pt": be.addr()}, nil), func(o *Options) {
		o.Cert.ProxyProtocol = map[int][]netip.Prefix{8443: loopbackNet}
	})
	raw, err := net.Dial("tcp", s2.Addr(8443))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(raw, "PROXY TCP4 203.0.113.8 10.0.0.1 52000 8443\r\n")
	tc := tls.Client(raw, &tls.Config{RootCAs: p.pool, ServerName: "a.test"})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("passthrough handshake after a PROXY header: %v", err)
	}
	io.WriteString(tc, "ping\n")
	if line, _ := bufio.NewReader(tc).ReadString('\n'); line != "pt:ping\n" {
		t.Fatalf("reply %q", line)
	}
	tc.Close()
	waitFor(t, "the passthrough record", func() bool { h := history(s2); return len(h) > 0 })
	if rec := history(s2)[0]; rec.ClientIP != "203.0.113.8" || rec.ClientPort != 52000 {
		t.Errorf("passthrough record client %q:%d", rec.ClientIP, rec.ClientPort)
	}
}

// ---- outbound ----

// ppUpstream is an HTTP backend behind a trusted PROXY protocol listener: the
// RemoteAddr its handlers see is the address the header carried.
type ppUpstream struct {
	*httptest.Server
	mu    sync.Mutex
	paths map[string][]string // path -> remote addresses seen
	conns atomic.Int64
}

func newPPUpstream(t *testing.T, h2c bool) *ppUpstream {
	u := &ppUpstream{paths: map[string][]string{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		u.mu.Lock()
		u.paths[r.URL.Path] = append(u.paths[r.URL.Path], r.RemoteAddr)
		u.mu.Unlock()
		fmt.Fprintf(w, `{"name":"pp","host":%q,"path":%q,"headers":{"x-proto":%q}}`, r.RemoteAddr, r.URL.Path, r.Proto)
	}))
	srv.Listener = &ppListener{Listener: srv.Listener, trusted: loopbackNet}
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			u.conns.Add(1)
		}
	}
	if h2c {
		var p http.Protocols
		p.SetHTTP1(true)
		p.SetUnencryptedHTTP2(true)
		srv.Config.Protocols = &p
	}
	srv.Start()
	t.Cleanup(srv.Close)
	u.Server = srv
	return u
}

func (u *ppUpstream) remotes(path string) []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.paths[path]...)
}

func ppBackendServer(t *testing.T, def m, inbound bool) *Server {
	raw := snapRes(m{gwKeyT + "gw": httpGateway(""), rtKeyT + "r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": def}, nil)
	return startServer(t, raw, func(o *Options) {
		if inbound {
			o.Cert.ProxyProtocol = map[int][]netip.Prefix{8080: loopbackNet}
		}
	})
}

func TestProxyProtocolOutboundHTTP(t *testing.T) {
	for _, ver := range []string{"v1", "v2"} {
		t.Run(ver, func(t *testing.T) {
			u := newPPUpstream(t, false)
			def := m{"endpoints": l{u.Listener.Addr().String()}, "proxyProtocol": ver}
			s, sIn := ppBackendServer(t, def, false), ppBackendServer(t, def, true)

			// A direct client: the backend learns the client's own address.
			_, e, laddr := rawGet(t, s.Addr(8080), nil, "x.test")
			if e.Host != laddr {
				t.Errorf("backend saw the client as %q, want %s", e.Host, laddr)
			}
			// Behind an inbound PROXY header the backend sees that source, end to end.
			var pre []byte
			if ver == "v1" {
				pre = []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 80\r\n")
			} else {
				pre = encodeProxyHeader("v2", &net.TCPAddr{IP: net.ParseIP("2001:db8::7"), Port: 51001}, &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 80})
			}
			_, e, _ = rawGet(t, sIn.Addr(8080), pre, "x.test")
			want := "203.0.113.7:51000"
			if ver == "v2" {
				want = "[2001:db8::7]:51001"
			}
			if e.Host != want {
				t.Errorf("backend saw %q, want the inbound PROXY source %s", e.Host, want)
			}

			// One connection per request: a header names a single client, so keep-alive is off.
			before := u.conns.Load()
			cl := client(s.Addr(8080), nil)
			cl.Transport.(*http.Transport).DisableKeepAlives = false
			for i := 0; i < 3; i++ {
				req(t, cl, "http", "GET", "x.test", "/", "")
			}
			if got := u.conns.Load() - before; got != 3 {
				t.Errorf("3 requests used %d upstream connections, want 3", got)
			}
		})
	}
}

func TestProxyProtocolOutboundHealthCheckAndH2C(t *testing.T) {
	u := newPPUpstream(t, true)
	s := ppBackendServer(t, m{"endpoints": l{u.Listener.Addr().String()}, "proxyProtocol": "v2", "protocol": "h2c",
		"healthCheck": m{"path": "/health", "interval": "20ms", "timeout": "1s"}}, false)
	// The health check connects with the "no client" header and passes.
	waitFor(t, "the health check to reach the PROXY protocol backend", func() bool { return len(u.remotes("/health")) > 0 })
	_, e, _ := rawGet(t, s.Addr(8080), nil, "x.test")
	if e.Headers["x-proto"] != "HTTP/2.0" {
		t.Errorf("upstream protocol %q, want HTTP/2.0 (h2c with PROXY protocol)", e.Headers["x-proto"])
	}
	if e.Name != "pp" {
		t.Errorf("not served by the backend: %+v", e)
	}
	b := s.Table().Backends["t/a:80"]
	if b == nil || !b.Eps[0].healthy.Load() {
		t.Error("the PROXY protocol backend is not healthy")
	}
}

func TestProxyProtocolOutboundTCPAndPassthrough(t *testing.T) {
	// TCP backend: reads the header, then behaves like tcpBackend.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				h, err := readProxyHeader(br)
				if err != nil || h.src == nil {
					io.WriteString(c, "noheader")
					return
				}
				io.WriteString(c, "src="+h.src.String()+":")
				io.Copy(c, br)
			}()
		}
	}()
	res := m{gwKeyT + "gw": l4Gateway("TCP", 9000), tcpKeyT + "r": l4Route("", 0, ref("b", 1))}
	s := startServer(t, snapRes(res, map[string]any{"b": m{"endpoints": l{ln.Addr().String()}, "proxyProtocol": "v1"}}, nil), func(o *Options) { o.PortMap[9000] = 0 })
	c, err := net.Dial("tcp", s.Addr(9000))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "hello")
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, _ := io.ReadAll(c)
	if want := "src=" + c.LocalAddr().String() + ":hello"; string(got) != want {
		t.Errorf("TCPRoute upstream saw %q, want %q", got, want)
	}
	c.Close()

	// Passthrough: the backend terminates TLS after reading the header.
	p := newPKI(t)
	cert, key := p.issue("a.test")
	pair, _ := tls.X509KeyPair(cert, key)
	rawLn, _ := net.Listen("tcp", "127.0.0.1:0")
	t.Cleanup(func() { rawLn.Close() })
	pl := &ppListener{Listener: rawLn, trusted: loopbackNet}
	srcs := make(chan string, 4)
	go func() {
		for {
			c, err := pl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				srcs <- c.RemoteAddr().String()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{pair}})
				if tc.Handshake() != nil {
					return
				}
				line, _ := bufio.NewReader(tc).ReadString('\n')
				io.WriteString(tc, "pt:"+line)
			}()
		}
	}()
	doc := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": passGateway(), tlsKeyT + "a": tlsRoute("", []string{"a.test"}, tref("pt", 1))},
		"backends":  m{"t/pt:443": m{"endpoints": l{rawLn.Addr().String()}, "proxyProtocol": "v2"}}})
	s2 := startServer(t, doc, nil)
	tc, err := dialTLS(s2.Addr(8443), p, "a.test")
	if err != nil {
		t.Fatalf("handshake through passthrough with an upstream PROXY header: %v", err)
	}
	defer tc.Close()
	io.WriteString(tc, "ping\n")
	if line, _ := bufio.NewReader(tc).ReadString('\n'); line != "pt:ping\n" {
		t.Errorf("reply %q", line)
	}
	if src := <-srcs; src != tc.LocalAddr().String() {
		t.Errorf("backend saw the client as %s, want %s", src, tc.LocalAddr())
	}
}

func TestBackendProtocolOptionsAreValidated(t *testing.T) {
	be, _ := upstreams(t, "a")
	for _, c := range []struct {
		name string
		def  m
		want string
	}{
		{"bad proxy version", m{"endpoints": l{be["a"]}, "proxyProtocol": "v3"}, "proxyProtocol"},
		{"bad protocol", m{"endpoints": l{be["a"]}, "protocol": "spdy"}, "protocol"},
		{"h2c over https", m{"endpoints": l{"https://127.0.0.1:1"}, "protocol": "h2c"}, "plain http"},
	} {
		s := startServer(t, snapRes(m{gwKeyT + "gw": httpGateway(""), rtKeyT + "r": route("", rule("/", ref("a", 1)))}, map[string]any{"a": c.def}, nil), nil)
		got := cond(s.Status().Routes["t/r"].Parents[0].Conditions, "ResolvedRefs")
		if got.Status != "False" || !strings.Contains(got.Message, c.want) {
			t.Errorf("%s: ResolvedRefs %+v, want a message naming %q", c.name, got, c.want)
		}
	}
}

func TestH2CBackendForPlainHTTPRoute(t *testing.T) {
	var protos atomic.Value
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		protos.Store(r.Proto)
		fmt.Fprintf(w, `{"name":"h2c","headers":{"x-proto":%q}}`, r.Proto)
	}))
	srv.Config.Protocols = &p
	srv.Start()
	t.Cleanup(srv.Close)
	addr := strings.TrimPrefix(srv.URL, "http://")

	for _, c := range []struct{ name, proto, want string }{{"option", "h2c", "HTTP/2.0"}, {"default", "", "HTTP/1.1"}} {
		def := m{"endpoints": l{addr}}
		if c.proto != "" {
			def["protocol"] = c.proto
		}
		s := ppBackendServer(t, def, false)
		if _, e, _ := rawGet(t, s.Addr(8080), nil, "x.test"); e.Headers["x-proto"] != c.want {
			t.Errorf("%s: upstream spoke %q, want %q", c.name, e.Headers["x-proto"], c.want)
		}
		if c.proto == "h2c" {
			s.FlushAccessLog()
			if rec := lastRecord(t, s); rec.UpstreamProto != "h2c" && rec.UpstreamProto != "h2" && rec.UpstreamProto != "http/2" {
				t.Logf("connection record upstream protocol %q", rec.UpstreamProto)
			}
		}
	}
}

func TestKubeBackendProtocolMapping(t *testing.T) {
	var def BackendDef
	app := "kubernetes.io/h2c"
	kubeBackendProtocol(&def, &app, nil)
	if def.Protocol != "h2c" {
		t.Errorf("appProtocol kubernetes.io/h2c -> %q", def.Protocol)
	}
	other := "http"
	def = BackendDef{}
	kubeBackendProtocol(&def, &other, map[string]string{annotPROXY: "v2"})
	if def.Protocol != "" || def.ProxyProtocol != "v2" {
		t.Errorf("%+v", def)
	}
}

func TestCertFlagsRejectedByMain(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--proxy-protocol", "80"}, "--proxy-protocol"},
		{[]string{"--acme-production"}, "--acme-dir"},
		{[]string{"--acme-dir", t.TempDir(), "--acme-production", "--acme-directory", "https://x.test/d"}, "mutually exclusive"},
		{[]string{"--alt-svc", "h3=\":443\"\r\n"}, "--alt-svc"},
	} {
		var out, errb strings.Builder
		args := append([]string{"run", "--config", filepath.Join(t.TempDir(), "none.json"), "--admin", "off"}, c.args...)
		if code := Main(args, &out, &errb, nil); code != 2 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%v: exit %d, stderr %q, want exit 2 naming %q", c.args, code, errb.String(), c.want)
		}
	}
}
