package gateway

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const tlsKeyT = "tlsroutes.gateway.networking.k8s.io/"

// tlsBackend terminates TLS itself with a certificate for hosts, then answers
// each line with "<name>:<line>". It records the SNI it saw.
type tlsBackend struct {
	net.Listener
	name string
	mu   sync.Mutex
	snis []string
}

func newTLSBackend(t *testing.T, p *pki, name string, hosts ...string) *tlsBackend {
	t.Helper()
	cert, key := p.issue(hosts...)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &tlsBackend{Listener: ln, name: name}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{pair}})
				if tc.Handshake() != nil {
					return
				}
				b.mu.Lock()
				b.snis = append(b.snis, tc.ConnectionState().ServerName)
				b.mu.Unlock()
				r := bufio.NewReader(tc)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					io.WriteString(tc, name+":"+line)
				}
			}()
		}
	}()
	return b
}

func (b *tlsBackend) addr() string { return b.Addr().String() }

func (b *tlsBackend) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.snis)
}

func passGateway(extra ...m) m {
	ls := l{m{"name": "pass", "protocol": "TLS", "port": 8443, "tls": m{"mode": "Passthrough"}}}
	for _, x := range extra {
		ls = append(ls, x)
	}
	return m{"gatewayClassName": "setura", "listeners": ls}
}

func tlsRoute(section string, hosts []string, backends ...m) m {
	r := m{"parentRefs": l{m{"name": "gw"}}, "rules": l{m{"backendRefs": toList(backends)}}}
	if section != "" {
		r["parentRefs"] = l{m{"name": "gw", "sectionName": section}}
	}
	if hosts != nil {
		hs := l{}
		for _, h := range hosts {
			hs = append(hs, h)
		}
		r["hostnames"] = hs
	}
	return r
}

// dialTLS connects through the gateway, verifying the backend's own certificate.
func dialTLS(addr string, p *pki, sni string) (*tls.Conn, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	return tls.DialWithDialer(d, "tcp", addr, &tls.Config{RootCAs: p.pool, ServerName: sni})
}

func askTLS(t *testing.T, addr string, p *pki, sni string) string {
	t.Helper()
	c, err := dialTLS(addr, p, sni)
	if err != nil {
		t.Fatalf("%s: handshake: %v", sni, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	io.WriteString(c, "ping\n")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("%s: read: %v", sni, err)
	}
	return strings.TrimSpace(line)
}

func tlsSnap(gw m, routes map[string]m, backends map[string]string, extra m) []byte {
	res := m{gwKeyT + "gw": gw}
	for k, v := range routes {
		res[k] = v
	}
	be := m{}
	for k, v := range backends {
		be["t/"+k+":443"] = v
	}
	doc := m{"schema": SnapshotSchema, "namespace": "t", "resources": res, "backends": be}
	for k, v := range extra {
		doc[k] = v
	}
	return mustJSON(doc)
}

func tref(name string, w int) m {
	b := m{"name": name, "port": 443}
	if w >= 0 {
		b["weight"] = w
	}
	return b
}

func TestTLSPassthroughSNIRouting(t *testing.T) {
	p := newPKI(t)
	exact := newTLSBackend(t, p, "exact", "a.test")
	wild := newTLSBackend(t, p, "wild", "x.wild.test", "y.wild.test")
	spec := newTLSBackend(t, p, "spec", "x.wild.test")
	all := newTLSBackend(t, p, "all", "other.test")
	routes := map[string]m{
		tlsKeyT + "exact": tlsRoute("", []string{"a.test"}, tref("exact", 1)),
		tlsKeyT + "wild":  tlsRoute("", []string{"*.wild.test"}, tref("wild", 1)),
		tlsKeyT + "spec":  tlsRoute("", []string{"x.wild.test"}, tref("spec", 1)),
	}
	be := map[string]string{"exact": exact.addr(), "wild": wild.addr(), "spec": spec.addr(), "all": all.addr()}
	logs := &syncBuf{}
	s := startServer(t, tlsSnap(passGateway(), routes, be, nil), func(o *Options) { o.AccessLog = logs })
	addr := s.Addr(8443)

	for _, c := range []struct{ sni, want string }{{"a.test", "exact"}, {"y.wild.test", "wild"}, {"x.wild.test", "spec"}, {"A.TEST", "exact"}} {
		sni := strings.ToLower(c.sni)
		if got := askTLS(t, addr, p, sni); got != c.want+":ping" {
			t.Errorf("%s: got %q want %s", c.sni, got, c.want)
		}
	}
	// The backend, not the gateway, did the handshake: it saw the real SNI.
	if exact.snis[0] != "a.test" {
		t.Errorf("backend SNI = %v", exact.snis)
	}
	// Unknown names and bare wildcard apex get no route: the connection is dropped.
	for _, sni := range []string{"nobody.test", "wild.test"} {
		if c, err := dialTLS(addr, p, sni); err == nil {
			c.Close()
			t.Errorf("%s: handshake unexpectedly succeeded", sni)
		}
	}
	// Plain text on a TLS port is dropped without a reply.
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(raw, "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n")
	raw.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, _ := raw.Read(make([]byte, 16)); n != 0 {
		t.Errorf("got %d bytes back for plain text", n)
	}
	raw.Close()
	if all.count() != 0 {
		t.Error("unrouted backend got a connection")
	}
	s.Close()
	out := logs.String()
	for _, want := range []string{`"method":"TLS"`, `"host":"a.test"`, `"route":"TLSRoute/t/exact"`, `"backend":"t/exact:443"`} {
		if !strings.Contains(out, want) {
			t.Errorf("access log lacks %s:\n%s", want, out)
		}
	}
	snap := s.Stats().Snapshot()
	if snap["requests"].(int64) < 6 {
		t.Errorf("stats %v", snap)
	}
}

func TestTLSPassthroughWeighted(t *testing.T) {
	p := newPKI(t)
	a := newTLSBackend(t, p, "a", "m.test")
	b := newTLSBackend(t, p, "b", "m.test")
	z := newTLSBackend(t, p, "z", "m.test")
	routes := map[string]m{tlsKeyT + "m": tlsRoute("", []string{"m.test"}, tref("a", 3), tref("b", 1), tref("z", 0))}
	s := startServer(t, tlsSnap(passGateway(), routes, map[string]string{"a": a.addr(), "b": b.addr(), "z": z.addr()}, nil), nil)
	for i := 0; i < 100; i++ {
		askTLS(t, s.Addr(8443), p, "m.test")
	}
	if a.count()+b.count() != 100 || z.count() != 0 || a.count() < 55 || b.count() < 5 {
		t.Errorf("a=%d b=%d z=%d", a.count(), b.count(), z.count())
	}
}

func TestTLSPassthroughListenerHostnames(t *testing.T) {
	p := newPKI(t)
	one := newTLSBackend(t, p, "one", "a.one.test")
	two := newTLSBackend(t, p, "two", "b.two.test")
	gw := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "one", "protocol": "TLS", "port": 8443, "hostname": "*.one.test", "tls": m{"mode": "Passthrough"}},
		m{"name": "two", "protocol": "TLS", "port": 8443, "hostname": "*.two.test", "tls": m{"mode": "Passthrough"}}}}
	routes := map[string]m{
		tlsKeyT + "one": tlsRoute("one", nil, tref("one", 1)), // no hostnames: the listener's apply
		tlsKeyT + "two": tlsRoute("two", []string{"b.two.test"}, tref("two", 1)),
	}
	s := startServer(t, tlsSnap(gw, routes, map[string]string{"one": one.addr(), "two": two.addr()}, nil), nil)
	if got := askTLS(t, s.Addr(8443), p, "a.one.test"); got != "one:ping" {
		t.Errorf("one: %q", got)
	}
	if got := askTLS(t, s.Addr(8443), p, "b.two.test"); got != "two:ping" {
		t.Errorf("two: %q", got)
	}
	if c, err := dialTLS(s.Addr(8443), p, "c.two.test"); err == nil {
		c.Close()
		t.Error("c.two.test has no TLSRoute")
	}
}

func TestTLSPassthroughBackendDown(t *testing.T) {
	p := newPKI(t)
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	routes := map[string]m{tlsKeyT + "d": tlsRoute("", []string{"d.test"}, tref("d", 1)), tlsKeyT + "g": tlsRoute("", []string{"g.test"}, tref("ghost", 1))}
	s := startServer(t, tlsSnap(passGateway(), routes, map[string]string{"d": addr}, nil), nil)
	for _, sni := range []string{"d.test", "g.test"} {
		if c, err := dialTLS(s.Addr(8443), p, sni); err == nil {
			c.Close()
			t.Errorf("%s: should fail", sni)
		}
	}
	bs := s.Stats().Snapshot()["backends"].(map[string]Counter)
	if bs["t/d:443"].Status["5xx"] != 1 {
		t.Errorf("backend stats %v", bs)
	}
}

func TestTLSRouteStatusAndKinds(t *testing.T) {
	p := newPKI(t)
	a := newTLSBackend(t, p, "a", "a.test")
	gw := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "pass", "protocol": "TLS", "port": 8443, "hostname": "*.test", "tls": m{"mode": "Passthrough"}},
		m{"name": "term", "protocol": "TLS", "port": 8444, "tls": m{"mode": "Terminate", "certificateRefs": l{m{"name": "c"}}}},
		m{"name": "notls", "protocol": "TLS", "port": 8445},
		m{"name": "http", "protocol": "HTTP", "port": 8080},
		m{"name": "httponly", "protocol": "TLS", "port": 8446, "tls": m{"mode": "Passthrough"}, "allowedRoutes": m{"kinds": l{m{"kind": "HTTPRoute"}}}},
	}}
	hr := route("", rule("/", ref("a", 1)))
	hr["parentRefs"] = l{m{"name": "gw", "sectionName": "pass"}}
	routes := map[string]m{
		tlsKeyT + "good":     tlsRoute("pass", []string{"a.test"}, tref("a", 1)),
		tlsKeyT + "nohost":   tlsRoute("pass", []string{"a.other"}, tref("a", 1)),
		tlsKeyT + "onhttp":   tlsRoute("http", nil, tref("a", 1)),
		tlsKeyT + "onterm":   tlsRoute("term", nil, tref("a", 1)),
		tlsKeyT + "kinds":    tlsRoute("httponly", nil, tref("a", 1)),
		tlsKeyT + "missing":  tlsRoute("pass", []string{"b.test"}, tref("ghost", 1)),
		rtKeyT + "httponpas": hr,
	}
	raw := tlsSnap(gw, routes, map[string]string{"a": a.addr()}, nil)
	s := startServerPorts(t, raw, map[int]int{8080: 0, 8443: 0, 8444: 0, 8445: 0, 8446: 0})
	st := s.Status()
	for name, want := range map[string][2]string{
		"good": {"True/Accepted", "True/ResolvedRefs"}, "nohost": {"False/NoMatchingListenerHostname", "True/ResolvedRefs"},
		"onhttp": {"False/NotAllowedByListeners", "True/ResolvedRefs"}, "onterm": {"False/NotAllowedByListeners", "True/ResolvedRefs"},
		"kinds": {"False/NotAllowedByListeners", "True/ResolvedRefs"}, "missing": {"True/Accepted", "False/BackendNotFound"},
	} {
		rs := st.Routes["TLSRoute/t/"+name]
		if rs == nil || len(rs.Parents) != 1 {
			t.Errorf("%s: no status", name)
			continue
		}
		cs := rs.Parents[0].Conditions
		got := [2]string{cond(cs, "Accepted").Status + "/" + cond(cs, "Accepted").Reason, cond(cs, "ResolvedRefs").Status + "/" + cond(cs, "ResolvedRefs").Reason}
		if got != want {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	if c := cond(st.Routes["t/httponpas"].Parents[0].Conditions, "Accepted"); c.Status != "False" || c.Reason != "NotAllowedByListeners" {
		t.Errorf("HTTPRoute on a TLS listener: %+v", c)
	}
	byName := map[string]ListenerStatus{}
	for _, ls := range st.Gateways["t/gw"].Listeners {
		byName[ls.Name] = ls
	}
	if k := byName["pass"].SupportedKinds; len(k) != 1 || k[0].Kind != "TLSRoute" || byName["pass"].AttachedRoutes != 2 {
		t.Errorf("pass listener: %+v", byName["pass"])
	}
	for _, n := range []string{"term", "notls"} {
		if c := cond(byName[n].Conditions, "Accepted"); c.Status != "False" || c.Reason != "UnsupportedProtocol" {
			t.Errorf("%s listener Accepted = %+v", n, c)
		}
	}
	if k := byName["http"].SupportedKinds; len(k) != 2 {
		t.Errorf("http listener kinds %+v", k)
	}
	if s.Addr(8444) != "" || s.Addr(8445) != "" {
		t.Error("rejected TLS listeners must not bind")
	}
	if !strings.Contains(strings.Join(s.Listening(), "\n"), "tls-passthrough") {
		t.Errorf("Listening: %v", s.Listening())
	}
	if got := askTLS(t, s.Addr(8443), p, "a.test"); got != "a:ping" {
		t.Errorf("good route: %q", got)
	}
}

func TestTLSPassthroughShutdownClosesConnections(t *testing.T) {
	p := newPKI(t)
	a := newTLSBackend(t, p, "a", "a.test")
	routes := map[string]m{tlsKeyT + "a": tlsRoute("", []string{"a.test"}, tref("a", 1))}
	s := startServer(t, tlsSnap(passGateway(), routes, map[string]string{"a": a.addr()}, nil), nil)
	c, err := dialTLS(s.Addr(8443), p, "a.test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s.mu.Lock()
	bp := s.ports[8443]
	s.mu.Unlock()
	done := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		bp.shutdown(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown hung on an idle connection")
	}
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after shutdown")
	}
}

func TestClientHelloParsing(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	go func() {
		tls.Client(c1, &tls.Config{ServerName: "Parse.Example.test.", InsecureSkipVerify: true}).Handshake()
	}()
	raw, sni, err := readClientHello(c2)
	c1.Close()
	if err != nil || sni != "parse.example.test" {
		t.Fatalf("sni %q err %v", sni, err)
	}
	// Re-frame the same handshake as two records; the SNI must survive.
	hs := raw[5:]
	var split []byte
	for _, part := range [][]byte{hs[:20], hs[20:]} {
		split = append(split, 22, 3, 1, byte(len(part)>>8), byte(len(part)))
		split = append(split, part...)
	}
	r := bytes.NewReader(append(split, []byte("trailing application bytes")...))
	got, sni, err := readClientHello(r)
	if err != nil || sni != "parse.example.test" || !bytes.Equal(got, split) {
		t.Fatalf("split hello: sni %q err %v consumed %d of %d", sni, err, len(got), len(split))
	}
	if r.Len() != len("trailing application bytes") {
		t.Errorf("read past the ClientHello: %d bytes left", r.Len())
	}
	for name, in := range map[string][]byte{"not tls": []byte("GET / HTTP/1.1\r\n"), "short": raw[:10], "truncated body": append(append([]byte{}, raw[:5]...), raw[5:30]...)} {
		if _, _, err := readClientHello(bytes.NewReader(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	// A hello without SNI yields an empty name.
	c3, c4 := net.Pipe()
	defer c4.Close()
	go func() { tls.Client(c3, &tls.Config{InsecureSkipVerify: true}).Handshake() }()
	_, sni, err = readClientHello(c4)
	c3.Close()
	if err != nil || sni != "" {
		t.Errorf("no-SNI hello: %q %v", sni, err)
	}
}

func TestTLSKubernetesSource(t *testing.T) {
	p := newPKI(t)
	be := newTLSBackend(t, p, "kube", "k.test")
	api := newFakeAPI(t)
	api.put("gatewayclasses", "", "setura", m{"spec": m{"controllerName": ControllerName}})
	api.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "pass", "protocol": "TLS", "port": 8080, "tls": m{"mode": "Passthrough"}, "allowedRoutes": m{"namespaces": m{"from": "All"}}}}}})
	api.put("tlsroutes", "shop", "k", m{"metadata": m{"creationTimestamp": "2026-01-01T00:00:00Z", "generation": 1},
		"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra"}}, "hostnames": l{"k.test"},
			"rules": l{m{"backendRefs": l{m{"name": "tls-svc", "port": 443}}}}}})
	api.put("services", "shop", "tls-svc", m{"spec": m{"ports": l{m{"port": 443}}}})
	api.put("endpointslices", "shop", "tls-svc-1", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "tls-svc"}},
		"endpoints": l{m{"addresses": l{hostOf(be.addr())}, "conditions": m{"ready": true}}},
		"ports":     l{m{"port": portOf(be.addr())}}})
	s, _, _ := kubeServer(t, api, nil)
	if got := askTLS(t, s.Addr(8080), p, "k.test"); got != "kube:ping" {
		t.Fatalf("got %q", got)
	}
	waitFor(t, "tlsroute status", func() bool {
		st, _ := api.get("tlsroutes", "shop", "k")["status"].(m)
		parents, _ := st["parents"].([]any)
		return len(parents) == 1
	})
}

func TestExampleGRPCTLSRoutes(t *testing.T) {
	raw, err := os.ReadFile("../../examples/grpc-tls-routes.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.GRPCRoutes) != 1 || len(cfg.TLSRoutes) != 2 {
		t.Fatalf("parsed %d GRPCRoutes, %d TLSRoutes", len(cfg.GRPCRoutes), len(cfg.TLSRoutes))
	}
	st := BuildStatus(BuildTable(cfg), nil, time.Now(), nil)
	for key, rs := range st.Routes {
		for _, p := range rs.Parents {
			if cond(p.Conditions, "Accepted").Status != "True" || cond(p.Conditions, "ResolvedRefs").Status != "True" {
				t.Errorf("%s: %+v", key, p.Conditions)
			}
		}
	}
	if len(st.Routes) != 3 {
		t.Errorf("routes in status: %v", st.Routes)
	}
}
