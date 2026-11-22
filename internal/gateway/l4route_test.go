package gateway

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	tcpKeyT = "tcproutes.gateway.networking.k8s.io/"
	udpKeyT = "udproutes.gateway.networking.k8s.io/"
)

// tcpBackend answers every connection with its name followed by an echo of
// whatever the client sends, until the client half-closes.
func tcpBackend(t *testing.T, name string) string {
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
				io.WriteString(c, name+":")
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func l4Gateway(proto string, port int) m {
	return m{"gatewayClassName": "setura", "listeners": l{m{"name": proto, "protocol": proto, "port": port}}}
}

func l4Route(key string, ports int, refs ...m) m {
	_ = key
	return m{"parentRefs": l{m{"name": "gw"}}, "rules": l{m{"name": "main", "backendRefs": toList(refs)}}}
}

func TestTCPRouteWeightedHalfClose(t *testing.T) {
	a, b := tcpBackend(t, "A"), tcpBackend(t, "B")
	res := m{gwKeyT + "gw": l4Gateway("TCP", 9000), tcpKeyT + "r": l4Route("", 0, ref("a", 0), ref("b", 1))}
	s := startServer(t, snapRes(res, map[string]any{"a": a, "b": b}, nil), func(o *Options) { o.PortMap[9000] = 0 })
	for i := 0; i < 5; i++ {
		c, err := net.Dial("tcp", s.Addr(9000))
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "hello")
		c.(*net.TCPConn).CloseWrite() // half-close: the backend must still deliver its answer
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		got, err := io.ReadAll(c)
		c.Close()
		if err != nil || string(got) != "B:hello" {
			t.Fatalf("connection %d: %q %v (weight 0 never gets traffic, the reply survives a half-close)", i, got, err)
		}
	}
	st := s.Status()
	if c := cond(st.Routes["TCPRoute/t/r"].Parents[0].Conditions, "Accepted"); c.Status != "True" {
		t.Errorf("route Accepted: %+v", c)
	}
	ls := st.Gateways["t/gw"].Listeners[0]
	if ls.AttachedRoutes != 1 || len(ls.SupportedKinds) != 1 || ls.SupportedKinds[0].Kind != "TCPRoute" {
		t.Errorf("listener status: %+v", ls)
	}
	// The counters are written when the connection handler returns, after the client saw EOF.
	waitFor(t, "TCP stats and metrics", func() bool {
		var sb strings.Builder
		s.WriteMetrics(&sb)
		got := s.Stats().Snapshot()["routes"].(map[string]Counter)["TCPRoute/t/r"]
		return got.Requests == 5 && strings.Contains(sb.String(), `setura_gateway_l4_connections_total{protocol="TCP",route="TCPRoute/t/r",backend="t/b:80"} 5`)
	})
}

func TestExplainL4(t *testing.T) {
	res := m{gwKeyT + "gw": l4Gateway("TCP", 9000), tcpKeyT + "r": l4Route("", 0, ref("a", 3), ref("b", 1))}
	tb := tableOf(t, snapRes(res, map[string]any{"a": "127.0.0.1:9", "b": "127.0.0.1:10"}, nil), nil)
	req, err := ParseExplainRequest("GET", "http://x.test:9000/", nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	tr := Explain(tb, req)
	if tr.Verdict != VerdictRouted || tr.Winner == nil || tr.Winner.Kind != "TCPRoute" || tr.Winner.RuleName != "main" || len(tr.Winner.Backends) != 2 || tr.Winner.Backends[0].Percent != 75 {
		t.Fatalf("TCP explanation: %s\n%s", tr.Verdict, dumpTrace(tr))
	}
	// An HTTP replay must never treat a TCP port as an HTTP listener.
	if g := tb.Ports[9000]; g == nil || g.L4 != "TCP" {
		t.Errorf("port group: %+v", g)
	}
}

func TestTCPRouteBackendDownAndInvalid(t *testing.T) {
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()
	res := m{gwKeyT + "gw": l4Gateway("TCP", 9000), tcpKeyT + "r": l4Route("", 0, ref("gone", 1), ref("nope", 0))}
	s := startServer(t, snapRes(res, map[string]any{"gone": addr}, nil), func(o *Options) { o.PortMap[9000] = 0 })
	c, err := net.Dial("tcp", s.Addr(9000))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := c.Read(make([]byte, 8)); err == nil || n != 0 {
		t.Errorf("a connection to a dead backend is closed: %d %v", n, err)
	}
	c.Close()
	rc := cond(s.Status().Routes["TCPRoute/t/r"].Parents[0].Conditions, "ResolvedRefs")
	if rc.Status != "False" || rc.Reason != "BackendNotFound" {
		t.Errorf("ResolvedRefs: %+v", rc)
	}
}

func TestL4ListenerKindsAndConflicts(t *testing.T) {
	res := m{gwKeyT + "gw": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "tcp", "protocol": "TCP", "port": 9000},
		m{"name": "udp", "protocol": "UDP", "port": 9000},
		m{"name": "bad", "protocol": "TCP", "port": 9001, "allowedRoutes": m{"kinds": l{m{"kind": "HTTPRoute"}}}},
	}},
		tcpKeyT + "r":   l4Route("", 0, ref("a", 1)),
		udpKeyT + "u":   l4Route("", 0, ref("a", 1)),
		rtKeyT + "http": route("", rule("/", ref("a", 1))),
	}
	tb := tableOf(t, snapRes(res, map[string]any{"a": "127.0.0.1:9"}, nil), nil)
	st := BuildStatus(tb, nil, tnow(), nil)
	by := map[string]ListenerStatus{}
	for _, ls := range st.Gateways["t/gw"].Listeners {
		by[ls.Name] = ls
	}
	if c := cond(by["udp"].Conditions, "Conflicted"); c.Status != "True" || c.Reason != "ProtocolConflict" {
		t.Errorf("TCP and UDP on one port conflict: %+v", c)
	}
	if c := cond(by["bad"].Conditions, "ResolvedRefs"); c.Status != "False" || c.Reason != "InvalidRouteKinds" {
		t.Errorf("a TCP listener cannot carry HTTPRoute: %+v", c)
	}
	if c := cond(st.Routes["t/http"].Parents[0].Conditions, "Accepted"); c.Status != "True" {
		// the HTTPRoute names gw without a section, no HTTP listener exists
		t.Logf("http route: %+v", c)
	}
	if c := cond(st.Routes["UDPRoute/t/u"].Parents[0].Conditions, "Accepted"); c.Status != "False" {
		t.Errorf("a UDPRoute cannot attach to the conflicted UDP listener: %+v", c)
	}
}

func TestUDPRouteSessionsAndIdleTimeout(t *testing.T) {
	back, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { back.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := back.ReadFrom(buf)
			if err != nil {
				return
			}
			back.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	res := m{gwKeyT + "gw": l4Gateway("UDP", 9001), udpKeyT + "u": l4Route("", 0, ref("dns", 1))}
	s := startServer(t, snapRes(res, map[string]any{"dns": back.LocalAddr().String()}, nil), func(o *Options) {
		o.PortMap[9001] = 0
		o.UDPIdle = 150 * time.Millisecond
	})
	talk := func(msg string) *net.UDPConn {
		raddr, _ := net.ResolveUDPAddr("udp", s.Addr(9001))
		c, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err != nil || string(buf[:n]) != "echo:"+msg {
			t.Fatalf("udp reply %q %v", buf[:n], err)
		}
		return c
	}
	c1, c2 := talk("one"), talk("two")
	defer c1.Close()
	defer c2.Close()
	sessions := func() int {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.ports[9001].udp.sessionCount()
	}
	if n := sessions(); n != 2 {
		t.Fatalf("one session per client address, got %d", n)
	}
	// A second datagram of the same client reuses its session.
	c1.Write([]byte("again"))
	buf := make([]byte, 64)
	c1.SetDeadline(time.Now().Add(3 * time.Second))
	if n, err := c1.Read(buf); err != nil || string(buf[:n]) != "echo:again" {
		t.Fatalf("second datagram: %q %v", buf[:n], err)
	}
	if n := sessions(); n != 2 {
		t.Errorf("sessions after reuse: %d", n)
	}
	// Idle sessions are removed.
	deadline := time.Now().Add(5 * time.Second)
	for sessions() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("idle sessions never expired: %d left", sessions())
		}
		time.Sleep(20 * time.Millisecond)
	}
	waitFor(t, "UDP metrics", func() bool {
		var sb strings.Builder
		s.WriteMetrics(&sb)
		return strings.Contains(sb.String(), `setura_gateway_l4_connections_total{protocol="UDP"`) && strings.Contains(sb.String(), "setura_gateway_udp_sessions_open 0")
	})
	if c := cond(s.Status().Routes["UDPRoute/t/u"].Parents[0].Conditions, "Accepted"); c.Status != "True" {
		t.Errorf("UDPRoute Accepted: %+v", c)
	}
}
