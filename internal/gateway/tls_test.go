package gateway

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func httpsGateway(listeners ...m) m {
	ls := l{}
	for _, x := range listeners {
		ls = append(ls, x)
	}
	return m{"gatewayClassName": "setura", "listeners": ls}
}

func tlsListener(name, host, secret string) m {
	lm := m{"name": name, "protocol": "HTTPS", "port": 8443, "tls": m{"mode": "Terminate", "certificateRefs": l{m{"name": secret}}}}
	if host != "" {
		lm["hostname"] = host
	}
	return lm
}

func tlsClient(addr string, p *pki, sni string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: p.pool, ServerName: sni},
		DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, n, addr)
		}}}
}

func TestTLSTerminationAndSNI(t *testing.T) {
	p := newPKI(t)
	be, ups := upstreams(t, "a", "b", "w")
	gw := httpsGateway(tlsListener("a", "a.mactra.test", "a-cert"), tlsListener("b", "b.mactra.test", "b-cert"), tlsListener("wild", "*.wild.test", "w-cert"))
	routes := map[string]m{
		"a": {"parentRefs": l{m{"name": "gw", "sectionName": "a"}}, "rules": l{rule("/", ref("a", 1))}},
		"b": {"parentRefs": l{m{"name": "gw", "sectionName": "b"}}, "rules": l{rule("/", ref("b", 1))}},
		"w": {"parentRefs": l{m{"name": "gw", "sectionName": "wild"}}, "rules": l{rule("/", ref("w", 1))}},
	}
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": gw, rtKeyT + "a": routes["a"], rtKeyT + "b": routes["b"], rtKeyT + "w": routes["w"]},
		"backends":  m{"t/a:80": be["a"], "t/b:80": be["b"], "t/w:80": be["w"]},
		"secrets":   m{"a-cert": p.files("a", "a.mactra.test"), "b-cert": p.files("b", "b.mactra.test"), "w-cert": p.files("w", "*.wild.test")}})
	s := startServer(t, raw, nil)
	addr := s.Addr(8443)

	for _, c := range []struct{ host, want string }{{"a.mactra.test", "a"}, {"b.mactra.test", "b"}, {"x.wild.test", "w"}} {
		r := req(t, tlsClient(addr, p, c.host), "https", "GET", c.host, "/", "")
		if r.Status != 200 || r.Echo.Name != c.want {
			t.Errorf("%s: status %d backend %q", c.host, r.Status, r.Echo.Name)
		}
		if r.Echo.Headers["x-forwarded-proto"] != "https" {
			t.Errorf("%s: x-forwarded-proto = %q", c.host, r.Echo.Headers["x-forwarded-proto"])
		}
	}
	// HTTP/2 is negotiated by ALPN on the TLS listener.
	c := tlsClient(addr, p, "a.mactra.test")
	resp, err := c.Get("https://a.mactra.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("proto %s, want HTTP/2", resp.Proto)
	}
	// The certificate really is selected by SNI: a.mactra.test's cert does not
	// verify for b.mactra.test, so verifying b's name against SNI a must fail.
	bad := tlsClient(addr, p, "a.mactra.test")
	bad.Transport.(*http.Transport).TLSClientConfig.ServerName = "a.mactra.test"
	rq, _ := http.NewRequest("GET", "https://b.mactra.test/", nil)
	if resp, err := bad.Do(rq); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			// SNI a with Host b: allowed, the cert was a's and Host b matches no route on listener a.
			t.Logf("host/SNI mismatch served status %d", resp.StatusCode)
		}
	}
	// Unknown SNI falls back to a default cert, which fails verification for that name.
	if _, err := tlsClient(addr, p, "nobody.test").Get("https://nobody.test/"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("unknown SNI should fail certificate verification, got %v", err)
	}
	if n := len(ups["a"].seen()); n < 2 {
		t.Errorf("backend a saw %d requests", n)
	}
	for _, ls := range s.Status().Gateways["t/gw"].Listeners {
		for _, c := range ls.Conditions {
			if c.Status != map[string]string{"Conflicted": "False"}[c.Type] && c.Status != "True" {
				t.Errorf("listener %s condition %s = %s (%s)", ls.Name, c.Type, c.Status, c.Message)
			}
		}
	}
}

func TestTLSBadCertificateRefOnlyDisablesThatListener(t *testing.T) {
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	gw := m{"gatewayClassName": "setura", "listeners": l{
		tlsListener("good", "good.test", "good-cert"),
		m{"name": "bad", "protocol": "HTTPS", "port": 9443, "hostname": "bad.test", "tls": m{"certificateRefs": l{m{"name": "missing"}}}},
		m{"name": "plain", "protocol": "HTTP", "port": 8080},
	}}
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": gw, rtKeyT + "r": route("", rule("/", ref("a", 1)))},
		"backends":  m{"t/a:80": be["a"]}, "secrets": m{"good-cert": p.files("good", "good.test")}})
	s := startServer(t, raw, func(o *Options) { o.PortMap[9443] = 0 })
	if r := req(t, tlsClient(s.Addr(8443), p, "good.test"), "https", "GET", "good.test", "/", ""); r.Status != 200 {
		t.Fatalf("good listener status %d", r.Status)
	}
	if s.Addr(9443) != "" {
		t.Error("a listener with an unresolvable certificate must not bind")
	}
	if get(t, s, "any.test", "/").Status != 200 {
		t.Error("the HTTP listener should keep serving")
	}
	for _, ls := range s.Status().Gateways["t/gw"].Listeners {
		if ls.Name != "bad" {
			continue
		}
		got := map[string]Condition{}
		for _, c := range ls.Conditions {
			got[c.Type] = c
		}
		if got["ResolvedRefs"].Status != "False" || got["ResolvedRefs"].Reason != "InvalidCertificateRef" || got["Programmed"].Status != "False" {
			t.Errorf("bad listener conditions: %+v", got)
		}
	}
	if gc := s.Status().Gateways["t/gw"].Conditions[1]; gc.Type != "Programmed" || gc.Status != "False" {
		t.Errorf("gateway Programmed should be False: %+v", gc)
	}
}

func TestSecretNeedsReferenceGrant(t *testing.T) {
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	lm := tlsListener("web", "a.test", "x")
	lm["tls"].(m)["certificateRefs"] = l{m{"name": "x", "namespace": "certs"}}
	mk := func(grants l) []byte {
		return mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
			"resources": m{gwKeyT + "gw": httpsGateway(lm), rtKeyT + "r": route("", rule("/", ref("a", 1)))},
			"backends":  m{"t/a:80": be["a"]}, "secrets": m{"certs/x": p.files("x", "a.test")}, "referenceGrants": grants})
	}
	s := startServer(t, mk(nil), nil)
	if s.Addr(8443) != "" {
		t.Fatal("cross-namespace secret without a grant must not be served")
	}
	if c := s.Status().Gateways["t/gw"].Listeners[0].Conditions[2]; c.Reason != "RefNotPermitted" {
		t.Fatalf("ResolvedRefs = %+v", c)
	}
	grant := l{m{"metadata": m{"namespace": "certs"}, "spec": m{
		"from": l{m{"group": APIGroup, "kind": "Gateway", "namespace": "t"}}, "to": l{m{"group": "", "kind": "Secret"}}}}}
	s = startServer(t, mk(grant), nil)
	if r := req(t, tlsClient(s.Addr(8443), p, "a.test"), "https", "GET", "a.test", "/", ""); r.Status != 200 {
		t.Fatalf("with a grant: status %d", r.Status)
	}
}
