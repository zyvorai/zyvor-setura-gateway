package gateway

import (
	"strings"
	"testing"
)

// Two Gateways in different namespaces that claim the same port and hostname:
// the loser must say which Gateway won, on the listener, on the Gateway and on
// the routes that lost their listener.
func TestCrossNamespaceListenerConflictNamesTheOtherGateway(t *testing.T) {
	be, _ := upstreams(t, "ok")
	raw := snap(httpGateway("x.test"), map[string]m{"r": route("x.test", rule("/", ref("ok", 1)))}, be)
	tb := tableOf(t, raw, func(c *Config) {
		c.Gateways = append(c.Gateways, &Gateway{NS: "zed", Name: "edge", Generation: 1, ClassName: "setura",
			Listeners: []Listener{{Name: "web", Hostname: "x.test", Port: 8080, Protocol: "HTTP"}}})
		c.Routes = append(c.Routes, &Route{NS: "zed", Name: "r2", Generation: 1, Hostnames: []string{"x.test"},
			Parents: []ParentRef{{Name: "edge"}}, Rules: []Rule{{BackendRefs: []BackendRef{{Name: "ok", Port: 80}}}}})
	})
	st := BuildStatus(tb, nil, tnow(), nil)

	win := st.Gateways["t/gw"]
	if c := cond(win.Conditions, "Programmed"); c.Status != "True" {
		t.Errorf("first Gateway must keep serving: %+v", c)
	}
	lose := st.Gateways["zed/edge"]
	if len(lose.Listeners) != 1 {
		t.Fatalf("listeners: %+v", lose.Listeners)
	}
	c := cond(lose.Listeners[0].Conditions, "Conflicted")
	if c.Status != "True" || c.Reason != "HostnameConflict" {
		t.Fatalf("listener conflict: %+v", c)
	}
	for _, want := range []string{`Gateway t/gw`, `listener "web"`, "port 8080", `"x.test"`} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("listener message %q lacks %q", c.Message, want)
		}
	}
	p := cond(lose.Conditions, "Programmed")
	if p.Status != "False" || p.Reason != "ListenersNotValid" || !strings.Contains(p.Message, "HostnameConflict") || !strings.Contains(p.Message, "Gateway t/gw") {
		t.Errorf("Gateway Programmed must name the conflict and the winner: %+v", p)
	}
	rs := st.Routes["zed/r2"].Parents[0]
	a := cond(rs.Conditions, "Accepted")
	if a.Status != "False" || a.Reason != "NotAllowedByListeners" || !strings.Contains(a.Message, "Gateway t/gw") {
		t.Errorf("route Accepted must name the conflicting Gateway: %+v", a)
	}
}

func TestProtocolConflictNamesTheOtherGateway(t *testing.T) {
	be, _ := upstreams(t, "ok")
	raw := snap(httpGateway(""), map[string]m{"r": route("", rule("/", ref("ok", 1)))}, be)
	tb := tableOf(t, raw, func(c *Config) {
		c.Gateways = append(c.Gateways, &Gateway{NS: "zed", Name: "edge", ClassName: "setura",
			Listeners: []Listener{{Name: "tcp", Port: 8080, Protocol: "TCP"}}})
	})
	l := tb.Listeners[len(tb.Listeners)-1]
	if !l.Conflicted.OK || l.Conflicted.Reason != "ProtocolConflict" || !strings.Contains(l.Conflicted.Message, "Gateway t/gw") {
		t.Errorf("%+v", l.Conflicted)
	}
}
