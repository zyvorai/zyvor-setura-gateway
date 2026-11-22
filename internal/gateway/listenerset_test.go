package gateway

import (
	"testing"
)

const lsKeyT = "listenersets.gateway.networking.k8s.io/"

func setRes(name, parent string, listeners ...m) m {
	return m{"parentRef": m{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": parent}, "listeners": toList(listeners)}
}

func TestListenerSetAttachment(t *testing.T) {
	be, _ := upstreams(t, "web", "api")
	gw := m{"gatewayClassName": "setura", "listeners": l{m{"name": "web", "protocol": "HTTP", "port": 8080}},
		"allowedListeners": m{"namespaces": m{"from": "Same"}}}
	viaSet := route("", rule("/", ref("api", 1)))
	viaSet["parentRefs"] = l{m{"group": "gateway.networking.k8s.io", "kind": "ListenerSet", "name": "ls"}}
	viaGw := route("", rule("/", ref("web", 1)))
	viaGw["parentRefs"] = l{m{"name": "gw", "sectionName": "web"}}
	all := route("", rule("/all", ref("web", 1)))
	res := m{
		gwKeyT + "gw":  gw,
		lsKeyT + "ls":  setRes("ls", "gw", m{"name": "extra", "protocol": "HTTP", "port": 8081, "hostname": "api.test"}),
		rtKeyT + "set": viaSet,
		rtKeyT + "gwr": viaGw,
		rtKeyT + "all": all,
	}
	s := startServer(t, snapRes(res, be, nil), func(o *Options) { o.PortMap[8081] = 0 })
	if r := req(t, client(s.Addr(8081), nil), "http", "GET", "api.test:8081", "/", ""); r.Status != 200 || r.Echo.Name != "api" {
		t.Fatalf("listener from the ListenerSet: %d %+v", r.Status, r.Echo)
	}
	// A Gateway parentRef without sectionName also attaches to the set's listeners.
	if r := req(t, client(s.Addr(8081), nil), "http", "GET", "other.test:8081", "/", ""); r.Status != 404 {
		t.Errorf("hostname mismatch on the set listener: %d", r.Status)
	}
	if r := get(t, s, "x.test", "/"); r.Echo.Name != "web" {
		t.Errorf("gateway listener: %+v", r)
	}
	st := s.Status()
	ss := st.ListenerSets["t/ls"]
	if ss == nil {
		t.Fatalf("no ListenerSet status: %+v", st.ListenerSets)
	}
	if c := cond(ss.Conditions, "Accepted"); c.Status != "True" {
		t.Errorf("Accepted: %+v", c)
	}
	if c := cond(ss.Conditions, "Programmed"); c.Status != "True" {
		t.Errorf("Programmed: %+v", c)
	}
	if len(ss.Listeners) != 1 || ss.Listeners[0].AttachedRoutes != 2 || ss.Listeners[0].Name != "extra" {
		t.Errorf("set listener status: %+v", ss.Listeners)
	}
	if g := st.Gateways["t/gw"]; g.AttachedListenerSets == nil || *g.AttachedListenerSets != 1 || len(g.Listeners) != 1 {
		t.Errorf("gateway status must count the set and keep its own listeners separate: %+v", g)
	}
	if c := cond(st.Routes["t/set"].Parents[0].Conditions, "Accepted"); c.Status != "True" || st.Routes["t/set"].Parents[0].ParentRef.Kind != "ListenerSet" {
		t.Errorf("route status scoped to the ListenerSet parentRef: %+v", st.Routes["t/set"])
	}
}

func TestListenerSetNotAllowed(t *testing.T) {
	be, _ := upstreams(t, "api")
	for name, allowed := range map[string]any{"default none": nil, "explicit none": m{"namespaces": m{"from": "None"}},
		"selector no match": m{"namespaces": m{"from": "Selector", "selector": m{"matchLabels": m{"team": "x"}}}}} {
		gw := m{"gatewayClassName": "setura", "listeners": l{m{"name": "web", "protocol": "HTTP", "port": 8080}}}
		if allowed != nil {
			gw["allowedListeners"] = allowed
		}
		viaSet := route("", rule("/", ref("api", 1)))
		viaSet["parentRefs"] = l{m{"kind": "ListenerSet", "name": "ls"}}
		res := m{gwKeyT + "gw": gw, lsKeyT + "ls": setRes("ls", "gw", m{"name": "extra", "protocol": "HTTP", "port": 8081}), rtKeyT + "set": viaSet}
		tb := tableOf(t, snapRes(res, be, m{"namespaces": m{"t": m{"labels": m{"team": "y"}}}}), nil)
		st := BuildStatus(tb, nil, tnow(), nil)
		ss := st.ListenerSets["t/ls"]
		if c := cond(ss.Conditions, "Accepted"); c.Status != "False" || c.Reason != "NotAllowed" {
			t.Errorf("%s: %+v", name, c)
		}
		if g := st.Gateways["t/gw"]; g.AttachedListenerSets == nil || *g.AttachedListenerSets != 0 {
			t.Errorf("%s: gateway attachedListenerSets: %+v", name, g.AttachedListenerSets)
		}
		if _, ok := tb.Ports[8081]; ok {
			t.Errorf("%s: a refused ListenerSet must not open its port", name)
		}
		if c := cond(st.Routes["t/set"].Parents[0].Conditions, "Accepted"); c.Status != "False" {
			t.Errorf("%s: a route on a refused set is not accepted: %+v", name, c)
		}
	}
}

func TestListenerSetConflictAndSelector(t *testing.T) {
	gw := m{"gatewayClassName": "setura", "listeners": l{m{"name": "web", "protocol": "HTTP", "port": 8080, "hostname": "a.test"}},
		"allowedListeners": m{"namespaces": m{"from": "Selector", "selector": m{"matchExpressions": l{m{"key": "team", "operator": "In", "values": l{"y"}}}}}}}
	res := m{gwKeyT + "gw": gw, lsKeyT + "ls": setRes("ls", "gw",
		m{"name": "dup", "protocol": "HTTP", "port": 8080, "hostname": "a.test"},
		m{"name": "proto", "protocol": "HTTPS", "port": 8080, "hostname": "b.test"},
		m{"name": "fine", "protocol": "HTTP", "port": 8080, "hostname": "c.test"})}
	tb := tableOf(t, snapRes(res, map[string]any{}, m{"namespaces": m{"t": m{"labels": m{"team": "y"}}}}), nil)
	by := map[string]ListenerStatus{}
	for _, ls := range BuildStatus(tb, nil, tnow(), nil).ListenerSets["t/ls"].Listeners {
		by[ls.Name] = ls
	}
	if c := cond(by["dup"].Conditions, "Conflicted"); c.Status != "True" || c.Reason != "HostnameConflict" {
		t.Errorf("a set listener that repeats the Gateway's hostname conflicts: %+v", c)
	}
	if c := cond(by["proto"].Conditions, "Conflicted"); c.Status != "True" || c.Reason != "ProtocolConflict" {
		t.Errorf("protocol conflict: %+v", c)
	}
	if c := cond(by["fine"].Conditions, "Programmed"); c.Status != "True" {
		t.Errorf("the other listener is fine: %+v", c)
	}
}

func TestSelectorExpressions(t *testing.T) {
	labels := map[string]string{"team": "a", "env": "prod"}
	for _, c := range []struct {
		op   string
		key  string
		vals []string
		want bool
	}{
		{"In", "team", []string{"a", "b"}, true}, {"In", "team", []string{"b"}, false}, {"In", "none", []string{"a"}, false},
		{"NotIn", "team", []string{"b"}, true}, {"NotIn", "team", []string{"a"}, false}, {"NotIn", "none", []string{"a"}, true},
		{"Exists", "env", nil, true}, {"Exists", "none", nil, false},
		{"DoesNotExist", "none", nil, true}, {"DoesNotExist", "env", nil, false},
		{"Bogus", "env", nil, false},
	} {
		if got := (SelectorRequirement{Key: c.key, Operator: c.op, Values: c.vals}).matches(labels); got != c.want {
			t.Errorf("%s %s %v: %v", c.key, c.op, c.vals, got)
		}
	}
	if why := selectorWhy(map[string]string{"team": "a"}, []SelectorRequirement{{Key: "env", Operator: "NotIn", Values: []string{"prod"}}}, labels); why != "env notin (prod)" {
		t.Errorf("selectorWhy: %q", why)
	}
}

func TestAllowedRoutesMatchExpressions(t *testing.T) {
	be, _ := upstreams(t, "a")
	sel := func(exprs l) m {
		return m{"gatewayClassName": "setura", "listeners": l{m{"name": "web", "protocol": "HTTP", "port": 8080,
			"allowedRoutes": m{"namespaces": m{"from": "Selector", "selector": m{"matchExpressions": exprs}}}}}}
	}
	for name, c := range map[string]struct {
		exprs l
		ok    bool
	}{
		"In":           {l{m{"key": "team", "operator": "In", "values": l{"a"}}}, true},
		"NotIn":        {l{m{"key": "team", "operator": "NotIn", "values": l{"a"}}}, false},
		"Exists":       {l{m{"key": "team", "operator": "Exists"}}, true},
		"DoesNotExist": {l{m{"key": "team", "operator": "DoesNotExist"}}, false},
		"combined":     {l{m{"key": "team", "operator": "In", "values": l{"a"}}, m{"key": "tier", "operator": "DoesNotExist"}}, true},
	} {
		r := route("", rule("/", ref("a", 1)))
		r["parentRefs"] = l{m{"name": "gw", "namespace": "t"}}
		res := m{gwKeyT + "gw": sel(c.exprs), rtKeyT + "apps/r": r}
		tb := tableOf(t, snapRes(res, be, m{"namespaces": m{"apps": m{"labels": m{"team": "a"}}}}), nil)
		st := BuildStatus(tb, nil, tnow(), nil)
		got := cond(st.Routes["apps/r"].Parents[0].Conditions, "Accepted").Status == "True"
		if got != c.ok {
			t.Errorf("%s: attached %v, want %v", name, got, c.ok)
		}
	}
}

func TestGatewayStaticAddressesAndRuleName(t *testing.T) {
	be, _ := upstreams(t, "a")
	gw := httpGateway("")
	gw["addresses"] = l{m{"type": "IPAddress", "value": "203.0.113.7"}, m{"type": "Hostname", "value": "gw.example.com"}, m{"value": "198.51.100.9"}}
	rl := rule("/", ref("a", 1))
	rl["name"] = "checkout"
	s := startServer(t, snap(gw, map[string]m{"r": route("", rl)}, be), nil)
	gs := s.Status().Gateways["t/gw"]
	if len(gs.Addresses) != 3 || gs.Addresses[0] != (GatewayAddress{"IPAddress", "203.0.113.7"}) || gs.Addresses[1].Type != "Hostname" || gs.Addresses[2].Type != "IPAddress" {
		t.Errorf("static addresses are reported in status: %+v", gs.Addresses)
	}
	if c := cond(gs.Conditions, "Programmed"); c.Status != "True" {
		t.Errorf("Programmed: %+v", c)
	}
	if tr := explain(t, s.Table(), "GET", "http://x.test:8080/"); tr.Winner.RuleName != "checkout" {
		t.Errorf("rule name in explain: %+v", tr.Winner)
	}
	// An address type the gateway cannot report is refused with the spec's reason.
	gw["addresses"] = l{m{"type": "NamedAddress", "value": "pool-a"}}
	s = startServer(t, snap(gw, map[string]m{"r": route("", rl)}, be), nil)
	gs = s.Status().Gateways["t/gw"]
	if c := cond(gs.Conditions, "Accepted"); c.Status != "False" || c.Reason != "UnsupportedAddress" {
		t.Errorf("unsupported address: %+v", c)
	}
	if c := cond(gs.Conditions, "Programmed"); c.Status != "False" || c.Reason != "AddressNotUsable" {
		t.Errorf("unsupported address Programmed: %+v", c)
	}
}

// DestinationPortMatching: a route attaches to the listener port named by its
// parentRef, and the port the request arrived on (not the Host header's port)
// decides which route serves it.
func TestDestinationPortMatching(t *testing.T) {
	be, _ := upstreams(t, "p1", "p2")
	gw := m{"gatewayClassName": "setura", "listeners": l{m{"name": "one", "protocol": "HTTP", "port": 8080}, m{"name": "two", "protocol": "HTTP", "port": 8081}}}
	mk := func(port int, backend string) m {
		r := route("", rule("/", ref(backend, 1)))
		r["parentRefs"] = l{m{"name": "gw", "port": port}}
		return r
	}
	s := startServer(t, snap(gw, map[string]m{"one": mk(8080, "p1"), "two": mk(8081, "p2")}, be), func(o *Options) { o.PortMap[8081] = 0 })
	for _, c := range []struct {
		port int
		host string
		want string
	}{{8080, "x.test:8080", "p1"}, {8081, "x.test:8081", "p2"}, {8081, "x.test:8080", "p2"}, {8080, "x.test", "p1"}} {
		if r := req(t, client(s.Addr(c.port), nil), "http", "GET", c.host, "/", ""); r.Echo.Name != c.want {
			t.Errorf("destination port %d, Host %s -> %s, want %s", c.port, c.host, r.Echo.Name, c.want)
		}
	}
}
