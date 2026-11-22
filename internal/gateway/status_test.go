package gateway

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func cond(cs []Condition, typ string) Condition {
	for _, c := range cs {
		if c.Type == typ {
			return c
		}
	}
	return Condition{}
}

func TestRouteStatusConditions(t *testing.T) {
	be, _ := upstreams(t, "ok")
	crossNS := m{"name": "ok", "port": 80, "namespace": "other"}
	badKind := m{"name": "ok", "port": 80, "kind": "ConfigMap"}
	badRegex := m{"matches": l{m{"path": m{"type": "RegularExpression", "value": "("}}}, "backendRefs": l{ref("ok", 1)}}
	routes := map[string]m{
		"good":    route("", rule("/good", ref("ok", 1))),
		"missing": route("", rule("/", ref("ghost", 1))),
		"cross":   route("", rule("/", crossNS)),
		"kind":    route("", rule("/", badKind)),
		"regex":   route("", badRegex),
		"nogw":    {"parentRefs": l{m{"name": "nope"}}, "rules": l{rule("/", ref("ok", 1))}},
		"nosect":  {"parentRefs": l{m{"name": "gw", "sectionName": "ghost"}}, "rules": l{rule("/", ref("ok", 1))}},
		"filter": func() m {
			r := rule("/", ref("ok", 1))
			r["filters"] = l{m{"type": "ExtensionRef"}}
			return route("", r)
		}(),
		"redirect": route("", m{"filters": l{m{"type": "RequestRedirect", "requestRedirect": m{"statusCode": 399}}}}),
	}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	st := s.Status()
	for name, want := range map[string][2]string{
		"good": {"True/Accepted", "True/ResolvedRefs"}, "missing": {"True/Accepted", "False/BackendNotFound"},
		"cross": {"True/Accepted", "False/RefNotPermitted"}, "kind": {"True/Accepted", "False/InvalidKind"},
		"regex": {"False/UnsupportedValue", "True/ResolvedRefs"}, "nogw": {"False/NoMatchingParent", "True/ResolvedRefs"},
		"nosect": {"False/NoMatchingParent", "True/ResolvedRefs"}, "filter": {"False/UnsupportedValue", "True/ResolvedRefs"},
		"redirect": {"False/UnsupportedValue", "True/ResolvedRefs"},
	} {
		p := st.Routes["t/"+name].Parents[0]
		if p.ControllerName != ControllerName {
			t.Errorf("%s controller %q", name, p.ControllerName)
		}
		a, r := cond(p.Conditions, "Accepted"), cond(p.Conditions, "ResolvedRefs")
		if got := a.Status + "/" + a.Reason; got != want[0] {
			t.Errorf("%s Accepted = %s, want %s (%s)", name, got, want[0], a.Message)
		}
		if got := r.Status + "/" + r.Reason; got != want[1] {
			t.Errorf("%s ResolvedRefs = %s, want %s (%s)", name, got, want[1], r.Message)
		}
		if a.ObservedGeneration != st.Routes["t/"+name].ObservedGeneration || a.ObservedGeneration == 0 {
			t.Errorf("%s observedGeneration %d", name, a.ObservedGeneration)
		}
	}
	gs := st.Gateways["t/gw"]
	if cond(gs.Conditions, "Accepted").Status != "True" || cond(gs.Conditions, "Programmed").Status != "True" {
		t.Errorf("gateway conditions %+v", gs.Conditions)
	}
	if gs.Listeners[0].AttachedRoutes != 4 { // good, missing, cross and kind attach; invalid routes do not
		t.Errorf("attached routes: %d, want 4", gs.Listeners[0].AttachedRoutes)
	}
	// Lint-clean data plane behaviour matches the status: a ResolvedRefs=False route returns 500.
	if r := get(t, s, "x.test", "/good"); r.Status != 200 {
		t.Error("good route should serve", r.Status, r.Body)
	}
}

func TestListenerConflictsAndBindFailure(t *testing.T) {
	be, _ := upstreams(t, "ok")
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	gw := m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080},
		m{"name": "dup", "protocol": "HTTP", "port": 8080},
		m{"name": "mixed", "protocol": "HTTPS", "port": 8080, "hostname": "s.test", "tls": m{"certificateRefs": l{m{"name": "c"}}}},
		m{"name": "tcp", "protocol": "SCTP", "port": 9000},
		m{"name": "busy", "protocol": "HTTP", "port": 7000},
	}}
	s := startServer(t, snap(gw, map[string]m{"r": route("", rule("/", ref("ok", 1)))}, be), func(o *Options) {
		o.PortMap[7000] = busy.Addr().(*net.TCPAddr).Port
	})
	by := map[string]ListenerStatus{}
	for _, ls := range s.Status().Gateways["t/gw"].Listeners {
		by[ls.Name] = ls
	}
	for name, want := range map[string][2]string{
		"web": {"Programmed", "True"}, "dup": {"Conflicted", "True"}, "mixed": {"Conflicted", "True"},
		"tcp": {"Accepted", "False"}, "busy": {"Programmed", "False"},
	} {
		if c := cond(by[name].Conditions, want[0]); c.Status != want[1] {
			t.Errorf("listener %s %s = %s (%s)", name, want[0], c.Status, c.Message)
		}
	}
	if c := cond(by["dup"].Conditions, "Conflicted"); c.Reason != "HostnameConflict" {
		t.Errorf("dup reason %q", c.Reason)
	}
	if c := cond(by["mixed"].Conditions, "Conflicted"); c.Reason != "ProtocolConflict" {
		t.Errorf("mixed reason %q", c.Reason)
	}
	if c := cond(by["tcp"].Conditions, "Accepted"); c.Reason != "UnsupportedProtocol" {
		t.Errorf("tcp reason %q", c.Reason)
	}
	if c := cond(by["busy"].Conditions, "Programmed"); c.Reason != "PortUnavailable" {
		t.Errorf("busy reason %q", c.Reason)
	}
	if by["web"].AttachedRoutes != 1 || by["dup"].AttachedRoutes != 0 {
		t.Errorf("attached routes: %+v", by)
	}
}

func TestAdminEndpoints(t *testing.T) {
	p := newPKI(t)
	be, _ := upstreams(t, "a")
	secret := p.files("a", "a.test")
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": httpsGateway(tlsListener("web", "a.test", "c")), rtKeyT + "r": route("", rule("/", ref("a", 1)))},
		"backends":  m{"t/a:80": be["a"]}, "secrets": m{"c": secret}})
	path := filepath.Join(t.TempDir(), "cfg.json")
	writeFile(t, path, raw)
	s, _, _ := startFile(t, path, func(o *Options) { o.PortMap[8443] = 0 })
	admin := "http://" + s.AdminAddr()
	fetch := func(p string) (int, string) {
		resp, err := http.Get(admin + p)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := fetch("/ready"); code != 200 {
		t.Errorf("/ready = %d", code)
	}
	req(t, tlsClient(s.Addr(8443), p, "a.test"), "https", "GET", "a.test", "/", "")
	code, body := fetch("/stats")
	if code != 200 || !strings.Contains(body, `"t/r"`) || !strings.Contains(body, `"t/a:80"`) {
		t.Errorf("/stats = %d %s", code, body)
	}
	code, body = fetch("/config")
	if code != 200 || !strings.Contains(body, `"httproutes"`) || !strings.Contains(body, `"secrets"`) {
		t.Errorf("/config = %d %s", code, body)
	}
	if strings.Contains(body, "BEGIN") || strings.Contains(body, secret["keyFile"].(string)) {
		t.Error("/config must never include secret material or its paths")
	}
	code, body = fetch("/status")
	var doc StatusDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil || code != 200 || doc.Schema != StatusSchema || !doc.LastReload.OK || doc.ConfigHash == "" {
		t.Errorf("/status = %d %v %s", code, err, body)
	}
	if code, _ := fetch("/nope"); code != 404 {
		t.Errorf("/nope = %d", code)
	}
}
