package gateway

import (
	"strings"
	"testing"
)

func TestUnknownKeysTableIsReadFromStructs(t *testing.T) {
	for _, k := range []string{AuthKey, DirectResponseKey, RateLimitKey, LimitsKey, CompressKey, GRPCWebKey, BandwidthKey, FaultKey, ContractKey, AIKey, LoadBalancerKey} {
		if len(UnknownRuleKeys([]string{k})) != 0 {
			t.Errorf("%s must be a known rule key", k)
		}
		for _, a := range []string{k, k + ".rule-3"} {
			if len(UnknownAnnotationKeys([]string{a})) != 0 {
				t.Errorf("%s must be a known annotation", a)
			}
		}
	}
	for _, k := range []string{ShadowDiffKey, BackendsKey, ShadowDiffKey + ".rule-2"} {
		if len(UnknownAnnotationKeys([]string{k})) != 0 {
			t.Errorf("%s must be a known annotation", k)
		}
	}
	if len(UnknownListenerOptionKeys([]string{TLSMinVersionOption, TLSCipherSuitesOption})) != 0 {
		t.Error("tls options are known")
	}
	if got := UnknownAnnotationKeys([]string{"example.com/x", "kubernetes.io/foo"}); len(got) != 0 {
		t.Errorf("foreign annotations are not ours: %v", got)
	}
}

func TestUnknownKeysSuggestAndClassify(t *testing.T) {
	cases := []struct {
		key, suggest string
		typo         bool
	}{
		{"setura.zyvor.dev/authh", AuthKey, true},
		{"setura.zyvor.dev/rate-limt.rule-1", RateLimitKey + ".rule-1", true},
		{"setura.zyvor.dev/load-balancr", LoadBalancerKey, true},
		{"setura.zyvor.dev/something-else-entirely", "", false},
		{"setura.zyvor.dev/xyz", "", false}, // short names do not match everything
	}
	for _, c := range cases {
		is := UnknownAnnotationKeys([]string{c.key})
		if len(is) != 1 || is[0].Suggest != c.suggest || is[0].Typo != c.typo {
			t.Errorf("%s: %+v, want suggest %q typo %v", c.key, is, c.suggest, c.typo)
		}
	}
}

func extRule(key string) []byte {
	return []byte(`{"matches":[{"path":{"value":"/"}}],"` + key + `":{"x":1}}`)
}

func TestRuleWithUnknownKeyIsInvalidAtRunTime(t *testing.T) {
	be, _ := upstreams(t, "a")
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": httpGateway("a.test"), rtKeyT + "a": m{"parentRefs": l{m{"name": "gw"}},
			"rules": l{m{"setura.zyvor.dev/authh": m{"apiKey": m{}}, "backendRefs": l{ref("a", 1)}}}}},
		"backends": m{"t/a:80": be["a"]}})
	cfg, err := ParseConfig(raw, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tb := BuildTable(cfg)
	pr := tb.routes[0].Parents[0]
	if pr.Accepted.OK || pr.Accepted.Reason != "UnsupportedValue" || !strings.Contains(pr.Accepted.Message, `did you mean "setura.zyvor.dev/auth"`) {
		t.Fatalf("route must be refused: %+v", pr.Accepted)
	}
}

func routeWithAnnotations(t *testing.T, ann m) *parentResult {
	t.Helper()
	be, _ := upstreams(t, "a")
	raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
		"resources": m{gwKeyT + "gw": httpGateway("a.test"), rtKeyT + "a": m{"parentRefs": l{m{"name": "gw"}},
			SeturaAnnotationsKey: ann, "rules": l{m{"backendRefs": l{ref("a", 1)}}}}},
		"backends": m{"t/a:80": be["a"]}})
	cfg, err := ParseConfig(raw, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return BuildTable(cfg).routes[0].Parents[0]
}

func TestAnnotationTypoFailsClosedAndOtherUnknownWarns(t *testing.T) {
	pr := routeWithAnnotations(t, m{"setura.zyvor.dev/rate-limt.rule-1": `{"rate":"1/m"}`})
	if pr.Accepted.OK || !strings.Contains(pr.Accepted.Message, "rate-limt") {
		t.Fatalf("a probable typo must refuse the route: %+v", pr.Accepted)
	}
	pr = routeWithAnnotations(t, m{"setura.zyvor.dev/my-own-thing": "x"})
	if !pr.Accepted.OK || !strings.Contains(pr.Accepted.Message, "WARNING: unknown Setura extension key") {
		t.Fatalf("a far unknown key serves the route with a warning: %+v", pr.Accepted)
	}
	pr = routeWithAnnotations(t, m{RateLimitKey: `{"rate":"1/m"}`})
	if !pr.Accepted.OK || strings.Contains(pr.Accepted.Message, "WARNING") {
		t.Fatalf("a known key is clean: %+v", pr.Accepted)
	}
}

func TestGRPCRuleWithUnknownKeyFailsAuthClosed(t *testing.T) {
	var r GRPCRule
	if err := r.UnmarshalJSON(extRule("setura.zyvor.dev/autth")); err != nil {
		t.Fatal(err)
	}
	if r.Auth == nil || compileAuth(r.Auth) == nil {
		t.Fatal("an unknown key must make the GRPC rule's auth fail compilation")
	}
}

func TestKubernetesAnnotationTypoRefusesRouteAndUnknownWarns(t *testing.T) {
	for _, tc := range []struct {
		key        string
		wantServed bool
		wantMsg    string
		wantStatus string
	}{
		{"setura.zyvor.dev/authh", false, "did you mean", "False"},
		{"setura.zyvor.dev/my-own-thing", true, "WARNING: unknown Setura extension key", "True"},
	} {
		up := newUpstream(t, "primary")
		api := newFakeAPI(t)
		api.seed(up.addr())
		rt := api.get("httproutes", "shop", "orders")
		rt["metadata"].(m)["annotations"] = m{tc.key: `{"apiKey":{}}`}
		api.put("httproutes", "shop", "orders", rt)
		s, _, _ := kubeServer(t, api, nil)
		got := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders/1", "").Status
		if (got == 200) != tc.wantServed {
			t.Errorf("%s: served status %d, want served=%v", tc.key, got, tc.wantServed)
		}
		waitFor(t, tc.key+" status", func() bool {
			st, _ := api.get("httproutes", "shop", "orders")["status"].(m)
			for _, p := range st["parents"].([]any) {
				if p.(m)["controllerName"] != ControllerName {
					continue
				}
				for _, c := range p.(m)["conditions"].([]any) {
					cm := c.(m)
					if cm["type"] == "Accepted" && cm["status"] == tc.wantStatus && strings.Contains(cm["message"].(string), tc.wantMsg) {
						return true
					}
				}
			}
			return false
		})
	}
}

func TestWhyShowsUnknownKeys(t *testing.T) {
	build := func(ann m) *Table {
		be, _ := upstreams(t, "a")
		raw := mustJSON(m{"schema": SnapshotSchema, "namespace": "t",
			"resources": m{gwKeyT + "gw": httpGateway(""), rtKeyT + "a": m{"parentRefs": l{m{"name": "gw"}},
				SeturaAnnotationsKey: ann, "rules": l{m{"backendRefs": l{ref("a", 1)}}}}},
			"backends": m{"t/a:80": be["a"]}})
		cfg, err := ParseConfig(raw, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		return BuildTable(cfg)
	}
	q, _ := ParseExplainRequest("GET", "http://x.test:8080/", nil, "", "")
	tr := Explain(build(m{"setura.zyvor.dev/my-own-thing": "x"}), q)
	if tr.Winner == nil || !strings.Contains(strings.Join(tr.Winner.Notes, "\n"), "unknown Setura extension key") {
		t.Fatalf("why must show the ignored key: %+v", tr.Winner)
	}
	tr = Explain(build(m{"setura.zyvor.dev/authh": "{}"}), q)
	if tr.Winner != nil {
		t.Fatalf("a refused route must not win")
	}
	var reasons []string
	for _, r := range tr.Routes {
		reasons = append(reasons, r.Reason)
	}
	if !strings.Contains(strings.Join(reasons, "\n"), "authh") {
		t.Fatalf("why must say why the route is refused: %v", reasons)
	}
}
