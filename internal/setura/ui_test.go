package setura

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/zyvor-setura-gateway/internal/webui"
)

const uiSnap = `{
  "schema": "setura.route-specs/v1", "namespace": "shop",
  "resources": {
    "gateways.gateway.networking.k8s.io/edge": {"gatewayClassName": "setura",
      "listeners": [{"name": "web", "protocol": "HTTP", "port": 8080, "hostname": "*.shop.test"}]},
    "httproutes.gateway.networking.k8s.io/orders": {
      "parentRefs": [{"name": "edge", "sectionName": "web"}], "hostnames": ["orders.shop.test"],
      "rules": [
        {"matches": [{"path": {"type": "PathPrefix", "value": "/checkout"}, "method": "GET"}],
         "filters": [{"type": "RequestHeaderModifier", "requestHeaderModifier": {"set": [{"name": "Authorization", "value": "Bearer hunter2"}]}}],
         "backendRefs": [{"name": "v1", "port": 80, "weight": 90}, {"name": "v2", "port": 80, "weight": 10}]}]},
    "httproutes.gateway.networking.k8s.io/legacy": {
      "parentRefs": [{"name": "edge", "sectionName": "web"}], "hostnames": ["legacy.shop.test"],
      "rules": [{"backendRefs": [{"name": "old", "port": 80, "weight": 0}]}]}
  }
}`

func uiState(t *testing.T, in UIInput) obj {
	t.Helper()
	var snap obj
	if err := json.Unmarshal([]byte(uiSnap), &snap); err != nil {
		t.Fatal(err)
	}
	st, err := BuildUIState(snap, in)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func routeByName(st obj, name string) obj {
	for _, r := range asList(st["routes"]) {
		if asMap(r)["name"] == name {
			return asMap(r)
		}
	}
	return nil
}

func TestUIStateOverviewAndFindings(t *testing.T) {
	st := uiState(t, UIInput{Mode: "snapshot", Source: "demo.json"})
	sm := asMap(st["summary"])
	if st["schema"] != UIStateSchema || sm["status"] != "attention" || sm["headline"] != "1 route needs attention" ||
		sm["routes"] != 2 || sm["gateways"] != 1 || sm["listeners"] != 1 || sm["backends"] != 3 {
		t.Fatalf("summary %v", sm)
	}
	legacy := routeByName(st, "legacy")
	fs := asList(legacy["findings"])
	if legacy["status"] != "attention" || len(fs) != 1 {
		t.Fatalf("legacy %v", legacy)
	}
	f := asMap(fs[0])
	if f["id"] != "SET002" || f["title"] == "" || f["why"] == "" || !strings.Contains(asStr(f["fix"]), "weight") {
		t.Fatalf("finding must carry plain-language title, reason and fix: %v", f)
	}
	if o := routeByName(st, "orders"); o["status"] != "ok" || len(asList(o["findings"])) != 0 {
		t.Fatalf("orders %v", o)
	}
	for _, absent := range []string{"health", "history", "traffic", "reload"} {
		if _, ok := st[absent]; ok {
			t.Errorf("%s must be absent when there is no data", absent)
		}
	}
}

func TestUIStateHealthyHeadline(t *testing.T) {
	var snap obj
	json.Unmarshal([]byte(uiSnap), &snap)
	delete(asMap(snap["resources"]), "httproutes.gateway.networking.k8s.io/legacy")
	st, _ := BuildUIState(snap, UIInput{})
	if h := asMap(st["summary"])["headline"]; h != "All routes healthy" || asMap(st["summary"])["status"] != "ok" {
		t.Fatalf("headline %v", h)
	}
}

func TestUIStateSplitsMatchesAndNoSecrets(t *testing.T) {
	st := uiState(t, UIInput{})
	raw, _ := json.Marshal(st)
	for _, secret := range []string{"hunter2", "Bearer"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("state leaks %q: %s", secret, raw)
		}
	}
	rule := asMap(asList(routeByName(st, "orders")["rules"])[0])
	if m := asStr(asList(rule["matches"])[0]); m != "path starts with /checkout · GET" {
		t.Fatalf("match text %q", m)
	}
	if f := asStr(asMap(asList(rule["filters"])[0])["text"]); !strings.Contains(f, "Authorization") || !strings.Contains(f, "values hidden") {
		t.Fatalf("filter text %q", f)
	}
	bs := asList(rule["backends"])
	if s1, s2 := fnum(asMap(bs[0])["share"]), fnum(asMap(bs[1])["share"]); s1 != 0.9 || s2 < 0.099 || s2 > 0.101 {
		t.Fatalf("shares %v %v", s1, s2)
	}
	zero := asMap(asList(asMap(asList(routeByName(st, "legacy")["rules"])[0])["backends"])[0])
	if zero["share"] != 0.0 {
		t.Fatalf("all-zero weights must not divide by zero: %v", zero)
	}
}

func TestUIStateTrafficAndOptionalSections(t *testing.T) {
	stats := map[string]any{"requests": 100, "unmatched": 2,
		"routes":   map[string]any{"shop/orders": map[string]any{"requests": 98, "status": map[string]any{"2xx": 90, "5xx": 8}}},
		"backends": map[string]any{"shop/v1:80": map[string]any{"requests": 88, "status": map[string]any{}}, "shop/v2:80": map[string]any{"requests": 10, "status": map[string]any{}}}}
	health := map[string]any{"targets": []any{map[string]any{"url": "https://x.test/", "ok": false}}}
	hist := map[string]any{"series": []any{map[string]any{"name": "p95", "points": []any{1, 2}}}}
	st := uiState(t, UIInput{Stats: stats, Health: health, History: hist, Reload: map[string]any{"generation": 3, "ok": true}})
	o := routeByName(st, "orders")
	if tr := asMap(o["traffic"]); tr["requests"] != 98.0 || tr["errors"] != 8.0 {
		t.Fatalf("route traffic %v", tr)
	}
	b0 := asMap(asList(asMap(asList(o["rules"])[0])["backends"])[0])
	if b0["requests"] != 88.0 {
		t.Fatalf("backend requests %v", b0)
	}
	if asMap(st["traffic"])["requests"] != 100.0 {
		t.Fatal("top-level traffic")
	}
	for _, k := range []string{"health", "history", "reload"} {
		if st[k] == nil {
			t.Errorf("%s should be present", k)
		}
	}
	// A failing probe target also demands attention.
	var snap obj
	json.Unmarshal([]byte(uiSnap), &snap)
	delete(asMap(snap["resources"]), "httproutes.gateway.networking.k8s.io/legacy")
	st2, _ := BuildUIState(snap, UIInput{Health: health})
	if asMap(st2["summary"])["status"] != "attention" {
		t.Fatal("failing health target should flip the status")
	}
}

func TestUIStateWatchMode(t *testing.T) {
	st, err := BuildUIState(nil, UIInput{Mode: "watch"})
	if err != nil || asMap(st["summary"])["status"] != "unknown" {
		t.Fatalf("before first probe: %v %v", st["summary"], err)
	}
	b := newHealthBoard()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Setura-Backend", "v1") }))
	defer srv.Close()
	r, err := Probe(NewProbe(srv.URL + "/"))
	if err != nil || !r.OK {
		t.Fatalf("probe: %v %v", r, err)
	}
	b.Record(r, time.Now())
	st = watchUIState(b, false)().(obj)
	if h := asMap(st["summary"])["headline"]; h != "All targets passing" {
		t.Fatalf("headline %v", h)
	}
	if n := len(asList(asMap(st["health"])["targets"])); n != 1 {
		t.Fatalf("targets %d", n)
	}
}

func TestUIStateRedactAndScrub(t *testing.T) {
	st := uiState(t, UIInput{Redact: true})
	raw, _ := json.Marshal(st)
	for _, leak := range []string{"orders.shop.test", "legacy.shop.test", "*.shop.test"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("redacted state still contains %q", leak)
		}
	}
	if st["schema"] != UIStateSchema || !strings.HasPrefix(asStr(st["generated"]), "20") {
		t.Fatal("structural fields must not be masked")
	}
	cleaned := scrub(obj{"ok": "v", "apiToken": "x", "nested": obj{"Password": "p", "keep": "k"}, "list": []any{obj{"secretKey": "s"}}}, false)
	b, _ := json.Marshal(cleaned)
	if strings.Contains(string(b), "apiToken") || strings.Contains(string(b), "Password") || strings.Contains(string(b), "secretKey") || !strings.Contains(string(b), `"keep":"k"`) {
		t.Fatalf("scrub: %s", b)
	}
}

func TestUIProviderEventsAndErrors(t *testing.T) {
	hub := webui.NewHub(50)
	var snap obj
	json.Unmarshal([]byte(uiSnap), &snap)
	fail := false
	p := &uiProvider{hub: hub,
		load: func() (obj, error) {
			if fail {
				return nil, userError("boom")
			}
			return snap, nil
		},
		build: func(s obj) (obj, error) { return BuildUIState(s, UIInput{Mode: "snapshot"}) }}
	if p.State() != nil {
		t.Fatal("no state before first refresh")
	}
	if err := p.refresh(); err != nil || p.State() == nil {
		t.Fatal(err)
	}
	fail = true
	if err := p.refresh(); err == nil {
		t.Fatal("expected error")
	}
	st := p.State().(obj)
	if asMap(st["error"])["message"] != "boom" || len(asList(st["routes"])) != 2 {
		t.Fatalf("last good data must survive an error: %v", st["error"])
	}
	fail = false
	p.refresh()
	if p.State().(obj)["error"] != nil {
		t.Fatal("error should clear on recovery")
	}
	evs := hub.Since(0)
	var warned bool
	for _, e := range evs {
		warned = warned || (e.Level == "warn" && strings.Contains(e.Text, "boom"))
	}
	if !warned {
		t.Fatalf("expected a warning event, got %+v", evs)
	}
}

func TestUICommandRules(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main([]string{"ui", "--listen", "0.0.0.0:0", "--snapshot", "x.json"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "--token") {
		t.Fatalf("non-loopback without token: %d %q", code, errb.String())
	}
	errb.Reset()
	if code := Main([]string{"ui", "--snapshot", filepath.Join(t.TempDir(), "missing.json")}, &out, &errb); code == 0 {
		t.Fatal("missing snapshot must fail fast")
	}
	errb.Reset()
	if code := Main([]string{"ui", "--kube", "--snapshot", "x"}, &out, &errb); code != 2 {
		t.Fatalf("conflicting flags: %d", code)
	}
	errb.Reset()
	bad := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(bad, []byte(uiSnap), 0o600)
	if code := Main([]string{"ui", "--snapshot", bad, "--interval", "10ms"}, &out, &errb); code != 2 {
		t.Fatalf("interval floor: %d %q", code, errb.String())
	}
}

func TestUIListedInHelpAndCompletion(t *testing.T) {
	var out bytes.Buffer
	writeHelp(&out, newUI(false, termOptions{}, func(string) string { return "" }))
	if !strings.Contains(out.String(), "ui [--listen ADDR]") {
		t.Error("help lacks ui")
	}
	var c bytes.Buffer
	Completion("bash", &c)
	if !strings.Contains(c.String(), " ui ") {
		t.Error("completion lacks ui")
	}
	var m bytes.Buffer
	Man(&m)
	if !strings.Contains(m.String(), "ui") {
		t.Error("man lacks ui")
	}
}
