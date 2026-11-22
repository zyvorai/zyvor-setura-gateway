package setura

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadSnapshot(t *testing.T) obj {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "topology.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return asMap(v)
}

func firstRule(s obj) obj {
	return asMap(asList(asMap(asMap(s["resources"])[route+"/orders"])["rules"])[0])
}

func TestWeightAndCrossNamespace(t *testing.T) {
	s := loadSnapshot(t)
	ref := asMap(asList(firstRule(s)["backendRefs"])[1])
	ref["namespace"], ref["weight"] = "preview", float64(0)
	g, err := BuildTopology(s)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := Impact(g, "Service/preview/orders-canary")
	is(t, r["dependent_routes"], "[]")
	r, _ = Impact(g, "Service/setura-demo/orders")
	is(t, r["dependent_routes"], "[HTTPRoute/setura-demo/orders]")
	if _, err := Impact(g, "Service/elsewhere/missing"); err == nil {
		t.Fatal("unknown node accepted")
	}
}

func TestUnscopedParentAndSharedBackend(t *testing.T) {
	s := loadSnapshot(t)
	raw, _ := json.Marshal(asMap(s["resources"])[route+"/orders"])
	var other obj
	json.Unmarshal(raw, &other)
	other["parentRefs"] = []any{obj{"name": "external", "namespace": "infra"}}
	asMap(s["resources"])[route+"/alt"] = other
	g, _ := BuildTopology(s)
	r, _ := Impact(g, "Service/setura-demo/orders")
	contains(t, strings.Join(r["upstream"].([]string), ","), "Gateway/infra/external")
	is(t, len(r["dependent_routes"].([]string)), 2)
}

func TestPageEscapesSpecContent(t *testing.T) {
	s := loadSnapshot(t)
	firstRule(s)["matches"] = []any{obj{"headers": []any{obj{"name": "x", "value": "</script><img/onerror=alert(1)>"}}}}
	g, _ := BuildTopology(s)
	page, err := Page(g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page, "</script><img") {
		t.Fatal("unescaped script terminator in rendered page")
	}
	if strings.Contains(page, "GRAPH_PAYLOAD") || strings.Contains(page, "NAMESPACE_LABEL") {
		t.Fatal("template placeholder left in page")
	}
}

func TestCLIMapImpactAndAI(t *testing.T) {
	s := loadSnapshot(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	raw, _ := json.Marshal(s)
	os.WriteFile(path, raw, 0o600)
	code, out, _ := cli(t, nil, "map", "--format", "json", "--snapshot", path)
	is(t, code, 0)
	var graph any
	json.Unmarshal([]byte(out), &graph)
	facts, err := Evidence(graph)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range facts {
		found = found || strings.Contains(f.Observation, "weight 10")
	}
	if !found {
		t.Fatal("no fact mentions weight 10")
	}
	code, impact, _ := cli(t, nil, "impact", "Service/setura-demo/orders", "--snapshot", path)
	is(t, code, 0)
	report := filepath.Join(dir, "impact.json")
	os.WriteFile(report, []byte(impact), 0o600)
	if code, _, errs := cli(t, nil, "ai", report); code != 0 {
		t.Fatalf("ai exit %d: %s", code, errs)
	}
	if code, page, _ := cli(t, nil, "map", "--snapshot", path); code != 0 || !strings.Contains(page, "<html") {
		t.Fatalf("html map exit %d", code)
	}
}

func TestDualTargetKeepsSubject(t *testing.T) {
	bad := obj{"ok": false, "steps": obj{"tls": obj{"state": "failed", "reason": "untrusted"}}}
	facts, err := Evidence(obj{"targets": obj{"dns": bad, "127.0.0.1": obj{"ok": true, "steps": obj{}}}})
	if err != nil {
		t.Fatal(err)
	}
	is(t, len(facts), 2)
	is(t, facts[0].ID+facts[1].ID, "E1E2")
	contains(t, facts[0].Subject, "127.0.0.1") // keys are sorted: 127.0.0.1 passes first or fails second, both labelled
	contains(t, facts[1].Subject, "dns")
	contains(t, *facts[1].NextCheck, "certificate")
}

func TestEvidenceOrderIsDeterministic(t *testing.T) {
	report := obj{"ok": false, "steps": obj{
		"http": obj{"state": "failed", "reason": "h"}, "dns": obj{"state": "failed", "reason": "d"}, "tcp": obj{"state": "failed", "reason": "t"}}}
	for i := 0; i < 20; i++ {
		facts, _ := Evidence(report)
		is(t, facts[0].Observation+"|"+facts[1].Observation+"|"+facts[2].Observation, "dns failed: d|tcp failed: t|http failed: h")
	}
}

func TestProviderRoundTripAndInvalidCitations(t *testing.T) {
	reply := `{"findings":[{"interpretation":"Check the TLS trust chain.","evidence_ids":["E1"]}]}`
	var path string
	var stream any
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		var body obj
		json.NewDecoder(r.Body).Decode(&body)
		stream = body["stream"]
		json.NewEncoder(w).Encode(obj{"message": obj{"content": reply}})
	}))
	srv.Start()
	defer srv.Close()
	port := srv.Listener.Addr().(interface{ String() string }).String()
	p := port[strings.LastIndex(port, ":")+1:]
	n := 0
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	facts := []Fact{{ID: "E1", Observation: "TLS trust failed"}}
	got, err := Interpret(facts, "What failed?", "test", n)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", err, got)
	}
	is(t, path, "/api/chat")
	is(t, stream, false)
	reply = `{"findings":[{"interpretation":"x","evidence_ids":["E9"]}]}`
	if _, err := Interpret(facts, "What failed?", "test", n); err == nil || !strings.Contains(err.Error(), "evidence IDs") {
		t.Fatalf("unknown citation accepted: %v", err)
	}
}

func TestGateReportsUnstableGeneration(t *testing.T) {
	facts, err := Evidence(obj{"ok": false, "attempts": []any{obj{"streak": 0, "parent": obj{"ok": true},
		"probe": obj{"ok": true, "steps": obj{}}, "confirmed_after_probe": false}}})
	if err != nil {
		t.Fatal(err)
	}
	contains(t, facts[len(facts)-1].Observation, "could not be confirmed")
}
