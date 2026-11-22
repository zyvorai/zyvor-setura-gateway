package setura

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func changesCfg(split int, extra bool) []byte {
	routes := obj{
		"httproutes.gateway.networking.k8s.io/orders": obj{
			"parentRefs": []any{obj{"name": "edge", "sectionName": "web"}},
			"hostnames":  []any{"orders.test"},
			"rules": []any{obj{
				"matches":     []any{obj{"path": obj{"type": "PathPrefix", "value": "/checkout"}}},
				"backendRefs": []any{obj{"name": "v1", "port": 80, "weight": 100 - split}, obj{"name": "v2", "port": 80, "weight": split}},
			}},
		},
	}
	backends := obj{"v1:80": obj{"endpoints": []any{"127.0.0.1:1"}}, "v2:80": obj{"endpoints": []any{"127.0.0.1:2"}}}
	if extra {
		routes["httproutes.gateway.networking.k8s.io/search"] = obj{
			"parentRefs": []any{obj{"name": "edge", "sectionName": "web"}},
			"hostnames":  []any{"search.test"},
			"rules":      []any{obj{"matches": []any{obj{"path": obj{"type": "PathPrefix", "value": "/"}}}, "backendRefs": []any{obj{"name": "s", "port": 80}}}},
		}
		backends["s:80"] = obj{"endpoints": []any{"127.0.0.1:3"}}
	}
	res := obj{"gateways.gateway.networking.k8s.io/edge": obj{"gatewayClassName": "setura", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 18080}}}}
	for k, v := range routes {
		res[k] = v
	}
	b, _ := json.Marshal(obj{"schema": "setura.route-specs/v1", "namespace": "shop", "resources": res, "backends": backends})
	return b
}

func TestPlainDiff(t *testing.T) {
	tests := []struct {
		name          string
		a, b          []byte
		kinds         []string // kind per change, in order
		titleContains []string
		lineContains  string
	}{
		{"identical", changesCfg(10, false), changesCfg(10, false), nil, nil, ""},
		{"weights", changesCfg(10, false), changesCfg(30, false), []string{"changed"}, []string{"Route orders changed"}, "v1 90% → 70%"},
		{"added", changesCfg(10, false), changesCfg(10, true), []string{"added", "added"}, []string{"Backend s:80 was added", "Route search was added"}, "Serves search.test"},
		{"removed", changesCfg(10, true), changesCfg(10, false), []string{"removed", "removed"}, []string{"Route search was removed"}, "Serves search.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := plainDiff(tt.a, tt.b)
			if err != nil {
				t.Fatal(err)
			}
			var kinds []string
			var all []string
			for _, c := range got {
				kinds = append(kinds, c.Kind)
				all = append(all, c.Title)
				all = append(all, c.Lines...)
			}
			if strings.Join(kinds, ",") != strings.Join(tt.kinds, ",") {
				t.Fatalf("kinds %v want %v", kinds, tt.kinds)
			}
			joined := strings.Join(all, "\n")
			for _, w := range append(tt.titleContains, tt.lineContains) {
				if !strings.Contains(joined, w) {
					t.Errorf("missing %q in\n%s", w, joined)
				}
			}
		})
	}
	if _, err := plainDiff([]byte("nope"), changesCfg(1, false)); err == nil {
		t.Error("invalid JSON must be an error")
	}
}

func TestChangesSourceDocAndDetail(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "live.json")
	if err := os.WriteFile(cfgPath, changesCfg(0, false), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newChangesSource(cfgPath)

	// No history yet: a friendly, actionable document.
	doc := asMap(c.Doc())
	if doc["available"] != true || !strings.Contains(asStr(doc["headline"]), "No rollouts") || !strings.Contains(asStr(doc["next"]), "setura gateway rollout") {
		t.Fatalf("empty history: %v", doc)
	}

	// Two rollouts: the backups hold the configs that were replaced.
	h := newHistStore(cfgPath)
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	m1, err := h.add(changesCfg(0, false), histMeta{Reason: "rollout", Generation: 1, LintOK: true, Diff: summarizeDiff(changesCfg(0, false), changesCfg(10, false))}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.add(changesCfg(10, false), histMeta{Reason: "rollout", Generation: 2, LintOK: true}, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The live file is now a later edit: 10 -> 40 with a new route.
	os.WriteFile(cfgPath, changesCfg(40, true), 0o600)
	doc = asMap(c.Doc())
	diff := asMap(doc["diff"])
	changes := diff["changes"].([]uiChange)
	if len(changes) != 3 || !strings.Contains(asStr(doc["headline"]), "3 changes since the last rollout") {
		t.Fatalf("diff: %v / %v", doc["headline"], changes)
	}
	tl := doc["timeline"].([]any)
	if len(tl) != 2 || asMap(tl[0])["generation"] != int64(2) {
		t.Fatalf("timeline: %v", tl)
	}
	if ch := asMap(tl[1])["changes"].([]uiChange); len(ch) != 1 || ch[0].Kind != "changed" {
		t.Errorf("what the first rollout changed: %v", ch)
	}
	if _, err := json.Marshal(doc); err != nil {
		t.Fatalf("document must be JSON: %v", err)
	}

	// The what-would-this-do view of the oldest backup.
	d, ok := c.Detail(m1.ID)
	if !ok {
		t.Fatal("no detail")
	}
	dm := asMap(d)
	if !strings.Contains(asStr(dm["command"]), "rollback --config live.json --to "+m1.ID) || dm["lintOk"] != true {
		t.Errorf("detail: %v", dm)
	}
	rep := asMap(dm["replay"])
	if rep == nil || rep["changed"].(int64) == 0 || !strings.Contains(asStr(rep["headline"]), "routed differently") {
		t.Fatalf("replay: %v", dm["replay"])
	}
	if !strings.Contains(asStr(dm["why"]), "orders") && !strings.Contains(asStr(dm["why"]), "search") {
		t.Errorf("why text missing: %q", dm["why"])
	}
	if _, ok := c.Detail("20990101T000000.000Z-deadbeef"); ok {
		t.Error("unknown id must not resolve")
	}

	// A live file identical to a backup: nothing would change.
	os.WriteFile(cfgPath, changesCfg(10, false), 0o600)
	if d, _ := c.Detail(asStr(asMap(c.Doc())["diff"].(obj)["from"].(obj)["id"])); !strings.Contains(asStr(asMap(d)["summary"]), "Nothing would change") {
		t.Errorf("identical: %v", d)
	}

	// Unreadable live configuration is explained, not an error page.
	os.Remove(cfgPath)
	if doc := asMap(c.Doc()); doc["available"] != false || !strings.Contains(asStr(doc["headline"]), "Cannot read") {
		t.Errorf("unreadable: %v", doc)
	}
}
