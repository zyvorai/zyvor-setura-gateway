package setura

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prSnap(rules ...obj) string {
	b, _ := json.Marshal(obj{"schema": "setura.route-specs/v1", "namespace": "shop", "resources": obj{
		"gateways.gateway.networking.k8s.io/gw":    obj{"gatewayClassName": "setura", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 8080}}},
		"httproutes.gateway.networking.k8s.io/web": obj{"parentRefs": []any{obj{"name": "gw"}}, "hostnames": []any{"shop.test"}, "rules": rules},
	}, "backends": obj{"a": "127.0.0.1:9", "b": "127.0.0.1:9", "c": "127.0.0.1:9"}})
	return string(b)
}

func prRule(path, backend string, extra obj) obj {
	r := obj{"matches": []any{obj{"path": obj{"type": "PathPrefix", "value": path}}}, "backendRefs": []any{obj{"name": backend, "port": 80}}}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

func prFiles(t *testing.T) (dir, base, head, traffic string) {
	t.Helper()
	dir = t.TempDir()
	base = filepath.Join(dir, "base")
	head = filepath.Join(dir, "head")
	os.MkdirAll(base, 0o755)
	os.MkdirAll(head, 0o755)
	os.WriteFile(filepath.Join(base, "gateway.json"), []byte(prSnap(
		prRule("/api", "a", nil), prRule("/old", "a", nil), prRule("/gone", "b", nil), prRule("/static", "c", nil), prRule("/v1", "a", nil))), 0o644)
	redirect := obj{"filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"statusCode": 301, "path": obj{"type": "ReplaceFullPath", "replaceFullPath": "/new"}}}}, "backendRefs": nil}
	os.WriteFile(filepath.Join(head, "gateway.json"), []byte(prSnap(
		prRule("/api", "b", nil),
		obj{"matches": []any{obj{"path": obj{"type": "PathPrefix", "value": "/old"}}}, "filters": redirect["filters"]},
		prRule("/static", "c", nil),
		prRule("/v1", "a", obj{"filters": []any{obj{"type": "URLRewrite", "urlRewrite": obj{"path": obj{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2"}}}},
			"setura.zyvor.dev/auth": obj{"apiKey": obj{"keys": []any{obj{"name": "k", "hash": "sha256$AAAA$" + strings.Repeat("0", 64)}}}}}))), 0o644)
	var sb strings.Builder
	add := func(n int, path string) {
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, `{"host":"shop.test","method":"GET","path":"%s/%d","status":200}`+"\n", path, i)
		}
	}
	add(40, "/api")    // backend a -> b
	add(10, "/old")    // routed -> 301
	add(10, "/gone")   // routed -> 404
	add(30, "/static") // unchanged
	add(10, "/v1")     // rewrite + auth
	traffic = filepath.Join(dir, "traffic.jsonl")
	os.WriteFile(traffic, []byte(sb.String()), 0o644)
	return
}

func TestPRCheckImpact(t *testing.T) {
	_, base, head, traffic := prFiles(t)
	rep, err := PRCheck(PRCheckOptions{Base: base, Head: head, Traffic: traffic, Limit: 2, FailOver: 50, FailOverSet: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Input.Requests != 100 {
		t.Fatalf("requests %d", rep.Input.Requests)
	}
	get := func(name string) PRClass {
		for _, c := range rep.Classes {
			if c.Name == name {
				return c
			}
		}
		t.Fatalf("no class %s", name)
		return PRClass{}
	}
	for name, want := range map[string]int64{prBackend: 40, prRedirect: 10, prTo404: 10, prRoute: 10, prRewrite: 10, prAuth: 10, prWeights: 0} {
		if got := get(name).Requests; got != want {
			t.Errorf("%s: %d requests, want %d", name, got, want)
		}
	}
	// api (40) + old (10) + gone (10) + v1 rewrite (10) = 70 routing changes; static is untouched
	if rep.ChangedRequests != 70 || rep.ChangedPercent != 70 {
		t.Errorf("changed %d (%.2f%%), want 70", rep.ChangedRequests, rep.ChangedPercent)
	}
	if !rep.Failed || rep.Threshold == nil {
		t.Errorf("70%% over a limit of 50%% must fail")
	}
	ex := get(prRewrite).Examples
	if len(ex) != 1 || !strings.Contains(ex[0].After, "rewrite path /v1/") || !strings.Contains(ex[0].After, "/v2/") || !strings.Contains(ex[0].After, "auth apiKey") {
		t.Errorf("rewrite example: %+v", ex)
	}
	if ex := get(prTo404).Examples; len(ex) == 0 || !strings.Contains(ex[0].After, "404") {
		t.Errorf("404 example: %+v", ex)
	}
	var share *PRRoute
	for i := range rep.Routes {
		if rep.Routes[i].Route == "(404 no route)" {
			share = &rep.Routes[i]
		}
	}
	if share == nil || share.Before != 0 || share.After != 10 || share.DeltaPoints != 10 {
		t.Errorf("404 share: %+v", share)
	}
}

func TestPRCheckNewAndRemovedRoutes(t *testing.T) {
	dir := t.TempDir()
	one := prSnap(prRule("/", "a", nil))
	two := strings.Replace(one, `"httproutes.gateway.networking.k8s.io/web"`, `"httproutes.gateway.networking.k8s.io/other"`, 1)
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(one), 0o644)
	os.WriteFile(filepath.Join(dir, "b.json"), []byte(two), 0o644)
	tr := filepath.Join(dir, "t.jsonl")
	os.WriteFile(tr, []byte(`{"host":"shop.test","method":"GET","path":"/x","status":200}`+"\n"), 0o644)
	rep, err := PRCheck(PRCheckOptions{Base: filepath.Join(dir, "a.json"), Head: filepath.Join(dir, "b.json"), Traffic: tr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NewRoutes) != 1 || rep.NewRoutes[0].Route != "shop/other" || rep.NewRoutes[0].Requests != 1 ||
		len(rep.RemovedRoutes) != 1 || rep.RemovedRoutes[0].Route != "shop/web" || rep.RemovedRoutes[0].Requests != 1 {
		t.Errorf("new %+v removed %+v", rep.NewRoutes, rep.RemovedRoutes)
	}
	if rep.ChangedRequests != 1 {
		t.Errorf("a renamed route is a route change: %d", rep.ChangedRequests)
	}
}

func TestPRCheckNoChange(t *testing.T) {
	_, base, _, traffic := prFiles(t)
	rep, err := PRCheck(PRCheckOptions{Base: base, Head: base, Traffic: traffic, FailOver: 0, FailOverSet: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ChangedRequests != 0 || rep.Failed {
		t.Errorf("identical configs: %+v", rep)
	}
	if !strings.Contains(PRCheckMarkdown(rep, 3), "No change.") {
		t.Error("markdown must say no change")
	}
}

func TestPRCheckRateLimitTighter(t *testing.T) {
	_, base, _, traffic := prFiles(t)
	rep, err := PRCheck(PRCheckOptions{Base: base, Head: base, Traffic: traffic, BaseRate: "100/s", HeadRate: "10/s"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rc PRClass
	for _, c := range rep.Classes {
		if c.Name == prRate {
			rc = c
		}
	}
	if rc.Requests == 0 || !strings.Contains(rc.Title, "429") || rep.ChangedRequests != 0 {
		t.Errorf("tighter limit: %+v changed %d", rc, rep.ChangedRequests)
	}
	rep, _ = PRCheck(PRCheckOptions{Base: base, Head: base, Traffic: traffic, BaseRate: "10/s", HeadRate: "100/s"}, nil)
	for _, c := range rep.Classes {
		if c.Name == prRate && strings.Contains(c.Title, "tighter limit can") {
			t.Errorf("a looser limit must not promise 429s: %s", c.Title)
		}
	}
}

func TestPRCheckCommand(t *testing.T) {
	_, base, head, traffic := prFiles(t)
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Main(append([]string{"pr-check"}, args...), &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, _ := run("--base", base, "--head", head, "--traffic", traffic, "--format", "json", "--fail-if-changed-over", "5")
	var doc PRCheckReport
	if code != 1 || json.Unmarshal([]byte(out), &doc) != nil || doc.Schema != prSchema || doc.ChangedPercent != 70 || !doc.Failed {
		t.Fatalf("json: code %d\n%s", code, out)
	}
	if code, _, _ := run("--base", base, "--head", head, "--traffic", traffic, "--format", "json", "--fail-if-changed-over", "70"); code != 0 {
		t.Errorf("exactly at the limit must pass, code %d", code)
	}
	code, out, _ = run("--base", base, "--head", head, "--traffic", traffic, "--format", "markdown")
	for _, want := range []string{prMarkerTag, "### Traffic impact", "70 of 100 recorded requests (70.00%)", "| Impact | Requests | Share |", "<details>", "would turn into 404"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q:\n%s", want, out)
		}
	}
	if code != 0 {
		t.Errorf("markdown without a limit: code %d", code)
	}
	code, out, _ = run("--base", base, "--head", head, "--traffic", traffic, "--format", "table", "--ascii")
	if code != 0 || !strings.Contains(out, "Traffic share per route") || !strings.Contains(out, "(404 no route)") {
		t.Errorf("table: code %d\n%s", code, out)
	}
	for _, args := range [][]string{{"--base", base}, {"--base", base, "--head", head, "--traffic", traffic, "--fail-if-changed-over", "101"},
		{"--base", base, "--head", head, "--traffic", traffic, "--format", "xml"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: code %d, want 2", args, code)
		}
	}
	empty := filepath.Join(t.TempDir(), "e.jsonl")
	os.WriteFile(empty, []byte("garbage\n"), 0o644)
	if code, _, errs := run("--base", base, "--head", head, "--traffic", empty); code != 2 || !strings.Contains(errs, "no replayable requests") {
		t.Errorf("empty traffic: %d %s", code, errs)
	}
}

func TestResolveConfigPath(t *testing.T) {
	d := t.TempDir()
	if _, err := resolveConfigPath(d); err == nil {
		t.Error("empty directory must fail")
	}
	os.WriteFile(filepath.Join(d, "x.json"), []byte(prSnap()), 0o644)
	if p, err := resolveConfigPath(d); err != nil || filepath.Base(p) != "x.json" {
		t.Errorf("single snapshot: %q %v", p, err)
	}
	os.WriteFile(filepath.Join(d, "y.json"), []byte(prSnap()), 0o644)
	if _, err := resolveConfigPath(d); err == nil || !strings.Contains(err.Error(), "2 gateway configs") {
		t.Errorf("ambiguous: %v", err)
	}
	os.WriteFile(filepath.Join(d, "gateway.json"), []byte(prSnap()), 0o644)
	if p, _ := resolveConfigPath(d); filepath.Base(p) != "gateway.json" {
		t.Errorf("well known name wins: %q", p)
	}
}
