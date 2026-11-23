package gateway

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/zyvor-setura-gateway/internal/contract"
)

const ordersSpec = `{"openapi":"3.0.3","info":{"title":"o","version":"1"},"paths":{
 "/orders":{"get":{"responses":{"200":{"description":"ok"}}},"post":{"responses":{"201":{"description":"ok"}}}},
 "/orders/{id}":{"get":{"responses":{"200":{"description":"ok"}}}}}}`

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func accessLines(t *testing.T, b *syncBuf) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("bad log line %q: %v", ln, err)
		}
		out = append(out, m)
	}
	return out
}

func TestLearnRecordsInventoryWithoutSecrets(t *testing.T) {
	be, _ := upstreams(t, "a")
	r := rule("/", ref("a", 1))
	r[authKeyT] = m{"apiKey": m{"header": "X-Api-Key", "keys": l{m{"name": "ci", "key": "s3cret-key-value"}}}}
	file := filepath.Join(t.TempDir(), "inv.json")
	s := startServer(t, snap(httpGateway(""), map[string]m{"orders": route("a.test", r)}, be), func(o *Options) {
		o.LearnFile = file
		o.AccessLog = &syncBuf{}
	})
	hdr := []string{"X-Api-Key", "s3cret-key-value", "X-Tenant", "top-secret-tenant", "Accept", "application/json"}
	for _, p := range []string{"/orders/1", "/orders/2?q=TOPSECRETQ&limit=5", "/orders/3"} {
		if rp := get(t, s, "a.test", p, hdr...); rp.Status != 200 {
			t.Fatalf("%s: %d %s", p, rp.Status, rp.Body)
		}
	}
	get(t, s, "a.test", "/orders/9") // no key: 401, still an endpoint served by a protected rule
	rp := req(t, client(s.Addr(8080), nil), "http", "POST", "a.test", "/orders", `{"pw":"BODYSECRET"}`, append(hdr, "Content-Type", "application/json")...)
	if rp.Status != 200 {
		t.Fatalf("post %d", rp.Status)
	}
	s.FlushAccessLog()
	doc := s.Inventory()
	var got, post *contract.Endpoint
	for _, e := range doc.Endpoints {
		switch e.Key() {
		case "GET /orders/{id}":
			got = e
		case "POST /orders":
			post = e
		}
	}
	if got == nil || post == nil || len(doc.Endpoints) != 2 {
		t.Fatalf("endpoints: %+v", doc.Endpoints)
	}
	if got.Count != 4 || got.Status["200"] != 3 || got.Status["401"] != 1 {
		t.Errorf("counts %+v", got)
	}
	if strings.Join(got.Query, ",") != "limit,q" || !contains(got.Headers, "x-tenant") || !contains(got.Headers, "x-api-key") || contains(got.Headers, "accept") {
		t.Errorf("names: q=%v h=%v", got.Query, got.Headers)
	}
	if got.Routes["t/orders"] != 4 || len(got.Backends) == 0 || got.Auth.Protected != 4 || got.Auth.Open != 0 {
		t.Errorf("route/backend/auth: %+v", got)
	}
	if len(got.ResponseTypes) != 1 || post.RequestTypes["application/json"] != 1 || post.RequestBytes.N != 1 || got.Latency.N != 4 {
		t.Errorf("types/sizes: %+v %+v", got, post)
	}
	b, _ := json.Marshal(doc)
	for _, secret := range []string{"s3cret-key-value", "top-secret-tenant", "TOPSECRETQ", "BODYSECRET"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("inventory leaks %q", secret)
		}
	}
	// persisted on close, resumed by the next server
	s.Close()
	saved, err := contract.ReadDoc(file)
	if err != nil || len(saved.Endpoints) != 2 {
		t.Fatalf("saved: %v %+v", err, saved)
	}
	s2 := startServer(t, snap(httpGateway(""), map[string]m{"orders": route("a.test", r)}, be), func(o *Options) { o.LearnFile = file })
	if _, reqs, _ := s2.contract.learn.Stats(); reqs != 5 {
		t.Errorf("resumed %d requests", reqs)
	}
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func TestLearnIgnoresUnroutedAndIsBounded(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), func(o *Options) {
		o.LearnFile = filepath.Join(t.TempDir(), "i.json")
		o.LearnMax = 3
	})
	get(t, s, "nohost.test", "/x") // no route
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e"} {
		get(t, s, "a.test", p)
	}
	s.FlushAccessLog()
	d := s.Inventory()
	if len(d.Endpoints) != 3 || d.DroppedRequests != 2 {
		t.Fatalf("%d endpoints, %d dropped", len(d.Endpoints), d.DroppedRequests)
	}
}

func TestLearnAdminToggle(t *testing.T) {
	be, _ := upstreams(t, "a")
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), func(o *Options) { o.Admin = "127.0.0.1:0" })
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	adm := "http://" + s.AdminAddr()
	call := func(method, path string) (int, string) {
		rq, _ := http.NewRequest(method, adm+path, nil)
		resp, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	get(t, s, "a.test", "/before/1")
	s.FlushAccessLog()
	if n := len(s.Inventory().Endpoints); n != 0 {
		t.Fatalf("recorded while off: %d", n)
	}
	if code, body := call("POST", "/contract/learn?enabled=true"); code != 200 || !strings.Contains(body, `"enabled": true`) {
		t.Fatalf("enable: %d %s", code, body)
	}
	get(t, s, "a.test", "/after/1")
	s.FlushAccessLog()
	code, body := call("GET", "/contract")
	doc, err := contract.ParseDoc([]byte(body))
	if code != 200 || err != nil || len(doc.Endpoints) != 1 || doc.Endpoints[0].Path != "/after/{id}" {
		t.Fatalf("/contract: %d %v %s", code, err, body)
	}
	if code, _ := call("POST", "/contract/learn?enabled=false"); code != 200 || s.contract.learn.Enabled() {
		t.Fatal("disable failed")
	}
	if code, _ := call("POST", "/contract/learn?enabled=maybe"); code != 400 {
		t.Errorf("bad value: %d", code)
	}
	if code, _ := call("DELETE", "/contract/learn"); code != 405 {
		t.Errorf("method: %d", code)
	}
	if code, body := call("GET", "/contract/status"); code != 200 || !strings.Contains(body, `"learning"`) {
		t.Errorf("status: %d %s", code, body)
	}
}

func enforceServer(t *testing.T, mode string, rules ...m) (*Server, *syncBuf, *upstream) {
	t.Helper()
	be, ups := upstreams(t, "a")
	if len(rules) == 0 {
		rules = []m{rule("/", ref("a", 1))}
	}
	var log syncBuf
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rules...)}, be), func(o *Options) {
		o.ContractSpec, o.ContractEnforce, o.AccessLog = writeTemp(t, "spec.json", ordersSpec), mode, &log
	})
	return s, &log, ups["a"]
}

func TestContractMonitorCountsAndPasses(t *testing.T) {
	s, log, up := enforceServer(t, "monitor")
	if r := get(t, s, "a.test", "/orders/5"); r.Status != 200 {
		t.Fatalf("documented: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/secret-admin"); r.Status != 200 { // monitor never blocks
		t.Fatalf("monitor blocked: %d", r.Status)
	}
	if r := req(t, client(s.Addr(8080), nil), "http", "DELETE", "a.test", "/orders", ""); r.Status != 200 {
		t.Fatalf("monitor blocked method: %d", r.Status)
	}
	if len(up.seen()) != 3 {
		t.Errorf("upstream saw %d", len(up.seen()))
	}
	s.FlushAccessLog()
	var bad []string
	for _, ln := range accessLines(t, log) {
		if c, _ := ln["contract"].(string); c != "" {
			bad = append(bad, ln["path"].(string)+" "+c+" "+ln["contract_mode"].(string))
		}
	}
	if strings.Join(bad, "|") != "/secret-admin unknown_endpoint monitor|/orders unknown_method monitor" {
		t.Errorf("log fields: %v", bad)
	}
	var buf bytes.Buffer
	s.WriteMetrics(&buf)
	for _, w := range []string{`setura_gateway_contract_unknown_total{route="t/r",reason="unknown_endpoint",mode="monitor"} 1`,
		`setura_gateway_contract_unknown_total{route="t/r",reason="unknown_method",mode="monitor"} 1`, `setura_gateway_contract_spec_operations 3`} {
		if !strings.Contains(buf.String(), w) {
			t.Errorf("metrics missing %q", w)
		}
	}
}

func TestContractBlock(t *testing.T) {
	s, log, up := enforceServer(t, "block")
	if r := get(t, s, "a.test", "/orders"); r.Status != 200 {
		t.Fatalf("documented: %d", r.Status)
	}
	r := get(t, s, "a.test", "/nope/1")
	if r.Status != 404 || !strings.Contains(r.Body, "API contract") {
		t.Fatalf("unknown path: %d %s", r.Status, r.Body)
	}
	r = req(t, client(s.Addr(8080), nil), "http", "DELETE", "a.test", "/orders/7", "")
	if r.Status != 405 || r.Header.Get("Allow") != "GET" {
		t.Fatalf("unknown method: %d %v", r.Status, r.Header)
	}
	if n := len(up.seen()); n != 1 {
		t.Errorf("blocked requests reached the backend (%d)", n)
	}
	s.FlushAccessLog()
	lines := accessLines(t, log)
	if l := lines[1]; l["status"].(float64) != 404 || l["contract"] != "unknown_endpoint" || l["contract_mode"] != "block" || !strings.HasPrefix(l["error"].(string), "contract:") {
		t.Errorf("log %v", l)
	}
}

func TestContractPerRouteOverride(t *testing.T) {
	loose := rule("/open", ref("a", 1))
	loose[ContractKey] = "off"
	strict := rule("/", ref("a", 1))
	s, _, _ := enforceServer(t, "block", loose, strict)
	if r := get(t, s, "a.test", "/open/anything"); r.Status != 200 {
		t.Errorf("route with contract off: %d", r.Status)
	}
	if r := get(t, s, "a.test", "/other"); r.Status != 404 {
		t.Errorf("default block: %d", r.Status)
	}
	// without a default mode a rule can opt in on its own
	be, _ := upstreams(t, "a")
	in := rule("/", ref("a", 1))
	in[ContractKey] = "block"
	s2 := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", in)}, be), func(o *Options) { o.ContractSpec = writeTemp(t, "s.json", ordersSpec) })
	if r := get(t, s2, "a.test", "/zzz"); r.Status != 404 {
		t.Errorf("opt-in: %d", r.Status)
	}
	// an invalid mode is a config error, never silent
	bad := rule("/", ref("a", 1))
	bad[ContractKey] = "strict"
	s3 := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", bad)}, be), nil)
	if r := get(t, s3, "a.test", "/"); r.Status == 200 {
		t.Error("route with an invalid contract mode was served")
	}
	if b, _ := json.Marshal(s3.Status()); !strings.Contains(string(b), ContractKey) {
		t.Errorf("status does not name the bad annotation: %s", b)
	}
}

func TestContractAnnotationAndSpecReload(t *testing.T) {
	rules := []Rule{{}, {}}
	annotateContract(rules, map[string]string{ContractKey: "monitor", ContractKey + ".rule-2": " block "})
	if rules[0].Contract != "monitor" || rules[1].Contract != "block" {
		t.Errorf("%+v", rules)
	}
	s, _, _ := enforceServer(t, "block")
	if r := get(t, s, "a.test", "/new"); r.Status != 404 {
		t.Fatalf("before reload: %d", r.Status)
	}
	next := strings.Replace(ordersSpec, `"/orders/{id}"`, `"/new":{"get":{"responses":{"200":{"description":"ok"}}}},"/orders/{id}"`, 1)
	os.WriteFile(s.contract.specFile, []byte(next), 0o600)
	s.reloadSpec(false)
	if r := get(t, s, "a.test", "/new"); r.Status != 200 {
		t.Errorf("after reload: %d", r.Status)
	}
	os.WriteFile(s.contract.specFile, []byte(`{broken`), 0o600) // a broken file keeps the last good spec
	s.reloadSpec(false)
	if r := get(t, s, "a.test", "/new"); r.Status != 200 {
		t.Errorf("broken reload dropped the spec: %d", r.Status)
	}
	if st := s.ContractStatus(); st.Enforcement.Error == "" || st.Enforcement.Operations != 4 {
		t.Errorf("status %+v", st.Enforcement)
	}
}

func TestContractFlagValidation(t *testing.T) {
	spec := writeTemp(t, "s.json", ordersSpec)
	for name, c := range map[string]struct {
		args []string
		bad  string
	}{
		"enforce needs spec": {[]string{"--contract-enforce", "block"}, "needs --contract-spec"},
		"bad mode":           {[]string{"--contract-spec", spec, "--contract-enforce", "strict"}, "want monitor or block"},
		"bad spec":           {[]string{"--contract-spec", filepath.Join(t.TempDir(), "none.json")}, "--contract-spec"},
		"bad max":            {[]string{"--learn-max", "-1"}, "--learn-max"},
		"ok":                 {[]string{"--contract-spec", spec, "--contract-enforce", "monitor", "--learn", filepath.Join(t.TempDir(), "i.json")}, ""},
	} {
		var rf runFlags
		fs := newContractFlagSet()
		addRunFlags(fs, &rf)
		if err := fs.Parse(c.args); err != nil {
			t.Fatal(err)
		}
		_, err := rf.finish(io.Discard, io.Discard, nil)
		if (c.bad == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.bad)) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func newContractFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}
