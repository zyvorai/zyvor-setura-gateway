package setura

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const whyConfig = `{"schema":"setura.route-specs/v1","namespace":"demo","resources":{
"gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"web","protocol":"HTTP","port":8080}]},
"httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"hostnames":["a.test"],"rules":[
{"matches":[{"path":{"type":"PathPrefix","value":"/api"}}],"backendRefs":[{"name":"v1","port":80,"weight":3},{"name":"v2","port":80,"weight":1}]}]}},
"backends":{"v1":"127.0.0.1:9","v2":"127.0.0.1:9"}}`

func TestWhyCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gw.json")
	if err := os.WriteFile(path, []byte(whyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Main(args, &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, _ := run("why", "GET", "http://a.test:8080/api/x", "-H", "X-A: 1", "--config", path, "--ascii")
	if code != 0 || !strings.Contains(out, " 75.0%  v1") || !strings.Contains(out, "Routed") {
		t.Fatalf("code %d\n%s", code, out)
	}
	code, out, _ = run("why", "GET", "http://a.test:8080/other", "--config", path, "--format", "json")
	var tr map[string]any
	if code != 1 || json.Unmarshal([]byte(out), &tr) != nil || tr["verdict"] != "no-route" {
		t.Fatalf("code %d\n%s", code, out)
	}
	if code, _, _ = run("why", "GET", "http://a.test:8080/"); code != 2 {
		t.Fatalf("missing source: code %d", code)
	}
	if code, _, _ = run("why", "GET", "ftp://x", "--config", path); code != 2 {
		t.Fatalf("bad URL: code %d", code)
	}
}
