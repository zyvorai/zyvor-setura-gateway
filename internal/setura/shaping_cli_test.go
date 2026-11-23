package setura

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLintShapingRules(t *testing.T) {
	rl := func(shared obj, extra obj) obj {
		b := obj{"rate": "10/s", "shared": shared}
		for k, v := range extra {
			b[k] = v
		}
		return obj{"setura.zyvor.dev/rate-limit": b, "backendRefs": []any{obj{"name": "b", "port": 80}}}
	}
	ann := func(k, v string) obj { return obj{"setura.zyvor.dev/annotations": obj{k: v}} }
	withBackend := func(r obj) obj {
		if r["backendRefs"] == nil {
			r["backendRefs"] = []any{obj{"name": "b", "port": 80}}
		}
		return r
	}
	cases := []struct {
		name string
		rule obj
		spec obj
		want string // "" = no SET07x finding
	}{
		{"sound shared limit", rl(obj{"redis": "main"}, nil), nil, ""},
		{"fails closed", rl(obj{"failOpen": false}, nil), nil, "SET071"},
		{"no fallback", rl(obj{"fallback": "none"}, nil), nil, "SET071"},
		{"client chosen key", rl(obj{}, obj{"key": "header:X-Tenant"}), nil, "SET072"},
		{"compress brotli", withBackend(obj{"setura.zyvor.dev/compress": obj{"encodings": []any{"br"}}}), nil, "SET070"},
		{"compress unknown field", withBackend(obj{"setura.zyvor.dev/compress": obj{"nope": 1}}), nil, "SET070"},
		{"compress annotation", withBackend(obj{}), ann("setura.zyvor.dev/compress", `{"level":99}`), "SET070"},
		{"compress annotation names no rule", withBackend(obj{}), ann("setura.zyvor.dev/compress.rule-7", `{"enabled":true}`), "SET070"},
		{"compress image", withBackend(obj{"setura.zyvor.dev/compress": obj{"types": []any{"text/*", "image/png"}}}), nil, "SET073"},
		{"sound compress", withBackend(obj{"setura.zyvor.dev/compress": obj{"types": []any{"text/*", "*/*+json"}, "minSize": "1KB"}}), nil, ""},
		{"bandwidth invalid", withBackend(obj{"setura.zyvor.dev/bandwidth": obj{"response": "fast"}}), nil, "SET070"},
		{"sound bandwidth", withBackend(obj{"setura.zyvor.dev/bandwidth": obj{"response": "1MB/s"}}), nil, ""},
		{"grpc-web without cors", withBackend(obj{"setura.zyvor.dev/grpc-web": obj{}}), nil, "SET074"},
		{"grpc-web invalid", withBackend(obj{"setura.zyvor.dev/grpc-web": obj{"maxAge": -1}}), nil, "SET070"},
		{"grpc-web with origins", withBackend(obj{"setura.zyvor.dev/grpc-web": obj{"allowOrigins": []any{"https://app.test"}}}), nil, ""},
		{"grpc-web with retry", withBackend(obj{"setura.zyvor.dev/grpc-web": obj{"allowOrigins": []any{"*"}}, "retry": obj{"attempts": 2}}), nil, "SET075"},
	}
	for _, c := range cases {
		got := aiLint(t, c.rule, c.spec)
		var hit []string
		for id := range got {
			if strings.HasPrefix(id, "SET07") {
				hit = append(hit, id)
			}
		}
		switch {
		case c.want == "" && len(hit) != 0:
			t.Errorf("%s: unexpected %v %v", c.name, hit, got)
		case c.want != "" && len(got[c.want]) == 0:
			t.Errorf("%s: want %s, got %v", c.name, c.want, got)
		}
	}
	for _, id := range []string{"SET070", "SET071", "SET072", "SET073", "SET074", "SET075", "SET076"} {
		if _, ok := ruleHelp[id]; !ok {
			t.Errorf("%s has no help text", id)
		}
		found := false
		for _, r := range Rules {
			found = found || r.ID == id
		}
		if !found {
			t.Errorf("%s is not registered", id)
		}
	}
}

func TestLintListenerConnectionLimits(t *testing.T) {
	gw := func(lim obj) obj {
		return obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80, "setura.zyvor.dev/limits": lim}}}
	}
	check := func(lim obj) []string {
		rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{gateway + "/gw": gw(lim)}})
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, f := range asList(rep["findings"]) {
			ids = append(ids, asStr(asMap(f)["id"]))
		}
		return ids
	}
	if ids := check(obj{"maxConnections": 10, "maxConnectionsPerIP": 50}); !strings.Contains(strings.Join(ids, ","), "SET076") {
		t.Errorf("unreachable per-IP limit: %v", ids)
	}
	if ids := check(obj{"maxConnections": 100, "maxConnectionsPerIP": 5}); strings.Contains(strings.Join(ids, ","), "SET076") {
		t.Errorf("sound limits flagged: %v", ids)
	}
	if ids := check(obj{"maxConnections": -1}); !strings.Contains(strings.Join(ids, ","), "SET030") {
		t.Errorf("negative limit: %v", ids)
	}
}

func TestShapingFlagsHelpManCompletion(t *testing.T) {
	flags := []string{"--redis", "--redis-password-file", "--redis-tls", "--redis-ca", "--redis-timeout", "--redis-pool", "--compress", "--compress-types",
		"--compress-encodings", "--compress-min-size", "--compress-level", "--max-connections", "--max-connections-per-ip", "--tcp-keepalive-idle",
		"--tcp-keepalive-interval", "--tcp-keepalive-count", "--h2-max-streams", "--h2-initial-window", "--h2-max-frame-size", "--bandwidth-request",
		"--bandwidth-response", "--request-id"}
	var help, errb bytes.Buffer
	runGateway([]string{"--help"}, &help, &errb)
	for _, f := range flags {
		if !strings.Contains(help.String(), f) {
			t.Errorf("gateway --help lacks %s", f)
		}
		for _, sh := range []string{"bash", "zsh", "fish"} {
			var b bytes.Buffer
			Completion(sh, &b)
			if !strings.Contains(b.String(), strings.TrimPrefix(f, "--")) {
				t.Errorf("%s completion lacks %s", sh, f)
			}
		}
	}
	var man bytes.Buffer
	Man(&man)
	for _, w := range []string{"TRAFFIC SHAPING", "SET076", "brotli and zstd are not", "HTTP/3 is not served"} {
		if !strings.Contains(man.String(), w) {
			t.Errorf("man page lacks %q", w)
		}
	}
	for _, w := range []string{"X\\-RateLimit\\-Limit", "grpc\\-web"} {
		if !strings.Contains(man.String(), w) {
			t.Errorf("man page lacks %q", w)
		}
	}
}

func TestShapingFlagValidation(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "gw.json")
	os.WriteFile(cfg, []byte(`{"schema":"setura.route-specs/v1","resources":{}}`), 0o600)
	for name, args := range map[string][]string{
		"negative connections": {"--max-connections", "-1"},
		"keepalive off+idle":   {"--tcp-keepalive-off", "--tcp-keepalive-idle", "1s"},
		"h2 frame too small":   {"--h2-max-frame-size", "100"},
		"bad bandwidth":        {"--bandwidth-response", "fast"},
		"bad request id":       {"--request-id", "random"},
		"compress tuning only": {"--compress-level", "5"},
		"compress brotli":      {"--compress", "--compress-encodings", "br"},
		"compress level":       {"--compress", "--compress-level", "11"},
		"redis tls alone":      {"--redis-tls"},
		"redis garbage":        {"--redis", "http://x:1"},
		"redis twice":          {"--redis", "a=h:1", "--redis", "a=h:2"},
	} {
		var out, errb bytes.Buffer
		if code := runGateway(append([]string{"run", "--config", cfg, "--admin", "off"}, args...), &out, &errb); code != 2 {
			t.Errorf("%s: exit %d, %s", name, code, errb.String())
		}
	}
}
