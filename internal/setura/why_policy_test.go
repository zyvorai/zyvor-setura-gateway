package setura

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWhyPolicyOutput(t *testing.T) {
	cfg := whyConfig
	cfg = strings.Replace(cfg, `"backendRefs":[{"name":"v1"`, `"retry":{"codes":[503],"attempts":2,"backoff":"20ms"},"backendRefs":[{"name":"v1"`, 1)
	path := filepath.Join(t.TempDir(), "gw.json")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Main(args, &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, errs := run("why", "POST", "http://a.test:8080/api/x", "--config", path, "--ascii", "--client-ip", "10.1.2.3",
		"--rate-limit", "5/s", "--rate-burst", "7", "--rate-key", "ip", "-H", "X-Forwarded-For: 9.9.9.9")
	for _, want := range []string{"rate limit 5 tokens/s, burst 7, key ip", "10.1.2.3", "retry up to 2 time(s)", "not idempotent", "X-Forwarded-For: 10.1.2.3", "Traceparent:", "<generated-trace-id>"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("missing %q (code %d, %s)\n%s", want, code, errs, out)
		}
	}
	if strings.Contains(out, "9.9.9.9") && strings.Count(out, "9.9.9.9") > 1 {
		t.Errorf("the client's X-Forwarded-For must be shown only as the request header, not forwarded\n%s", out)
	}
	if code, _, _ = run("why", "GET", "http://a.test:8080/api", "--config", path, "--rate-limit", "bogus"); code != 2 {
		t.Errorf("bad --rate-limit: code %d", code)
	}
	if code, _, _ = run("why", "GET", "http://a.test:8080/api", "--admin", "127.0.0.1:1", "--rate-limit", "5/s"); code != 2 {
		t.Errorf("--rate-limit with --admin: code %d", code)
	}
}
