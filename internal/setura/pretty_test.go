package setura

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var plainUI = newUI(false, termOptions{Color: "never"}, func(string) string { return "" })

var ansi = regexp.MustCompile("\x1b\\[")

func env(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

func golden(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Fatalf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func failedReport() *Report {
	return &Report{URL: "https://orders.test/checkout", OK: false, ElapsedMS: 12.4, Steps: map[string]*Step{
		"dns":     {{"state", "ok"}, {"addresses", []string{"10.0.0.1"}}},
		"tcp":     {{"state", "failed"}, {"reason", "connection refused"}},
		"tls":     {{"state", "unused"}},
		"http":    {{"state", "untested"}},
		"backend": {{"state", "unused"}},
		"assert":  {{"state", "unused"}},
	}}
}

func TestExplainGolden(t *testing.T) {
	golden(t, plainUI.ExplainPretty(failedReport()), `
  https://orders.test/checkout

  ✓ dns      ok         addresses=['10.0.0.1']
  ✗ tcp      failed     connection refused
  – tls      unused
  · http     untested
  – backend  unused
  – assert   unused

  ✗ Failed at tcp in 12 ms
  Next: Check the destination port and whether the listener or forward is running.

`)
	r := failedReport()
	r.OK, r.ElapsedMS = true, 3.14
	for _, n := range stages {
		r.Steps[n] = &Step{{"state", "ok"}}
	}
	contains(t, plainUI.ExplainPretty(r), "  ✓ Passed in 3.1 ms\n")
	if strings.Contains(plainUI.ExplainPretty(r), "Next:") {
		t.Fatal("passing probe printed a hint")
	}
}

func TestASCIIFallback(t *testing.T) {
	u := newUI(false, termOptions{Color: "never", ASCII: true}, env())
	out := u.ExplainPretty(failedReport())
	for _, r := range out {
		if r > 127 {
			t.Fatalf("non-ASCII rune %q in %q", r, out)
		}
	}
	contains(t, out, "x tcp")
	if !newUI(false, termOptions{Color: "never"}, env("TERM", "dumb")).ascii {
		t.Fatal("TERM=dumb must imply ascii")
	}
}

func lintReport() obj {
	return obj{"errors": 1, "warnings": 1, "findings": []any{
		obj{"id": "SET001", "severity": "error", "resource": "HTTPRoute/demo/a", "message": "no parentRefs"},
		obj{"id": "SET004", "severity": "warning", "resource": "HTTPRoute/demo/a", "message": "cross namespace"},
		obj{"id": "SET003", "severity": "warning", "resource": "HTTPRoute/demo/b", "message": "no backends"}}}
}

func TestLintGolden(t *testing.T) {
	r := lintReport()
	r["warnings"] = 2
	golden(t, plainUI.LintPretty(r), `
  HTTPRoute/demo/a
    ✗ SET001  no parentRefs
    ▲ SET004  cross namespace

  HTTPRoute/demo/b
    ▲ SET003  no backends

  ✗ 1 error, 2 warnings

`)
	golden(t, plainUI.LintPretty(obj{"errors": 0, "warnings": 0, "findings": []any{}}), "\n  ✓ No findings\n\n")
	if got := newUI(false, termOptions{Color: "always"}, env()).LintPretty(r); !strings.Contains(got, "\x1b[2mSET001") {
		t.Fatalf("rule ids should be dimmed: %q", got)
	}
}

func TestCheckCompareGateDoctorGolden(t *testing.T) {
	ok := &Report{URL: "http://a", OK: true, ElapsedMS: 5, Steps: map[string]*Step{}}
	for _, n := range stages {
		ok.Steps[n] = &Step{{"state", "ok"}}
	}
	bad := failedReport()
	bad.URL = "http://b"
	golden(t, plainUI.CheckPretty([]*Report{ok, bad}), `
  ✓ http://a pass      5.0 ms
  ✗ http://b fail       12 ms  tcp: connection refused

  ✗ 1 of 2 cases failed (1 passed)

`)
	golden(t, plainUI.ComparePretty("http://x", []string{"dns", "10.0.0.1"}, obj{"ok": false, "targets": obj{"dns": ok, "10.0.0.1": bad}}), `
  http://x

  ✓ dns      ok        5.0 ms
  ✗ 10.0.0.1 fail       12 ms  tcp: connection refused

  ✗ At least one target failed

`)
	golden(t, plainUI.GatePretty("orders", 2, obj{"ok": false, "attempts": []any{
		obj{"attempt": 1, "parent": obj{"ok": false, "reason": "found 0 matching parent reports; expected one"}, "probe": nil, "streak": 0}}}), `
  Gate orders

  • attempt 1   parent ✗  probe –  streak 0/2  found 0 matching parent reports; expected one

  ✗ Gate failed
  Next: Inspect the route with: setura inspect orders

`)
	golden(t, plainUI.DoctorPretty(obj{"ok": false, "checks": []any{
		obj{"namespace": "demo", "verb": "get", "resource": "gateways", "subresource": "", "state": "allowed"},
		obj{"namespace": "envoy", "verb": "create", "resource": "pods", "subresource": "portforward", "state": "denied"}}}), `
  ✓ get gateways                           demo
  ✗ create pods/portforward                envoy                    denied

  ✗ 1 permission missing or unknown
  Next: Ask a cluster admin to grant the denied verbs, then rerun setura doctor.

`)
}

func TestHelpGolden(t *testing.T) {
	var b strings.Builder
	writeHelp(&b, plainUI)
	out := b.String()
	for _, want := range []string{"\n  Verify\n", "\n  Inspect\n", "\n  Analyze\n", "\n  Publish\n", "\n  Utilities\n", "Examples", "setura COMMAND -h"} {
		contains(t, out, want)
	}
	if ansi.MatchString(out) {
		t.Fatal("plain help contains escapes")
	}
	code, out, _ := cli(t, nil)
	is(t, code, 2)
	contains(t, out, "Verify")
	code, out, _ = cli(t, nil, "--help")
	is(t, code, 0)
	contains(t, out, "Utilities")
	code, _, errs := cli(t, nil, "explain", "-h")
	is(t, code, 0)
	contains(t, errs, "Examples")
	contains(t, errs, "-address")
}

func TestEveryCommandIsInHelp(t *testing.T) {
	for _, c := range commandNames {
		if _, ok := commandSummary(c); !ok {
			t.Errorf("command %q is missing from helpGroups", c)
		}
	}
}

func TestColorResolution(t *testing.T) {
	tty := true
	cases := []struct {
		name  string
		tty   bool
		opts  termOptions
		env   func(string) string
		depth colorDepth
	}{
		{"tty auto", tty, termOptions{Color: "auto"}, env("TERM", "xterm-256color"), color256},
		{"truecolor", tty, termOptions{Color: "auto"}, env("COLORTERM", "truecolor"), colorTrue},
		{"24bit", tty, termOptions{Color: "auto"}, env("COLORTERM", "24bit"), colorTrue},
		{"NO_COLOR", tty, termOptions{Color: "auto"}, env("NO_COLOR", "1"), colorNone},
		{"non-tty", false, termOptions{Color: "auto"}, env(), colorNone},
		{"dumb", tty, termOptions{Color: "auto"}, env("TERM", "dumb"), colorNone},
		{"never", tty, termOptions{Color: "never"}, env(), colorNone},
		{"always non-tty", false, termOptions{Color: "always"}, env(), color256},
	}
	for _, c := range cases {
		if got := newUI(c.tty, c.opts, c.env).depth; got != c.depth {
			t.Errorf("%s: depth %v, want %v", c.name, got, c.depth)
		}
	}
	for _, c := range cases {
		u := newUI(c.tty, c.opts, c.env)
		has := ansi.MatchString(u.ExplainPretty(failedReport()))
		if has != (c.depth != colorNone) {
			t.Errorf("%s: escapes=%v with depth %v", c.name, has, c.depth)
		}
	}
	if got := newUI(true, termOptions{Color: "always"}, env("COLORTERM", "truecolor")).green("x"); got != "\x1b[38;2;48;209;88mx\x1b[0m" {
		t.Errorf("truecolor green = %q", got)
	}
}

func TestPipedHumanOutputHasNoEscapes(t *testing.T) {
	url := fixture(t, nil)
	_, out, _ := cli(t, nil, "explain", url, "--address", "127.0.0.1")
	if ansi.MatchString(out) {
		t.Fatalf("piped explain has escapes: %q", out)
	}
	_, out, _ = cli(t, nil, "--color", "always", "explain", url, "--address", "127.0.0.1")
	if !ansi.MatchString(out) {
		t.Fatalf("--color always produced no escapes")
	}
	code, out, _ := cli(t, nil, "explain", url, "--address", "127.0.0.1", "--color=never")
	is(t, code, 0)
	if ansi.MatchString(out) {
		t.Fatal("escapes with --color=never")
	}
	if code, _, _ := cli(t, nil, "--color", "purple", "version"); code != 2 {
		t.Fatalf("bad --color accepted")
	}
}

func TestCheckFormatRule(t *testing.T) {
	url := fixture(t, nil)
	path := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(path, []byte(`[{"url":"`+url+`","address":"127.0.0.1"}]`), 0o600)
	// Piped (non-TTY): JSON by default.
	_, out, _ := cli(t, nil, "check", path)
	var rows []any
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("piped default must be JSON: %v %q", err, out)
	}
	_, out, _ = cli(t, nil, "check", path, "--format", "pretty")
	contains(t, out, "1 case passed")
	if code, _, _ := cli(t, nil, "check", path, "--format", "yaml"); code != 2 {
		t.Fatal("bad format accepted")
	}
}

func TestLintJSONGolden(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	warn := lintSnap(t, goodGateway(), obj{"parentRefs": []any{obj{"name": "dev"}},
		"rules": []any{obj{"backendRefs": []any{obj{"name": "c", "port": 80, "namespace": "other"}}}}})
	raw, _ := json.Marshal(warn)
	os.WriteFile(path, raw, 0o600)
	_, out, _ := cli(t, nil, "lint", "--snapshot", path, "--format", "json")
	golden(t, out, `{
  "errors": 0,
  "findings": [
    {
      "id": "SET004",
      "message": "rule 1: backendRef other/c needs a ReferenceGrant in namespace other",
      "resource": "HTTPRoute/demo/orders",
      "severity": "warning"
    }
  ],
  "namespace": "demo",
  "ok": true,
  "schema": "setura.lint/v1",
  "warnings": 1
}
`)
	_, out, _ = cli(t, nil, "lint", "--snapshot", path)
	golden(t, out, `
  HTTPRoute/demo/orders
    ▲ SET004  rule 1: backendRef other/c needs a ReferenceGrant in namespace other

  ▲ 1 warning

`)
}

func TestExplainJSONUnaffectedByColor(t *testing.T) {
	url := fixture(t, nil)
	_, a, _ := cli(t, nil, "explain", url, "--address", "127.0.0.1", "--json")
	_, b, _ := cli(t, nil, "--color", "always", "--ascii", "explain", url, "--address", "127.0.0.1", "--json")
	strip := regexp.MustCompile(`"elapsed_ms": [0-9.e+-]+`)
	if strip.ReplaceAllString(a, "") != strip.ReplaceAllString(b, "") || ansi.MatchString(b) {
		t.Fatalf("JSON changed:\n%s\n%s", a, b)
	}
}

func TestUnknownCommandSuggestion(t *testing.T) {
	code, _, errs := cli(t, nil, "explan")
	is(t, code, 2)
	contains(t, errs, `Did you mean "explain"?`)
	_, _, errs = cli(t, nil, "zzzzzzzz")
	if strings.Contains(errs, "Did you mean") {
		t.Fatalf("far-off command got a suggestion: %q", errs)
	}
	is(t, levenshtein("kitten", "sitting"), 3)
}

func TestMissingFlagShowsExample(t *testing.T) {
	code, _, errs := cli(t, nil, "publish", "dev")
	is(t, code, 2)
	contains(t, errs, "Example: setura publish dev --listener")
	code, _, errs = cli(t, nil, "explain")
	is(t, code, 2)
	contains(t, errs, "Example: setura explain")
}

func TestVersionVerbose(t *testing.T) {
	_, out, _ := cli(t, nil, "version")
	is(t, out, "setura "+Version+"\n")
	code, out, _ := cli(t, nil, "version", "--verbose")
	is(t, code, 0)
	contains(t, out, "platform")
	contains(t, out, "go")
}
