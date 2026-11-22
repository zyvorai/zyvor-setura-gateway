package setura

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const replayDir = "../../examples/replay/"

func replayRun(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(&errb)
	code, err := runReplay(fs, args, newUI(false, termOptions{Color: "never"}, func(string) string { return "" }), false, strings.NewReader(stdin), &out, &errb)
	if err != nil {
		code = 2
	}
	return code, out.String(), errb.String()
}

func replayLog(t *testing.T, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "access.jsonl")
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func logLine(method, path string) string {
	return fmt.Sprintf(`{"listener":"shop/dev/web","host":"orders.example.test","method":%q,"path":%q,"status":200,"route":"shop/orders"}`, method, path)
}

func replayJSON(t *testing.T, args ...string) (*ReplayReport, int) {
	t.Helper()
	code, out, errs := replayRun(t, append(args, "--format", "json"), "")
	if code == 2 {
		t.Fatalf("usage error: %s", errs)
	}
	var rep ReplayReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out)
	}
	return &rep, code
}

func classReq(r *ReplayReport, c string) int64 { return r.class(c).Requests }

func TestReplayExample(t *testing.T) {
	rep, code := replayJSON(t, "--log", replayDir+"access.jsonl", "--before", replayDir+"old.json", "--after", replayDir+"new.json")
	if code != 0 {
		t.Fatalf("code %d without --fail-on", code)
	}
	in := rep.Input
	if in.Requests != 165 || in.SkippedNonJSON != 1 || in.LoggedRouteMismatch != 0 {
		t.Errorf("input %+v", in)
	}
	for c, want := range map[string]int64{classRoute: 28, classBackend: 20, classOutcome: 20, classWeights: 70, classUnknown: 25} {
		if got := classReq(rep, c); got != want {
			t.Errorf("%s = %d, want %d", c, got, want)
		}
	}
	if rep.Changed != 135 || rep.Unchanged != 30 {
		t.Errorf("changed %d unchanged %d", rep.Changed, rep.Unchanged)
	}
	if ex := rep.class(classOutcome).Example; ex == nil || !strings.Contains(ex.After, "redirect 301") && !strings.Contains(ex.After, "no-route") {
		t.Errorf("outcome example %+v", ex)
	}
	if len(rep.WeightShifts) == 0 || rep.WeightShifts[0].Backends[0].BeforePercent != 90 || rep.WeightShifts[0].Backends[0].AfterPercent != 50 {
		t.Errorf("shifts %+v", rep.WeightShifts)
	}
}

func TestReplayFailOnExitCodes(t *testing.T) {
	base := []string{"--log", replayDir + "access.jsonl", "--before", replayDir + "old.json", "--after", replayDir + "new.json"}
	for _, c := range []struct {
		failOn string
		want   int
	}{{"route", 1}, {"backend", 1}, {"outcome", 1}, {"any", 1}, {"unknown", 1}} {
		if code, _, _ := replayRun(t, append(append([]string{}, base...), "--fail-on", c.failOn), ""); code != c.want {
			t.Errorf("--fail-on %s: code %d, want %d", c.failOn, code, c.want)
		}
	}
	same := []string{"--log", replayDir + "access.jsonl", "--before", replayDir + "old.json", "--after", replayDir + "old.json", "--fail-on", "any"}
	if code, _, _ := replayRun(t, same, ""); code != 0 {
		t.Errorf("identical configs: code %d", code)
	}
	for _, bad := range [][]string{{}, {"--log", "x"}, append(append([]string{}, base...), "--fail-on", "bogus"), append(append([]string{}, base...), "--format", "xml"), append(append([]string{}, base...), "--limit", "0"), {"--log", "missing.jsonl", "--before", replayDir + "old.json", "--after", replayDir + "new.json"}} {
		if code, _, _ := replayRun(t, bad, ""); code != 2 {
			t.Errorf("%v: code %d, want 2", bad, code)
		}
	}
}

func TestReplayIgnoreWeights(t *testing.T) {
	base := []string{"--log", replayDir + "access.jsonl", "--before", replayDir + "old.json", "--after", replayDir + "new.json", "--ignore-weights"}
	rep, _ := replayJSON(t, base...)
	if classReq(rep, classWeights) != 0 {
		t.Errorf("weights reported with --ignore-weights")
	}
}

func TestReplayChangeClasses(t *testing.T) {
	rep, _ := replayJSON(t, "--log", replayLog(t, logLine("GET", "/legacy/x"), logLine("GET", "/legacy/y"), logLine("GET", "/old/z"), logLine("GET", "/health"), `{"host":"orders.example.test"}`, "not json", `{"broken`),
		"--before", replayDir+"old.json", "--after", replayDir+"new.json")
	if rep.Input.Requests != 4 || rep.Input.SkippedNonJSON != 2 || rep.Input.SkippedIncomplete != 1 {
		t.Fatalf("input %+v", rep.Input)
	}
	if classReq(rep, classRoute) != 2 || classReq(rep, classOutcome) != 3 || rep.Unchanged != 1 {
		t.Errorf("classes %+v unchanged %d", rep.Classes, rep.Unchanged)
	}
	var sawRedirect, saw404 bool
	for _, g := range rep.TopGroups {
		sawRedirect = sawRedirect || g.After.Outcome == "redirect" && g.After.Status == 301
		saw404 = saw404 || g.After.Outcome == "no-route" && g.After.Status == 404
	}
	if !sawRedirect || !saw404 {
		t.Errorf("redirect=%v 404=%v groups %+v", sawRedirect, saw404, rep.TopGroups)
	}
}

func TestReplayHeaderDependentIsUnknown(t *testing.T) {
	rep, _ := replayJSON(t, "--log", replayLog(t, logLine("GET", "/api/items")), "--before", replayDir+"old.json", "--after", replayDir+"new.json")
	if classReq(rep, classUnknown) != 1 || classReq(rep, classRoute) != 0 || classReq(rep, classBackend) != 0 {
		t.Fatalf("classes %+v", rep.Classes)
	}
	// unknown only fails when asked for
	if _, code := replayJSON(t, "--log", replayLog(t, logLine("GET", "/api/items")), "--before", replayDir+"old.json", "--after", replayDir+"new.json", "--fail-on", "any"); code != 0 {
		t.Errorf("any must not fail on unknown, code %d", code)
	}
	if _, code := replayJSON(t, "--log", replayLog(t, logLine("GET", "/api/items")), "--before", replayDir+"old.json", "--after", replayDir+"new.json", "--fail-on", "unknown"); code != 1 {
		t.Errorf("unknown should fail, code %d", code)
	}
}

func TestReplayQueryDependentUsesLoggedQuery(t *testing.T) {
	cfg := func(extra string) string {
		return `{"schema":"setura.route-specs/v1","namespace":"t","resources":{
"gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"web","protocol":"HTTP","port":80}]},
"httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"rules":[` + extra + `{"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"backendRefs":[{"name":"a","port":80}]}]}},
"backends":{"a:80":{"endpoints":["127.0.0.1:1"]},"b:80":{"endpoints":["127.0.0.1:2"]}}}`
	}
	dir := t.TempDir()
	write := func(n, s string) string {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldP := write("old.json", cfg(""))
	newP := write("new.json", cfg(`{"matches":[{"path":{"type":"PathPrefix","value":"/s"},"queryParams":[{"name":"beta","value":"1"}]}],"backendRefs":[{"name":"b","port":80}]},`))
	lg := write("l.jsonl", `{"host":"h","method":"GET","path":"/s?beta=1"}`+"\n"+`{"host":"h","method":"GET","path":"/s?beta=0"}`+"\n")
	rep, _ := replayJSON(t, "--log", lg, "--before", oldP, "--after", newP)
	if rep.Changed != 1 || classReq(rep, classBackend) != 1 || classReq(rep, classUnknown) != 0 {
		t.Errorf("query routing: %+v", rep.Classes)
	}
}

func TestReplayWeightShiftOnly(t *testing.T) {
	rep, _ := replayJSON(t, "--log", replayLog(t, logLine("GET", "/checkout/1"), logLine("GET", "/checkout/2")), "--before", replayDir+"old.json", "--after", replayDir+"new.json")
	if rep.Changed != 2 || classReq(rep, classWeights) != 2 || classReq(rep, classRoute) != 0 || len(rep.TopGroups) != 1 {
		t.Errorf("%+v groups=%d", rep.Classes, len(rep.TopGroups))
	}
	if rep.TopGroups[0].Shape != "/checkout/:n" || rep.TopGroups[0].Requests != 2 {
		t.Errorf("group %+v", rep.TopGroups[0])
	}
}

func TestReplayGzipAndStdin(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(logLine("GET", "/legacy/a") + "\n" + logLine("GET", "/health") + "\n"))
	zw.Close()
	gz := filepath.Join(t.TempDir(), "a.jsonl.gz")
	os.WriteFile(gz, buf.Bytes(), 0o644)
	args := []string{"--before", replayDir + "old.json", "--after", replayDir + "new.json", "--format", "json"}
	for name, run := range map[string]func() (int, string, string){
		"gz file": func() (int, string, string) { return replayRun(t, append([]string{"--log", gz}, args...), "") },
		"stdin": func() (int, string, string) {
			return replayRun(t, append([]string{"--log", "-"}, args...), logLine("GET", "/legacy/a")+"\n"+logLine("GET", "/health")+"\n")
		},
		"stdin gz": func() (int, string, string) {
			return replayRun(t, append([]string{"--log", "-"}, args...), buf.String())
		},
		"no EOL": func() (int, string, string) {
			return replayRun(t, append([]string{"--log", "-"}, args...), logLine("GET", "/legacy/a")+"\n"+logLine("GET", "/health"))
		},
	} {
		code, out, errs := run()
		var rep ReplayReport
		if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || rep.Input.Requests != 2 || rep.Changed != 1 {
			t.Errorf("%s: code %d err %q out %s", name, code, errs, out)
		}
	}
}

func TestReplayLargeStreamingLog(t *testing.T) {
	const n = 60000
	p := filepath.Join(t.TempDir(), "big.jsonl")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	for i := 0; i < n; i++ {
		fmt.Fprintf(w, `{"listener":"shop/dev/web","host":"orders.example.test","method":"GET","path":"/checkout/%d?session=%d","status":200,"route":"shop/orders"}`+"\n", i, i*7)
		if i%20000 == 0 {
			fmt.Fprintf(w, "%s\n", strings.Repeat("x", 5<<20)) // overlong line is skipped, not buffered
		}
	}
	w.Flush()
	f.Close()
	rep, _ := replayJSON(t, "--log", p, "--before", replayDir+"old.json", "--after", replayDir+"new.json")
	if rep.Input.Requests != n || rep.Input.SkippedNonJSON != 3 {
		t.Fatalf("input %+v", rep.Input)
	}
	if len(rep.TopGroups) != 1 || rep.TopGroups[0].Requests != n || rep.TopGroups[0].Shape != "/checkout/:n?session" {
		t.Errorf("grouping: %d groups, first %+v", len(rep.TopGroups), rep.TopGroups)
	}
}

func TestReplayPrettyAndGitHub(t *testing.T) {
	args := []string{"--log", replayDir + "access.jsonl", "--before", replayDir + "old.json", "--after", replayDir + "new.json"}
	code, out, _ := replayRun(t, append(args, "--format", "pretty", "--limit", "2"), "")
	if code != 0 || !strings.Contains(out, "weight distribution shifted") || !strings.Contains(out, "unknown, depends on headers") || !strings.Contains(out, "90.0%") {
		t.Errorf("pretty:\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("escape codes without color")
	}
	code, out, _ = replayRun(t, append(args, "--format", "github", "--fail-on", "outcome"), "")
	if code != 1 || !strings.Contains(out, "::error title=setura replay outcome::") || !strings.Contains(out, "::warning title=setura replay weights::") {
		t.Errorf("github (code %d):\n%s", code, out)
	}
	_, out, _ = replayRun(t, []string{"--log", replayDir + "access.jsonl", "--before", replayDir + "old.json", "--after", replayDir + "old.json", "--format", "github"}, "")
	if !strings.HasPrefix(out, "::notice") {
		t.Errorf("no-impact github: %q", out)
	}
}

func TestPathShape(t *testing.T) {
	for in, want := range map[string]string{
		"/a/123/b": "/a/:n/b",
		"/u/550e8400-e29b-41d4-a716-446655440000": "/u/:uuid",
		"/o/deadbeefcafe01":                       "/o/:id",
		"/x?b=2&a=1":                              "/x?a&b",
		"/plain/path":                             "/plain/path",
	} {
		if got := pathShape(in); got != want {
			t.Errorf("pathShape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReplayCommandWiring(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main([]string{"replay", "-h"}, &out, &errb); code != 0 {
		t.Errorf("-h code %d", code)
	}
	var comp bytes.Buffer
	Completion("bash", &comp)
	if !strings.Contains(comp.String(), "replay") || !strings.Contains(comp.String(), "--fail-on") {
		t.Errorf("completion lacks replay")
	}
}
