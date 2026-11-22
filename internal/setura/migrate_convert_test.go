package setura

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden tests: every directory under testdata/convert holds the inputs, an
// args file ({in} stands for the directory) and the expected stdout
// (want.yaml), stderr summary (want.txt), report (want.report.json) and exit
// code (want.exit). Run with UPDATE_GOLDEN=1 to rewrite them.

func goldenCheck(t *testing.T, path, got string) {
	t.Helper()
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if got == "" {
			_ = os.Remove(path)
			return
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		if got == "" {
			return
		}
		t.Fatalf("%s: %v (run with UPDATE_GOLDEN=1)", path, err)
	}
	if string(want) != got {
		t.Errorf("%s differs (run with UPDATE_GOLDEN=1 to accept):\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

func TestConvertGolden(t *testing.T) {
	dirs, err := filepath.Glob("testdata/convert/*")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no golden cases: %v", err)
	}
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			continue
		}
		t.Run(filepath.Base(dir), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, "args"))
			if err != nil {
				t.Skip("no args file")
			}
			args := strings.Fields(strings.ReplaceAll(string(raw), "{in}", dir))
			report := filepath.Join(t.TempDir(), "report.json")
			code, out, errs := cli(t, nil, append([]string{"migrate", "convert", "--report", report}, args...)...)
			goldenCheck(t, filepath.Join(dir, "want.yaml"), out)
			goldenCheck(t, filepath.Join(dir, "want.txt"), errs)
			goldenCheck(t, filepath.Join(dir, "want.exit"), string(rune('0'+code))+"\n")
			if b, err := os.ReadFile(report); err == nil {
				goldenCheck(t, filepath.Join(dir, "want.report.json"), string(b))
				var rep convReport
				if err := json.Unmarshal(b, &rep); err != nil {
					t.Fatalf("report is not JSON: %v", err)
				}
				// every converted or todo item names its source and key
				for _, it := range rep.Items {
					if it.Source == "" || it.Key == "" || it.Status == "" {
						t.Errorf("incomplete item %+v", it)
					}
					if it.Status == convTodo && it.Reason == "" {
						t.Errorf("todo without a reason: %+v", it)
					}
				}
			}
			// generated YAML must be readable by our own decoder
			if code != 2 {
				if _, err := decodeManifests([]byte(out)); err != nil {
					t.Errorf("generated YAML does not parse: %v", err)
				}
			}
		})
	}
}

// Every annotation of the classification table is either converted or leaves a
// TODO: nothing is dropped silently.
func TestConvertNothingDroppedSilently(t *testing.T) {
	for _, name := range annotationHintTable() {
		if name == "ingress.class" {
			continue
		}
		in := "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: x\n  namespace: demo\n  annotations:\n    " + nginxPrefix + name + ": \"true\"\nspec:\n  rules:\n  - host: x.example.test\n    http:\n      paths:\n      - {path: /, pathType: Prefix, backend: {service: {name: s, port: {number: 80}}}}\n"
		path := filepath.Join(t.TempDir(), "in.yaml")
		if err := os.WriteFile(path, []byte(in), 0o644); err != nil {
			t.Fatal(err)
		}
		_, out, errs := cli(t, nil, "migrate", "convert", path, "--format", "json", "--no-check")
		if out == "" {
			t.Errorf("%s: no output (stderr %q)", name, errs)
			continue
		}
		var rep convReport
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		found := false
		for _, it := range rep.Items {
			if strings.HasSuffix(it.Key, "/"+name) || strings.HasPrefix(it.Key, nginxPrefix+name) {
				found = true
			}
		}
		if !found {
			t.Errorf("annotation %s produced no item in the report: %+v", name, rep.Items)
		}
	}
}

const convSimple = "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: web, namespace: demo}\nspec:\n  ingressClassName: nginx\n  rules:\n  - host: a.example.test\n    http:\n      paths:\n      - {path: /, pathType: Prefix, backend: {service: {name: web, port: {number: 80}}}}\n"

func TestConvertExitCodesAndOut(t *testing.T) {
	in := writeTmp(t, "in.yaml", convSimple)
	out := filepath.Join(t.TempDir(), "gw")
	code, stdout, errs := cli(t, nil, "migrate", "convert", in, "--out", out)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q stdout %q", code, errs, stdout)
	}
	for _, want := range []string{"Next:", "equivalent", "HTTPRoute", "gateway-demo-nginx.yaml"[:0] + "gateway-nginx.yaml"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("summary lacks %q:\n%s", want, stdout)
		}
	}
	files, _ := filepath.Glob(filepath.Join(out, "*.yaml"))
	if len(files) != 2 {
		t.Fatalf("want one file per resource (2), got %v", files)
	}
	// never overwrite without --force
	code, _, errs = cli(t, nil, "migrate", "convert", in, "--out", out)
	if code != 2 || !strings.Contains(errs, "--force") {
		t.Fatalf("second run: exit %d stderr %q", code, errs)
	}
	if code, _, errs = cli(t, nil, "migrate", "convert", in, "--out", out, "--force"); code != 0 {
		t.Fatalf("--force: exit %d %q", code, errs)
	}
	// the report file is protected the same way
	rep := filepath.Join(t.TempDir(), "r.json")
	if code, _, errs = cli(t, nil, "migrate", "convert", in, "--report", rep); code != 0 {
		t.Fatalf("report: exit %d %q", code, errs)
	}
	if code, _, errs = cli(t, nil, "migrate", "convert", in, "--report", rep); code != 2 || !strings.Contains(errs, "--force") {
		t.Fatalf("report overwrite: exit %d %q", code, errs)
	}
	// what was written passes migrate check against the original
	code, stdout, errs = cli(t, nil, "migrate", "check", "--ingress", in, "--routes", out)
	if code != 0 {
		t.Fatalf("migrate check on the output: exit %d\n%s\n%s", code, stdout, errs)
	}
}

func TestConvertUsageErrors(t *testing.T) {
	in := writeTmp(t, "in.yaml", convSimple)
	for _, args := range [][]string{
		{"--from", "nope", in},
		{"--format", "xml", in},
		{"--from", "nginx-conf"},
		{"--bogus"},
	} {
		code, _, _ := cli(t, nil, append([]string{"migrate", "convert"}, args...)...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if code, _, _ := cli(t, nil, "migrate", "convert", filepath.Join(t.TempDir(), "missing.yaml")); code != 2 {
		t.Errorf("missing file: exit %d, want 2", code)
	}
}

func TestConvertYAMLAndJSONFormats(t *testing.T) {
	in := writeTmp(t, "in.yaml", convSimple)
	code, out, errs := cli(t, nil, "migrate", "convert", in, "--format", "yaml")
	if code != 0 || errs != "" || !strings.HasPrefix(out, "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway") {
		t.Fatalf("yaml: exit %d stderr %q\n%s", code, errs, out)
	}
	code, out, _ = cli(t, nil, "migrate", "convert", in, "--format", "json")
	var rep convReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 0 || !rep.OK || len(rep.Manifests) != 2 || rep.Check == nil || rep.Check.Skipped {
		t.Fatalf("json: exit %d err %v %+v", code, err, rep)
	}
	_, out, _ = cli(t, nil, "migrate", "convert", in, "--format", "json", "--no-check")
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Check == nil || !rep.Check.Skipped {
		t.Fatalf("--no-check: %v %+v", err, rep.Check)
	}
}

func TestConvertTodoExitsOne(t *testing.T) {
	in := writeTmp(t, "in.yaml", strings.Replace(convSimple, "metadata: {name: web, namespace: demo}",
		"metadata: {name: web, namespace: demo, annotations: {nginx.ingress.kubernetes.io/server-snippet: \"return 418;\"}}", 1))
	code, out, errs := cli(t, nil, "migrate", "convert", in)
	if code != 1 || !strings.Contains(out, "# TODO(setura) nginx.ingress.kubernetes.io/server-snippet") || !strings.Contains(errs, "needs review") {
		t.Fatalf("exit %d\nstdout %s\nstderr %s", code, out, errs)
	}
}

func TestConvertLiveFromFakeCluster(t *testing.T) {
	res := map[string]any{
		"ingresses.networking.k8s.io": items(convSimple),
		"services":                    items("apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: demo}\nspec:\n  ports:\n  - {port: 80}\n"),
	}
	c, seen := keyedCluster(res)
	code, out, errs := cli(t, c, "migrate", "convert", "-n", "demo", "--format", "yaml")
	if code != 0 || !strings.Contains(out, "kind: HTTPRoute") {
		t.Fatalf("exit %d stderr %q\n%s", code, errs, out)
	}
	if len(*seen) == 0 {
		t.Fatal("the fake cluster was not used")
	}
	for _, args := range *seen {
		for _, a := range args {
			if a == "apply" || a == "delete" || a == "patch" || a == "create" {
				t.Errorf("convert must only read: %v", args)
			}
		}
	}
	c, _ = keyedCluster(map[string]any{})
	if code, _, _ := cli(t, c, "migrate", "convert", "-n", "demo"); code != 2 {
		t.Errorf("a cluster without Ingress resources: exit %d, want 2", code)
	}
}

func TestConvertNginxConfRefusalNamesLines(t *testing.T) {
	code, _, errs := cli(t, nil, "migrate", "convert", "--from", "nginx-conf", "testdata/convert/nginxconf-refused/nginx.conf")
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"nginx.conf:2:", "nginx.conf:4:", "nginx.conf:5:", "nginx.conf:7:", "nginx.conf:11:", "nginx.conf:12:", "nginx.conf:14:", "nginx.conf:18:"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
}

func TestConvertYAMLEmitterRoundTrips(t *testing.T) {
	v := obj{"apiVersion": "v1", "kind": "ConfigMap", "metadata": obj{"name": "x", "annotations": obj{"a": "yes", "b": "1", "c": "{\"k\": \"v\"}", "d": "a: b", "e": "", "f": "line\nbreak", "g": "#hash"}},
		"data": obj{"list": []any{"a", "true", float64(3), obj{"k": "v", "n": []any{"x"}}}, "empty": obj{}, "nil": []any{}}}
	text := emitYAML(v)
	docs, err := decodeManifests([]byte(text))
	if err != nil || len(docs) != 1 {
		t.Fatalf("%v\n%s", err, text)
	}
	got, _ := json.Marshal(docs[0])
	want, _ := json.Marshal(v)
	if string(got) != string(want) {
		t.Errorf("round trip differs:\n%s\n%s\n%s", text, got, want)
	}
}
