package setura

import (
	"strings"
	"testing"
)

func filterFindings(t *testing.T, rules []any) []string {
	t.Helper()
	rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{
		gateway + "/gw": obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}},
		route + "/r":    obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": rules}}})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range asList(rep["findings"]) {
		if m := asMap(f); asStr(m["id"]) == "SET090" {
			out = append(out, asStr(m["message"]))
		}
	}
	return out
}

func TestLintFilterCombinations(t *testing.T) {
	back := []any{obj{"name": "a", "port": 80}}
	redirect := obj{"type": "RequestRedirect", "requestRedirect": obj{"scheme": "https"}}
	rewrite := func(path obj) obj { return obj{"type": "URLRewrite", "urlRewrite": obj{"path": path}} }
	prefix := rewrite(obj{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/v2"})
	exact := []any{obj{"path": obj{"type": "Exact", "value": "/x"}}}
	pfx := []any{obj{"path": obj{"type": "PathPrefix", "value": "/x"}}}
	hdr := obj{"type": "RequestHeaderModifier", "requestHeaderModifier": obj{"set": []any{}}}
	cases := map[string]struct {
		rule obj
		want string // empty means clean
	}{
		"clean redirect":            {obj{"filters": []any{redirect}}, ""},
		"clean rewrite":             {obj{"matches": pfx, "backendRefs": back, "filters": []any{prefix, hdr}}, ""},
		"rewrite no matches":        {obj{"backendRefs": back, "filters": []any{prefix}}, ""},
		"rewrite and redirect":      {obj{"filters": []any{redirect, rewrite(obj{"type": "ReplaceFullPath", "replaceFullPath": "/"})}}, "cannot be combined"},
		"duplicate header modifier": {obj{"backendRefs": back, "filters": []any{hdr, hdr}}, "appears 2 times"},
		"duplicate redirect":        {obj{"filters": []any{redirect, redirect}}, "appears 2 times"},
		"mirror twice is allowed":   {obj{"backendRefs": back, "filters": []any{obj{"type": "RequestMirror", "requestMirror": obj{}}, obj{"type": "RequestMirror", "requestMirror": obj{}}}}, ""},
		"missing redirect block":    {obj{"filters": []any{obj{"type": "RequestRedirect"}}}, "no requestRedirect block"},
		"missing rewrite block":     {obj{"backendRefs": back, "filters": []any{obj{"type": "URLRewrite"}}}, "no urlRewrite block"},
		"missing header block":      {obj{"backendRefs": back, "filters": []any{obj{"type": "RequestHeaderModifier"}}}, "no requestHeaderModifier block"},
		"foreign block":             {obj{"backendRefs": back, "filters": []any{obj{"type": "RequestHeaderModifier", "requestHeaderModifier": obj{}, "urlRewrite": obj{}}}}, "carries a urlRewrite block"},
		"prefix needs prefix match": {obj{"matches": exact, "backendRefs": back, "filters": []any{prefix}}, "only works when every match"},
		"prefix with one regex":     {obj{"matches": append(append([]any{}, pfx...), obj{"path": obj{"type": "RegularExpression", "value": "x"}}), "backendRefs": back, "filters": []any{prefix}}, "only works when every match"},
		"full path with exact ok":   {obj{"matches": exact, "backendRefs": back, "filters": []any{rewrite(obj{"type": "ReplaceFullPath", "replaceFullPath": "/y"})}}, ""},
		"full path missing":         {obj{"backendRefs": back, "filters": []any{rewrite(obj{"type": "ReplaceFullPath"})}}, "no replaceFullPath"},
		"prefix missing":            {obj{"backendRefs": back, "filters": []any{rewrite(obj{"type": "ReplacePrefixMatch"})}}, "no replacePrefixMatch"},
		"mixed path fields":         {obj{"backendRefs": back, "filters": []any{rewrite(obj{"type": "ReplaceFullPath", "replaceFullPath": "/", "replacePrefixMatch": "/"})}}, "also sets replacePrefixMatch"},
		"unknown path type":         {obj{"backendRefs": back, "filters": []any{rewrite(obj{"type": "Regex"})}}, `has type "Regex"`},
		"redirect bad scheme":       {obj{"filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"scheme": "ftp"}}}}, "only http and https"},
		"redirect port 0":           {obj{"filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"port": 0}}}}, "outside 1 to 65535"},
		"redirect port big":         {obj{"filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"port": 70000}}}}, "outside 1 to 65535"},
		"redirect port fraction":    {obj{"filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"port": 80.5}}}}, "outside 1 to 65535"},
		"redirect prefix on exact":  {obj{"matches": exact, "filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"path": obj{"type": "ReplacePrefixMatch", "replacePrefixMatch": "/n"}}}}}, "only works when every match"},
		"hostile scheme is clipped": {obj{"filters": []any{obj{"type": "RequestRedirect", "requestRedirect": obj{"scheme": strings.Repeat("x", 5000)}}}}, "only http and https"},
		"non-map filter":            {obj{"backendRefs": back, "filters": []any{"RequestRedirect", 7, nil}}, ""},
		"non-string type":           {obj{"backendRefs": back, "filters": []any{obj{"type": 5}}}, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := filterFindings(t, []any{c.rule})
			joined := strings.Join(got, "|")
			if c.want == "" && len(got) != 0 {
				t.Fatalf("expected clean, got %v", got)
			}
			if c.want != "" && !strings.Contains(joined, c.want) {
				t.Fatalf("want %q, got %v", c.want, got)
			}
			if len(joined) > 2000 {
				t.Errorf("finding echoes unbounded input: %d bytes", len(joined))
			}
		})
	}
	if got := filterFindings(t, []any{obj{"backendRefs": back}, obj{"filters": []any{redirect, prefix}}}); len(got) != 1 || !strings.HasPrefix(got[0], "rule 2:") {
		t.Errorf("finding must name its rule: %v", got)
	}
	if r := ruleSeverity("SET090"); r != SeverityError {
		t.Errorf("SET090 is an error: %s", r)
	}
}
