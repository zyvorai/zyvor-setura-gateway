package setura

import (
	"strings"
	"testing"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

func set023(t *testing.T, gw obj, rt obj) []string {
	t.Helper()
	rep, err := Lint(obj{"schema": snapshotSchema, "namespace": "t", "resources": obj{gateway + "/gw": gw, route + "/r": rt}})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range asList(rep["findings"]) {
		if m := asMap(f); asStr(m["id"]) == "SET023" {
			if m["severity"] != SeverityError {
				t.Errorf("SET023 must be an error: %v", m)
			}
			out = append(out, asStr(m["message"]))
		}
	}
	return out
}

func extGW() obj {
	return obj{"gatewayClassName": "x", "listeners": []any{obj{"name": "web", "protocol": "HTTP", "port": 80}}}
}

func TestLintUnknownExtensionKeys(t *testing.T) {
	back := []any{obj{"name": "a", "port": 80}}
	rt := func(rule, ann obj) obj {
		r := obj{"parentRefs": []any{obj{"name": "gw"}}, "rules": []any{rule}}
		if ann != nil {
			r[builtin.SeturaAnnotationsKey] = ann
		}
		return r
	}
	got := set023(t, extGW(), rt(obj{"backendRefs": back, "setura.zyvor.dev/authh": obj{}}, nil))
	if len(got) != 1 || !strings.Contains(got[0], `did you mean "setura.zyvor.dev/auth"`) {
		t.Errorf("misspelt rule key: %v", got)
	}
	got = set023(t, extGW(), rt(obj{"backendRefs": back}, obj{"setura.zyvor.dev/rate-limt.rule-1": `{"rate":"1/m"}`}))
	if len(got) != 1 || !strings.Contains(got[0], `"setura.zyvor.dev/rate-limit.rule-1"`) {
		t.Errorf("misspelt annotation: %v", got)
	}
	// every known form is clean, including .rule-N and the compat annotations of the table.
	clean := obj{}
	for _, k := range builtin.RouteAnnotationKeys {
		clean[k] = "{}"
		clean[k+".rule-1"] = "{}"
	}
	ruleKeys := obj{"backendRefs": back}
	for _, k := range builtin.RuleKeys {
		ruleKeys[k] = obj{}
	}
	if got := set023(t, extGW(), rt(ruleKeys, clean)); len(got) != 0 {
		t.Errorf("known keys must be clean: %v", got)
	}
	gw := extGW()
	gw[builtin.SeturaAnnotationsKey] = obj{"setura.zyvor.dev/client-alow": "x"}
	gw["listeners"] = []any{obj{"name": "web", "protocol": "HTTPS", "port": 443, "tls": obj{"options": obj{"setura.zyvor.dev/tls-min-versoin": "1.2"}}, "setura.zyvor.dev/limitz": obj{}}}
	if got := set023(t, gw, rt(obj{"backendRefs": back}, nil)); len(got) != 3 {
		t.Errorf("gateway annotation, listener key and tls option must each be flagged: %v", got)
	}
}
