package setura

import (
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// extKeyRules evaluates SET023: a key under setura.zyvor.dev/ that no
// extension reads. The gateway never looks at it, so a misspelt key
// (setura.zyvor.dev/authh) leaves the route running without the protection its
// author meant. The known keys come from internal/gateway (extkeys.go), the
// same tables the gateway refuses unknown keys with at run time.
func extKeyRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != route && resource != grpcRoute && resource != gateway {
			continue
		}
		kind := map[string]string{route: "HTTPRoute", grpcRoute: "GRPCRoute", gateway: "Gateway"}[resource]
		id := kind + "/" + ns + "/" + name
		spec := asMap(specs[key])
		report := func(where string, is []builtin.ExtKeyIssue) {
			for _, i := range is {
				msg := fmt.Sprintf("%s: %s", where, i.Message())
				if i.Typo {
					msg += "; the gateway refuses the route at run time instead of serving it without the setting"
				} else {
					msg += "; the gateway ignores it"
				}
				findings = append(findings, obj{"id": "SET023", "severity": ruleSeverity("SET023"), "resource": id, "message": msg})
			}
		}
		keys := func(m obj) []string { return sortedKeys(m) }
		if resource == gateway {
			report("spec", builtin.UnknownRouteSpecKeys(keys(spec)))
			report("annotations", builtin.UnknownGatewayAnnotationKeys(keys(asMap(spec[builtin.SeturaAnnotationsKey]))))
			for _, l := range asList(spec["listeners"]) {
				lm := asMap(l)
				ln := asStr(lm["name"])
				report(fmt.Sprintf("listener %q", ln), builtin.UnknownListenerKeys(keys(lm)))
				report(fmt.Sprintf("listener %q tls.options", ln), builtin.UnknownListenerOptionKeys(keys(asMap(asMap(lm["tls"])["options"]))))
			}
			continue
		}
		report("spec", builtin.UnknownRouteSpecKeys(keys(spec)))
		report("annotations", builtin.UnknownAnnotationKeys(keys(asMap(spec[builtin.SeturaAnnotationsKey]))))
		for i, r := range asList(spec["rules"]) {
			rm := asMap(r)
			where := fmt.Sprintf("rule %d", i+1)
			report(where, builtin.UnknownRuleKeys(keys(rm)))
			for j, b := range asList(rm["backendRefs"]) {
				report(fmt.Sprintf("%s backendRef %d", where, j+1), builtin.UnknownBackendRefKeys(keys(asMap(b))))
			}
			for _, f := range asList(rm["filters"]) {
				if m := asMap(asMap(f)["requestMirror"]); m != nil {
					report(where+" RequestMirror", builtin.UnknownMirrorKeys(keys(m)))
				}
			}
		}
	}
	return findings
}
