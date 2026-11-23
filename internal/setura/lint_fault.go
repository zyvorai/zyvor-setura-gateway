package setura

import (
	"encoding/json"
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// faultRules evaluates SET020 over HTTPRoutes: every inline
// setura.zyvor.dev/fault block and every setura.zyvor.dev/fault annotation must
// parse and validate the way the built-in gateway compiles them. A fault with
// no ttl or expires is the main case: the gateway refuses such a route, so a
// chaos experiment can never be left running by accident.
func faultRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != route {
			continue
		}
		id := "HTTPRoute/" + ns + "/" + name
		add := func(msg string) {
			findings = append(findings, obj{"id": "SET020", "severity": ruleSeverity("SET020"), "resource": id, "message": msg})
		}
		spec := asMap(specs[key])
		rules := asList(spec["rules"])
		for i, r := range rules {
			if block, ok := asMap(r)[builtin.FaultKey]; ok {
				raw, _ := json.Marshal(block)
				if _, err := builtin.ParseFaultBlock(raw); err != nil {
					add(fmt.Sprintf("rule %d: %v", i+1, err))
				}
			}
		}
		ann := asMap(spec[builtin.SeturaAnnotationsKey])
		rawAnn := map[string]string{}
		for _, k := range sortedKeys(ann) {
			if !strings.HasPrefix(k, builtin.FaultKey) {
				continue
			}
			v, ok := ann[k].(string)
			if !ok {
				add(fmt.Sprintf("annotation %s: the value must be a JSON string", k))
				continue
			}
			rawAnn[k] = v
			if _, err := builtin.ParseFaultBlock([]byte(v)); err != nil {
				add(fmt.Sprintf("annotation %s: %v", k, err))
			}
		}
		for _, k := range builtin.OrphanFaultAnnotations(rawAnn, len(rules)) {
			add(fmt.Sprintf("annotation %s names no rule: use %s for the whole route or %s.rule-N with N from 1 to %d", k, builtin.FaultKey, builtin.FaultKey, len(rules)))
		}
	}
	return findings
}
