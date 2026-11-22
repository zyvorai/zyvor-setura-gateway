package setura

import (
	"encoding/json"
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// withShadowAnnotations returns the spec of a cluster object. The shadow-diff
// annotations of the object are carried in the spec under
// setura.zyvor.dev/annotations, because a snapshot keeps specs only; the
// built-in gateway reads them from there exactly as it reads them from
// metadata.annotations in controller mode.
func withShadowAnnotations(object obj) any {
	spec := object["spec"]
	sm := asMap(spec)
	if sm == nil {
		return spec
	}
	keep := obj{}
	for k, v := range asMap(asMap(object["metadata"])["annotations"]) {
		if strings.HasPrefix(k, builtin.ShadowDiffKey) {
			keep[k] = v
		}
	}
	if len(keep) > 0 {
		sm[builtin.SeturaAnnotationsKey] = keep
	}
	return sm
}

// shadowRules evaluates SET015 over HTTPRoutes and GRPCRoutes: every inline
// shadow-diff block and every shadow-diff annotation must parse and validate
// the way the gateway compiles them, and an annotation must reach a
// RequestMirror filter.
func shadowRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		kind := ""
		switch resource {
		case route:
			kind = "HTTPRoute"
		case grpcRoute:
			kind = "GRPCRoute"
		default:
			continue
		}
		id := kind + "/" + ns + "/" + name
		add := func(msg string) {
			findings = append(findings, obj{"id": "SET015", "severity": ruleSeverity("SET015"), "resource": id, "message": msg})
		}
		spec := asMap(specs[key])
		rules := asList(spec["rules"])
		mirrors := make([]int, len(rules)) // RequestMirror filters per rule
		for i, r := range rules {
			for _, f := range asList(asMap(r)["filters"]) {
				fm := asMap(f)
				if asStr(fm["type"]) != "RequestMirror" {
					continue
				}
				mirrors[i]++
				rm := asMap(fm["requestMirror"])
				if block, ok := rm[builtin.ShadowDiffKey]; ok {
					raw, _ := json.Marshal(block)
					if _, err := builtin.ParseShadowBlock(raw); err != nil {
						add(fmt.Sprintf("rule %d: %v", i+1, err))
					}
				}
			}
		}
		ann := asMap(spec[builtin.SeturaAnnotationsKey])
		rawAnn := map[string]string{}
		for _, k := range sortedKeys(ann) {
			if !strings.HasPrefix(k, builtin.ShadowDiffKey) {
				continue
			}
			v, ok := ann[k].(string)
			if !ok {
				add(fmt.Sprintf("annotation %s: the value must be a JSON string", k))
				continue
			}
			rawAnn[k] = v
			if _, err := builtin.ParseShadowBlock([]byte(v)); err != nil {
				add(fmt.Sprintf("annotation %s: %v", k, err))
			}
		}
		for _, k := range builtin.OrphanShadowAnnotations(rawAnn, len(rules)) {
			add(fmt.Sprintf("annotation %s names no rule: use %s for the whole route or %s.rule-N with N from 1 to %d", k, builtin.ShadowDiffKey, builtin.ShadowDiffKey, len(rules)))
		}
		total := 0
		for i := range rules {
			if _, ok := rawAnn[builtin.ShadowRuleAnnotation(i+1)]; ok && mirrors[i] == 0 {
				add(fmt.Sprintf("annotation %s: rule %d has no RequestMirror filter to apply it to", builtin.ShadowRuleAnnotation(i+1), i+1))
			}
			total += mirrors[i]
		}
		if _, ok := rawAnn[builtin.ShadowDiffKey]; ok && total == 0 {
			add("annotation " + builtin.ShadowDiffKey + ": the route has no RequestMirror filter to apply it to")
		}
	}
	return findings
}
