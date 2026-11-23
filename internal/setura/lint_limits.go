package setura

import (
	"encoding/json"
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// ruleHasDirect reports whether rule i (0-based) of a route answers with a
// direct response, through its own field or an annotation.
func ruleHasDirect(spec obj, rule obj, i int) bool {
	if _, ok := rule[builtin.DirectResponseKey]; ok {
		return true
	}
	ann := asMap(spec[builtin.SeturaAnnotationsKey])
	_, a := ann[builtin.RuleExtAnnotation(builtin.DirectResponseKey, i+1)]
	_, b := ann[builtin.DirectResponseKey]
	return a || b
}

// limitsRules evaluates SET030: the direct-response, rate-limit and limits
// extensions of HTTPRoute rules (fields and annotations) and the TLS version
// and limits settings of listeners must parse and validate the way the
// built-in gateway compiles them, and a direct-response rule must not also
// name backends, a redirect, a mirror or ExternalAuth.
func limitsRules(specs obj, ns string) []obj {
	var findings []obj
	add := func(id, msg string) {
		findings = append(findings, obj{"id": "SET030", "severity": ruleSeverity("SET030"), "resource": id, "message": msg})
	}
	parsers := map[string]func([]byte) error{
		builtin.DirectResponseKey: func(b []byte) error { _, err := builtin.ParseDirectResponseBlock(b); return err },
		builtin.RateLimitKey:      func(b []byte) error { _, err := builtin.ParseRateLimitBlock(b); return err },
		builtin.LimitsKey:         func(b []byte) error { _, err := builtin.ParseLimitsBlock(b); return err },
	}
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		spec := asMap(specs[key])
		switch resource {
		case route:
			id := "HTTPRoute/" + ns + "/" + name
			rules := asList(spec["rules"])
			for i, r := range rules {
				rule := asMap(r)
				for _, base := range builtin.RuleExtKeys {
					if block, ok := rule[base]; ok {
						raw, _ := json.Marshal(block)
						if err := parsers[base](raw); err != nil {
							add(id, fmt.Sprintf("rule %d: %v", i+1, err))
						}
					}
				}
				if ruleHasDirect(spec, rule, i) {
					if len(asList(rule["backendRefs"])) > 0 {
						add(id, fmt.Sprintf("rule %d: a direct-response rule answers by itself and must have no backendRefs", i+1))
					}
					for _, f := range asList(rule["filters"]) {
						if t := asStr(asMap(f)["type"]); t == "RequestRedirect" || t == "RequestMirror" || t == "ExternalAuth" {
							add(id, fmt.Sprintf("rule %d: a direct-response rule cannot also have a %s filter", i+1, t))
						}
					}
				}
			}
			ann := asMap(spec[builtin.SeturaAnnotationsKey])
			rawAnn := map[string]string{}
			for _, k := range sortedKeys(ann) {
				for _, base := range builtin.RuleExtKeys {
					if !strings.HasPrefix(k, base) {
						continue
					}
					v, ok := ann[k].(string)
					if !ok {
						add(id, fmt.Sprintf("annotation %s: the value must be a JSON string", k))
						break
					}
					rawAnn[k] = v
					if err := parsers[base]([]byte(v)); err != nil {
						add(id, fmt.Sprintf("annotation %s: %v", k, err))
					}
				}
			}
			for _, base := range builtin.RuleExtKeys {
				for _, k := range builtin.OrphanRuleAnnotations(rawAnn, base, len(rules)) {
					add(id, fmt.Sprintf("annotation %s names no rule: use %s for the whole route or %s.rule-N with N from 1 to %d", k, base, base, len(rules)))
				}
			}
		case gateway:
			id := "Gateway/" + ns + "/" + name
			for _, l := range asList(spec["listeners"]) {
				lm := asMap(l)
				ln := asStr(lm["name"])
				var min, max uint16
				var err error
				opts := asMap(asMap(lm["tls"])["options"])
				if v, ok := opts[builtin.TLSMinVersionOption].(string); ok {
					if min, err = builtin.ParseTLSVersion(v); err != nil {
						add(id, fmt.Sprintf("listener %q: tls.options %s: %v", ln, builtin.TLSMinVersionOption, err))
					}
				}
				if v, ok := opts[builtin.TLSMaxVersionOption].(string); ok {
					if max, err = builtin.ParseTLSVersion(v); err != nil {
						add(id, fmt.Sprintf("listener %q: tls.options %s: %v", ln, builtin.TLSMaxVersionOption, err))
					}
				}
				if min != 0 && max != 0 && min > max {
					add(id, fmt.Sprintf("listener %q: the minimum TLS version is higher than the maximum", ln))
				}
				if block, ok := lm[builtin.LimitsKey]; ok {
					raw, _ := json.Marshal(block)
					if _, err := builtin.ParseListenerLimitsBlock(raw); err != nil {
						add(id, fmt.Sprintf("listener %q: %v", ln, err))
					}
				}
			}
		}
	}
	return findings
}
