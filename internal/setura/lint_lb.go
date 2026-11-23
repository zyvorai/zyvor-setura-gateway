package setura

import (
	"encoding/json"
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// lbBlockFor returns the raw load-balancer block of rule i: its own field or its annotation.
func lbBlockFor(spec obj, i int, rule obj) (raw []byte, where string, ok bool) {
	if b, has := rule[builtin.LoadBalancerKey]; has {
		raw, _ := json.Marshal(b)
		return raw, fmt.Sprintf("rule %d", i+1), true
	}
	if k, v, has := annotationFor(spec, builtin.LoadBalancerKey, i); has {
		return []byte(v), "annotation " + k, true
	}
	return nil, "", false
}

// lbRules evaluates SET050 to SET053: load-balancer blocks must compile the way
// the gateway compiles them and name rules that exist (SET050), a consistent
// hash must have a single backend and no competing session persistence to be
// useful (SET051), backend declarations must be valid (SET052) and a backendRef
// of kind Backend must name a declared backend (SET053).
func lbRules(snapshot, specs obj, ns string) []obj {
	var findings []obj
	addFor := func(resource string) func(id, msg string) {
		return func(id, msg string) {
			findings = append(findings, obj{"id": id, "severity": ruleSeverity(id), "resource": resource, "message": msg})
		}
	}
	declared := map[string]bool{}
	snapAdd := addFor("Snapshot/" + ns)
	backends := asMap(snapshot["backends"])
	for _, k := range sortedKeys(backends) {
		raw, _ := json.Marshal(backends[k])
		if err := builtin.CheckBackendDef(raw); err != nil {
			snapAdd("SET052", fmt.Sprintf("backends[%q]: %v", k, err))
		}
		name := k
		if i := strings.LastIndex(name, ":"); i > 0 {
			name = name[:i]
		}
		if !strings.Contains(name, "/") {
			name = ns + "/" + name
		}
		declared[name] = true
	}
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != route {
			continue
		}
		add := addFor("HTTPRoute/" + ns + "/" + name)
		spec := asMap(specs[key])
		rules := asList(spec["rules"])
		ann := asMap(spec[builtin.SeturaAnnotationsKey])
		routeBackends := map[string]bool{}
		if v, ok := ann[builtin.BackendsKey]; ok {
			s, isStr := v.(string)
			var defs map[string]json.RawMessage
			switch {
			case !isStr:
				add("SET052", fmt.Sprintf("annotation %s: the value must be a JSON string", builtin.BackendsKey))
			case json.Unmarshal([]byte(s), &defs) != nil:
				add("SET052", fmt.Sprintf("annotation %s: the value must be a JSON object of backend name to backend", builtin.BackendsKey))
			default:
				for _, n := range sortedKeys(defs) {
					routeBackends[n] = true
					if err := builtin.CheckBackendDef(defs[n]); err != nil {
						add("SET052", fmt.Sprintf("annotation %s: backend %q: %v", builtin.BackendsKey, n, err))
					}
				}
			}
		}
		rawAnn := map[string]string{}
		for _, k := range sortedKeys(ann) {
			if !strings.HasPrefix(k, builtin.LoadBalancerKey) {
				continue
			}
			v, ok := ann[k].(string)
			if !ok {
				add("SET050", fmt.Sprintf("annotation %s: the value must be a JSON string", k))
				continue
			}
			rawAnn[k] = v
		}
		for _, k := range builtin.OrphanRuleAnnotations(rawAnn, builtin.LoadBalancerKey, len(rules)) {
			add("SET050", fmt.Sprintf("annotation %s names no rule: use %s for the whole route or %s.rule-N with N from 1 to %d", k, builtin.LoadBalancerKey, builtin.LoadBalancerKey, len(rules)))
		}
		for i, r := range rules {
			rule := asMap(r)
			refs := asList(rule["backendRefs"])
			where := fmt.Sprintf("rule %d", i+1)
			for _, b := range refs {
				ref := asMap(b)
				if !builtin.IsBackendRef(str(ref, "group", ""), str(ref, "kind", "Service")) {
					continue
				}
				bn := asStr(ref["name"])
				if bns := str(ref, "namespace", ns); !declared[bns+"/"+bn] && !(bns == ns && routeBackends[bn]) {
					add("SET053", fmt.Sprintf("%s: backendRef Backend %s/%s is not declared: add it to the snapshot backends section or the %s annotation", where, bns, bn, builtin.BackendsKey))
				}
			}
			raw, w, ok := lbBlockFor(spec, i, rule)
			if !ok {
				continue
			}
			c, err := builtin.ParseLBBlock(raw)
			if err != nil {
				add("SET050", fmt.Sprintf("%s: %v", w, err))
				continue
			}
			if c.ConsistentHash == nil {
				continue
			}
			live := 0
			for _, b := range refs {
				if wt, has := num(asMap(b)["weight"]); !has || wt > 0 {
					live++
				}
			}
			if live > 1 {
				add("SET051", fmt.Sprintf("%s: consistentHash only pins the endpoint inside a backend; the rule still splits traffic by weight across %d backendRefs, so one client can reach different backends", w, live))
			}
			if rule["sessionPersistence"] != nil {
				add("SET051", w+": consistentHash and sessionPersistence both pin a client; the session wins, so the hash is ignored for returning clients")
			}
		}
	}
	return findings
}
