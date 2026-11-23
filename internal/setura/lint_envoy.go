package setura

import (
	"sort"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// Envoy Gateway policies in a snapshot (read best effort, the CRDs are
// optional): SET080 to SET083.

// envoyPolicyResources are the snapshot resource keys of the policy kinds.
var envoyPolicyResources = func() map[string]string {
	out := map[string]string{}
	for _, k := range builtin.EnvoyKinds {
		if k.Kind == "BackendTrafficPolicy" || k.Kind == "ClientTrafficPolicy" || k.Kind == "SecurityPolicy" {
			out[k.Plural+"."+builtin.EnvoyGroup] = k.Kind
		}
	}
	return out
}()

// envoyRules evaluates SET080 to SET083 over the Envoy Gateway policies of a
// snapshot: fields Setura ignores, a security field it cannot enforce, a
// target that names nothing, and two policies on one target.
func envoyRules(specs obj, ns string) []obj {
	var findings []obj
	type pol struct {
		kind, name string
		spec       obj
	}
	var pols []pol
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if kind, ok := envoyPolicyResources[resource]; ok {
			pols = append(pols, pol{kind, name, asMap(specs[key])})
		}
	}
	if len(pols) == 0 {
		return nil
	}
	exists := map[string]bool{}
	for key := range specs {
		resource, name, _ := strings.Cut(key, "/")
		switch resource {
		case route:
			exists["HTTPRoute/"+name] = true
		case grpcRoute:
			exists["GRPCRoute/"+name] = true
		case gateway:
			exists["Gateway/"+name] = true
		}
	}
	type claim struct{ kind, target string }
	claims := map[claim][]string{}
	for _, p := range pols {
		id := p.kind + "/" + ns + "/" + p.name
		add := func(rule, msg string) {
			findings = append(findings, obj{"id": rule, "severity": ruleSeverity(rule), "resource": id, "message": msg})
		}
		tk := "HTTPRoute"
		tr := builtin.TranslateEnvoyPolicy(p.kind, p.spec, builtin.EnvoyOptions{TargetKind: tk})
		if ig := tr.Ignored(); len(ig) > 0 {
			add("SET080", "Setura ignores these fields: "+strings.Join(ig, ", ")+" (docs/envoy-gateway-compat.md)")
		}
		if len(tr.FailClosed) > 0 {
			add("SET083", "Setura cannot enforce "+strings.Join(tr.FailClosed, ", ")+": the controller refuses the targeted traffic (or serves it open with the annotation "+builtin.EnvoyFailOpenAnnotation+")")
		}
		refs := asList(p.spec["targetRefs"])
		if r := asMap(p.spec["targetRef"]); r != nil {
			refs = append(refs, r)
		}
		for _, r := range refs {
			m := asMap(r)
			kind, name, section := asStr(m["kind"]), asStr(m["name"]), asStr(m["sectionName"])
			if !exists[kind+"/"+name] {
				add("SET081", "target "+kind+" "+name+" is not in the snapshot")
			}
			claims[claim{p.kind, kind + "/" + name + "/" + section}] = append(claims[claim{p.kind, kind + "/" + name + "/" + section}], p.name)
		}
	}
	var keys []claim
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].kind+keys[i].target < keys[j].kind+keys[j].target })
	for _, k := range keys {
		names := claims[k]
		if len(names) < 2 {
			continue
		}
		sort.Strings(names)
		for _, n := range names {
			findings = append(findings, obj{"id": "SET082", "severity": ruleSeverity("SET082"), "resource": k.kind + "/" + ns + "/" + n,
				"message": "policies " + strings.Join(names, ", ") + " target " + strings.TrimSuffix(k.target, "/") + " at the same level: the oldest wins and the others are Conflicted"})
		}
	}
	return findings
}

// envoyKindResources are the policy resources captured into a snapshot.
func envoyKindResources() []string {
	var out []string
	for k := range envoyPolicyResources {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
