package setura

import (
	"fmt"
	"strings"
)

// filterRules evaluates SET090: the filters of an HTTPRoute rule must be
// combinations the Gateway API accepts. A controller that follows the API
// rejects the route (Accepted False, reason IncompatibleFilters or an
// admission error), so a route that lints dirty here is not served as written.
//
//   - URLRewrite and RequestRedirect may not be combined in one rule.
//   - A core filter type may appear at most once in a rule.
//   - A filter's type must have its matching configuration block, and no other.
//   - ReplacePrefixMatch (URLRewrite and RequestRedirect) needs every match of
//     the rule to be a PathPrefix match.
//   - A path modifier's type must match the field it fills.
//   - A redirect scheme is http or https and a redirect port is 1 to 65535.
func filterRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != route {
			continue
		}
		id := "HTTPRoute/" + ns + "/" + name
		add := func(i int, msg string) {
			findings = append(findings, obj{"id": "SET090", "severity": ruleSeverity("SET090"), "resource": id,
				"message": fmt.Sprintf("rule %d: %s", i+1, msg)})
		}
		for i, r := range asList(asMap(specs[key])["rules"]) {
			rule := asMap(r)
			filters := asList(rule["filters"])
			if len(filters) == 0 {
				continue
			}
			onlyPrefix := true
			for _, m := range asList(rule["matches"]) {
				if p := asMap(asMap(m)["path"]); p != nil && str(p, "type", "PathPrefix") != "PathPrefix" {
					onlyPrefix = false
				}
			}
			count := map[string]int{}
			for _, f := range filters {
				fm := asMap(f)
				t := asStr(fm["type"])
				count[t]++
				switch t {
				case "RequestHeaderModifier", "ResponseHeaderModifier", "RequestMirror":
					if field := lowerFirst(t); fm[field] == nil {
						add(i, fmt.Sprintf("filter %s has no %s block", t, field))
					}
				case "URLRewrite":
					rw := asMap(fm["urlRewrite"])
					if rw == nil {
						add(i, "filter URLRewrite has no urlRewrite block")
						break
					}
					checkPathModifier(asMap(rw["path"]), "urlRewrite.path", onlyPrefix, func(m string) { add(i, m) })
				case "RequestRedirect":
					rr := asMap(fm["requestRedirect"])
					if rr == nil {
						add(i, "filter RequestRedirect has no requestRedirect block")
						break
					}
					checkPathModifier(asMap(rr["path"]), "requestRedirect.path", onlyPrefix, func(m string) { add(i, m) })
					if s, ok := rr["scheme"].(string); ok && s != "http" && s != "https" {
						add(i, fmt.Sprintf("requestRedirect.scheme is %q: only http and https are allowed", clipStr(s, 20)))
					}
					if p, ok := num(rr["port"]); ok && (p < 1 || p > 65535 || p != float64(int(p))) {
						add(i, fmt.Sprintf("requestRedirect.port %v is outside 1 to 65535", p))
					}
				}
				if fm["urlRewrite"] != nil && t != "URLRewrite" {
					add(i, fmt.Sprintf("filter of type %s carries a urlRewrite block", t))
				}
				if fm["requestRedirect"] != nil && t != "RequestRedirect" {
					add(i, fmt.Sprintf("filter of type %s carries a requestRedirect block", t))
				}
			}
			if count["URLRewrite"] > 0 && count["RequestRedirect"] > 0 {
				add(i, "URLRewrite and RequestRedirect cannot be combined in one rule (the controller reports IncompatibleFilters)")
			}
			for _, t := range []string{"RequestHeaderModifier", "ResponseHeaderModifier", "URLRewrite", "RequestRedirect"} {
				if count[t] > 1 {
					add(i, fmt.Sprintf("filter %s appears %d times; a core filter may appear once per rule", t, count[t]))
				}
			}
		}
	}
	return findings
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// checkPathModifier validates a urlRewrite.path or requestRedirect.path block.
func checkPathModifier(p obj, where string, onlyPrefix bool, add func(string)) {
	if p == nil {
		return
	}
	switch t := asStr(p["type"]); t {
	case "ReplaceFullPath":
		if _, ok := p["replaceFullPath"].(string); !ok {
			add(where + " has type ReplaceFullPath but no replaceFullPath")
		}
		if p["replacePrefixMatch"] != nil {
			add(where + " has type ReplaceFullPath but also sets replacePrefixMatch")
		}
	case "ReplacePrefixMatch":
		if _, ok := p["replacePrefixMatch"].(string); !ok {
			add(where + " has type ReplacePrefixMatch but no replacePrefixMatch")
		}
		if p["replaceFullPath"] != nil {
			add(where + " has type ReplacePrefixMatch but also sets replaceFullPath")
		}
		if !onlyPrefix {
			add(where + " uses ReplacePrefixMatch, which only works when every match of the rule is a PathPrefix match")
		}
	default:
		add(fmt.Sprintf("%s has type %q: use ReplaceFullPath or ReplacePrefixMatch", where, clipStr(t, 30)))
	}
}
