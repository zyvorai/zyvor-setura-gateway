package setura

import (
	"encoding/json"
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// authRules evaluates SET016, SET017 and SET018 over HTTPRoutes: every inline
// setura.zyvor.dev/auth block and every setura.zyvor.dev/auth annotation must
// parse and validate the way the built-in gateway compiles them (SET018), and
// obviously weak policies are flagged: a JWT policy that does not check the
// audience (SET016), and API keys or passwords stored in clear text (SET017).
func authRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != route {
			continue
		}
		id := "HTTPRoute/" + ns + "/" + name
		add := func(rule, msg string) {
			findings = append(findings, obj{"id": rule, "severity": ruleSeverity(rule), "resource": id, "message": msg})
		}
		check := func(where string, raw []byte) {
			p, err := builtin.ParseAuthBlock(raw)
			if err != nil {
				add("SET018", fmt.Sprintf("%s: %v", where, err))
				return
			}
			if j := p.JWT; j != nil && len(j.Audience) == 0 {
				add("SET016", where+": the jwt policy has no audience, so a token issued for any other service by the same issuer is accepted; set jwt.audience")
			}
			if j := p.JWT; j != nil && strings.HasPrefix(strings.ToLower(j.JWKSURI), "http://") {
				add("SET016", where+": jwt.jwksUri uses plain http, so the signing keys can be replaced in transit; use https")
			}
			if a := p.APIKey; a != nil {
				for _, k := range a.Keys {
					if k.Key != "" {
						add("SET017", fmt.Sprintf("%s: API key %q is stored in clear text; store a hash (setura gateway hash --kind apikey)", where, k.Name))
					}
				}
			}
			if b := p.Basic; b != nil {
				for _, u := range b.Users {
					if u.Password != "" {
						add("SET017", fmt.Sprintf("%s: password of user %q is stored in clear text; store a hash (setura gateway hash --kind password)", where, u.Name))
					}
				}
			}
		}
		spec := asMap(specs[key])
		rules := asList(spec["rules"])
		for i, r := range rules {
			if block, ok := asMap(r)[builtin.AuthKey]; ok {
				raw, _ := json.Marshal(block)
				check(fmt.Sprintf("rule %d", i+1), raw)
			}
		}
		ann := asMap(spec[builtin.SeturaAnnotationsKey])
		rawAnn := map[string]string{}
		for _, k := range sortedKeys(ann) {
			if !strings.HasPrefix(k, builtin.AuthKey) {
				continue
			}
			v, ok := ann[k].(string)
			if !ok {
				add("SET018", fmt.Sprintf("annotation %s: the value must be a JSON string", k))
				continue
			}
			rawAnn[k] = v
			check("annotation "+k, []byte(v))
		}
		for _, k := range builtin.OrphanAuthAnnotations(rawAnn, len(rules)) {
			add("SET018", fmt.Sprintf("annotation %s names no rule: use %s for the whole route or %s.rule-N with N from 1 to %d", k, builtin.AuthKey, builtin.AuthKey, len(rules)))
		}
	}
	return findings
}
