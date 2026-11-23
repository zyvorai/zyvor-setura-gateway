package setura

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// annotationFor finds the value of a rule's annotation: the rule specific one
// (base.rule-N) wins over the route wide one (base).
func annotationFor(spec obj, base string, rule int) (key, value string, ok bool) {
	ann := asMap(spec[builtin.SeturaAnnotationsKey])
	for _, k := range []string{fmt.Sprintf("%s.rule-%d", base, rule+1), base} {
		if v, found := ann[k].(string); found {
			return k, v, true
		}
	}
	return "", "", false
}

// aiBlockFor returns the raw AI block of rule i: its own, or its annotation.
func aiBlockFor(spec obj, i int, rule obj) (raw []byte, where string, ok bool) {
	if b, has := rule[builtin.AIKey]; has {
		raw, _ := json.Marshal(b)
		return raw, fmt.Sprintf("rule %d", i+1), true
	}
	if k, v, has := annotationFor(spec, builtin.AIKey, i); has {
		return []byte(v), "annotation " + k, true
	}
	return nil, "", false
}

func hasAIBlock(spec obj, i int, rule obj) bool {
	_, _, ok := aiBlockFor(spec, i, rule)
	return ok
}

// authFor returns the parsed auth policy of rule i, nil when there is none (or it is unparsable: SET018 says so).
func authFor(spec obj, i int, rule obj) *builtin.AuthPolicy {
	var raw []byte
	if b, has := rule[builtin.AuthKey]; has {
		raw, _ = json.Marshal(b)
	} else if _, v, has := annotationFor(spec, builtin.AuthKey, i); has {
		raw = []byte(v)
	}
	if raw == nil {
		return nil
	}
	p, err := builtin.ParseAuthBlock(raw)
	if err != nil {
		return nil
	}
	if p.Enabled != nil && !*p.Enabled {
		return nil
	}
	return p
}

// privateHost reports whether a provider host is loopback, a private address or
// an in-cluster name, where a plain http call does not cross the open network.
func privateHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return h == "localhost" || !strings.Contains(h, ".") || strings.HasSuffix(h, ".svc") || strings.HasSuffix(h, ".cluster.local") ||
		strings.Contains(h, ".svc.")
}

// aiRules evaluates SET040 to SET047 over HTTPRoutes: the AI block must parse
// and validate the way the gateway compiles it, and obvious misconfigurations
// (a budget nobody can be identified for, an open route, a key in clear text on
// the wire) are flagged.
func aiRules(specs obj, ns string) []obj {
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
		spec := asMap(specs[key])
		rules := asList(spec["rules"])
		rawAnn := map[string]string{}
		ann := asMap(spec[builtin.SeturaAnnotationsKey])
		for _, k := range sortedKeys(ann) {
			if !strings.HasPrefix(k, builtin.AIKey) {
				continue
			}
			v, ok := ann[k].(string)
			if !ok {
				add("SET040", fmt.Sprintf("annotation %s: the value must be a JSON string", k))
				continue
			}
			rawAnn[k] = v
		}
		for _, k := range builtin.OrphanAIAnnotations(rawAnn, len(rules)) {
			add("SET040", fmt.Sprintf("annotation %s names no rule: use %s for the whole route or %s.rule-N with N from 1 to %d", k, builtin.AIKey, builtin.AIKey, len(rules)))
		}
		for i, r := range rules {
			rule := asMap(r)
			raw, where, ok := aiBlockFor(spec, i, rule)
			if !ok {
				continue
			}
			p, err := builtin.ParseAIBlock(raw)
			if err != nil {
				add("SET040", fmt.Sprintf("%s: %v", where, err))
				continue
			}
			if p.Enabled != nil && !*p.Enabled {
				continue
			}
			auth := authFor(spec, i, rule)
			kind, _, _ := strings.Cut(p.Identity, ":")
			if kind == "" {
				kind = "subject"
			}
			if len(asList(rule["backendRefs"])) > 0 {
				add("SET047", where+": backendRefs are ignored on an AI rule")
			}
			if auth == nil {
				add("SET044", where+": the AI route has no auth policy, so anyone who can reach the gateway can spend the provider keys")
			}
			if p.Budget != nil {
				switch {
				case kind == "header":
					if auth == nil {
						add("SET042", fmt.Sprintf("%s: budgets count per %s, which the client sets itself; put a trusted layer in front that overwrites it, or use an authenticated identity", where, p.Identity))
					}
				case auth == nil:
					add("SET041", fmt.Sprintf("%s: the budget counts per identity %q but the rule has no auth policy to provide it, so every request is refused with 401", where, kindOrDefault(p.Identity)))
				case kind == "apikey" && auth.APIKey == nil:
					add("SET041", where+": identity apikey needs an apiKey auth policy; the rule authenticates another way")
				case kind == "claim" && auth.JWT == nil:
					add("SET041", fmt.Sprintf("%s: identity %s needs a jwt auth policy to read the claim from", where, p.Identity))
				}
				budgetLimits := []builtin.AILimits{p.Budget.Default}
				if p.Budget.Route != nil {
					budgetLimits = append(budgetLimits, *p.Budget.Route)
				}
				for _, o := range p.Budget.Overrides {
					budgetLimits = append(budgetLimits, o)
				}
				for _, l := range budgetLimits {
					if l.MonthlyCost > 0 && len(p.Prices) == 0 {
						add("SET046", where+": monthlyCost needs prices (route \"prices\" or the gateway's --ai-prices)")
						break
					}
				}
			}
			if c := p.Cache; c != nil && c.Enabled {
				if c.Scope == "route" && auth != nil {
					add("SET045", where+": the cache is shared across the route's clients (scope route) on a route that authenticates")
				}
				if c.Scope != "route" && kind == "header" && auth == nil {
					add("SET042", fmt.Sprintf("%s: the cache is partitioned by %s, which the client sets itself", where, p.Identity))
				}
			}
			for _, pr := range p.Providers {
				if pr.APIKey != nil && strings.HasPrefix(strings.ToLower(pr.BaseURL), "http://") {
					host := strings.TrimPrefix(strings.ToLower(pr.BaseURL), "http://")
					host, _, _ = strings.Cut(host, "/")
					if !privateHost(host) {
						add("SET043", fmt.Sprintf("%s: provider %s is called over http with an API key; use https", where, pr.Name))
					}
				}
			}
		}
	}
	return findings
}

func kindOrDefault(s string) string {
	if s == "" {
		return "subject"
	}
	return s
}
