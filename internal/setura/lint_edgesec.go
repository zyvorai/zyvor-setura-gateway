package setura

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// edgeSecRules evaluates SET060 to SET065: weak or pointless settings of the
// OIDC, authorization, CSRF and credential injection parts of the auth block,
// {claim:NAME} header variables nobody can fill, and invalid listener cipher
// suite and session resumption options. A block that does not parse is
// SET018's business and is skipped here.
func edgeSecRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		switch resource {
		case route, grpcRoute:
			kind := "HTTPRoute"
			if resource == grpcRoute {
				kind = "GRPCRoute"
			}
			id := kind + "/" + ns + "/" + name
			findings = append(findings, edgeRouteRules(id, asMap(specs[key]))...)
		case gateway:
			id := "Gateway/" + ns + "/" + name
			for _, l := range asList(asMap(specs[key])["listeners"]) {
				lm := asMap(l)
				ln := asStr(lm["name"])
				opts := asMap(asMap(lm["tls"])["options"])
				var min uint16
				if v, ok := opts[builtin.TLSMinVersionOption].(string); ok {
					min, _ = builtin.ParseTLSVersion(v)
				}
				if v, ok := opts[builtin.TLSCipherSuitesOption].(string); ok {
					if _, err := builtin.ParseCipherSuites(v); err != nil {
						findings = append(findings, edgeFinding("SET064", id, fmt.Sprintf("listener %q: tls.options %s: %v", ln, builtin.TLSCipherSuitesOption, err)))
					} else if min == 0x0304 {
						findings = append(findings, edgeFinding("SET064", id, fmt.Sprintf("listener %q: tls.options %s has no effect with a TLS 1.3 minimum: TLS 1.3 suites are not configurable", ln, builtin.TLSCipherSuitesOption)))
					}
				}
				if v, ok := opts[builtin.TLSSessionResumptionOption].(string); ok {
					if _, err := builtin.ParseResumption(v); err != nil {
						findings = append(findings, edgeFinding("SET064", id, fmt.Sprintf("listener %q: tls.options %s: %v", ln, builtin.TLSSessionResumptionOption, err)))
					}
				}
			}
		}
	}
	return findings
}

func edgeFinding(rule, resource, msg string) obj {
	return obj{"id": rule, "severity": ruleSeverity(rule), "resource": resource, "message": msg}
}

// effectivePolicy is the auth block that applies to rule i (0-based): the
// inline block, else the rule's annotation, else the route-wide one.
func effectivePolicy(spec obj, rule obj, i int) *builtin.AuthPolicy {
	var raw []byte
	if block, ok := rule[builtin.AuthKey]; ok {
		raw, _ = json.Marshal(block)
	} else {
		ann := asMap(spec[builtin.SeturaAnnotationsKey])
		if v, ok := ann[builtin.AuthRuleAnnotation(i+1)].(string); ok {
			raw = []byte(v)
		} else if v, ok := ann[builtin.AuthKey].(string); ok {
			raw = []byte(v)
		}
	}
	if raw == nil {
		return nil
	}
	p, err := builtin.ParseAuthBlock(raw)
	if err != nil {
		return nil
	}
	return p
}

func filterValues(filters []any) []string {
	var out []string
	for _, f := range filters {
		hm := asMap(asMap(f)["requestHeaderModifier"])
		for _, k := range []string{"set", "add"} {
			for _, nv := range asList(hm[k]) {
				out = append(out, asStr(asMap(nv)["value"]))
			}
		}
	}
	return out
}

func loopbackHost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "::1" || strings.HasPrefix(h, "127.")
}

func edgeRouteRules(id string, spec obj) []obj {
	var findings []obj
	add := func(rule, msg string) { findings = append(findings, edgeFinding(rule, id, msg)) }
	for i, r := range asList(spec["rules"]) {
		rule := asMap(r)
		where := fmt.Sprintf("rule %d", i+1)
		p := effectivePolicy(spec, rule, i)

		// {claim:NAME} variables need a verified JWT or OIDC session.
		var vals []string
		vals = append(vals, filterValues(asList(rule["filters"]))...)
		for _, br := range asList(rule["backendRefs"]) {
			vals = append(vals, filterValues(asList(asMap(br)["filters"]))...)
		}
		for _, v := range vals {
			if names := builtin.ClaimVars(v); len(names) > 0 && (p == nil || (p.JWT == nil && p.OIDC == nil)) {
				add("SET063", fmt.Sprintf("%s: header value %q uses {claim:%s} but the rule has no jwt or oidc policy, so there are never any verified claims and the header is never sent", where, v, names[0]))
			}
		}
		if p == nil {
			continue
		}
		if o := p.OIDC; o != nil {
			if strings.HasPrefix(strings.ToLower(o.Issuer), "http://") && !loopbackHost(o.Issuer) {
				add("SET060", where+": oidc.issuer uses plain http, so the login and the signing keys can be replaced in transit; use https")
			}
			if c := o.Cookie; c != nil {
				if c.Secure != nil && !*c.Secure {
					add("SET060", where+": oidc.cookie.secure is false: the session cookie is sent over plain http; keep it true outside development")
				}
				if strings.EqualFold(c.SameSite, "None") {
					add("SET060", where+": oidc.cookie.sameSite None sends the session cookie on cross-site requests; use Lax unless an embedded flow needs it, and set csrf")
				}
			}
			if o.ClientSecret == nil {
				add("SET060", where+": oidc has no clientSecret (a public client): only PKCE protects the code exchange; confidential clients should set one")
			}
			if p.CSRF == nil {
				add("SET062", where+": oidc authenticates by a cookie the browser sends on its own, and the rule has no csrf block: a POST from another site is accepted; add \"csrf\": {}")
			}
		}
		if a := p.Authorization; a != nil {
			def := a.DefaultAction
			if def == "" {
				def = "deny"
			}
			switch {
			case len(a.Rules) == 0 && def == "deny":
				add("SET061", where+": authorization has no rules and the default action is deny: every authenticated request is refused")
			case len(a.Rules) == 0:
				add("SET061", where+": authorization has no rules and the default action is allow: it changes nothing")
			case def == "allow":
				deny := false
				for _, ar := range a.Rules {
					deny = deny || ar.Action == "deny"
				}
				if !deny {
					add("SET061", where+": authorization allows by default and has only allow rules: they change nothing; set defaultAction deny or add deny rules")
				}
			}
			for j, ar := range a.Rules {
				if len(ar.Principals) == 0 && len(ar.Operations) == 0 && j < len(a.Rules)-1 {
					name := ar.Name
					if name == "" {
						name = fmt.Sprintf("#%d", j+1)
					}
					add("SET061", fmt.Sprintf("%s: authorization rule %s matches every request, so the %d rule(s) after it never run", where, name, len(a.Rules)-1-j))
					break
				}
			}
		}
		if len(p.Inject) > 0 && p.JWT == nil && p.APIKey == nil && p.Basic == nil && p.OIDC == nil && len(p.IPAllow) == 0 && !p.RequireClientCert {
			add("SET065", where+": credentials are injected but nobody has to authenticate: anyone who can reach the route uses them; add an auth method, ipAllow or requireClientCert")
		}
	}
	return findings
}
