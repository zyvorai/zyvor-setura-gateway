package setura

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Envoy Gateway to Setura. The Gateway API objects (Gateways, HTTPRoutes,
// GRPCRoutes) are carried over; the Envoy policies attached to them are
// translated onto the route rules they target:
//
//	BackendTrafficPolicy  timeout.http.requestTimeout -> timeouts.request, retry -> retry,
//	                      rateLimit and the rest -> TODO
//	SecurityPolicy        cors -> CORS filter, jwt -> auth jwt, authorization CIDR rules -> ipAllow/ipDeny,
//	                      basicAuth -> auth basic (users are a TODO), extAuth -> ExternalAuth filter
//	ClientTrafficPolicy   every field is a TODO (client-side connection settings are not route fields)

func envoySrc(p obj) string {
	n, ns := metaOf(p)
	return asStr(p["kind"]) + " " + ns + "/" + n
}

type envoyTarget struct {
	kind, name, section string
}

func envoyTargets(p obj) []envoyTarget {
	var out []envoyTarget
	refs := asList(dig(p, "spec", "targetRefs"))
	if r := asMap(dig(p, "spec", "targetRef")); r != nil {
		refs = append(refs, r)
	}
	for _, r := range refs {
		m := asMap(r)
		out = append(out, envoyTarget{asStr(m["kind"]), asStr(m["name"]), asStr(m["sectionName"])})
	}
	return out
}

// envoyRoute is a copied route and the rules of it.
type envoyRoute struct {
	res *convRes
}

func (c *converter) convertEnvoy(objs []obj) error {
	var routes []*convRes
	for _, o := range objs {
		kind := asStr(o["kind"])
		if kind != kindHTTPRoute && kind != kindGRPCRoute && kind != "Gateway" {
			continue
		}
		cp := deepCopy(o).(obj)
		name, ns := metaOf(cp)
		if ns == "" {
			ns = c.ns
			meta := asMap(cp["metadata"])
			meta["namespace"] = ns
		}
		delete(asMap(cp["metadata"]), "resourceVersion")
		delete(asMap(cp["metadata"]), "uid")
		delete(cp, "status")
		if c.gwClass != "" && kind == "Gateway" {
			asMap(cp["spec"])["gatewayClassName"] = c.gwClass
		}
		meta := asMap(cp["metadata"])
		delete(meta, "creationTimestamp")
		r := &convRes{Kind: kind, NS: ns, Name: name, Obj: cp}
		c.byKey[kind+"|"+ns+"|"+name] = r
		c.res = append(c.res, r)
		if kind != "Gateway" {
			routes = append(routes, r)
			for _, rr := range extractRouteRules(cp) {
				c.envoyOrig = append(c.envoyOrig, routeSig(rr))
			}
		}
	}
	if len(routes) == 0 {
		return userError("no HTTPRoute or GRPCRoute objects found; nothing to convert")
	}
	for _, p := range ofKind(objs, "BackendTrafficPolicy", "SecurityPolicy", "ClientTrafficPolicy") {
		c.envoyPolicy(p, routes)
	}
	// Auth annotations are written once the rule indexes are final.
	for _, r := range routes {
		c.envoyFinishAuth(r)
	}
	return nil
}

func routeSig(rr *routeRule) string {
	var bs []string
	for _, b := range rr.Backends {
		bs = append(bs, b.Name+":"+strconv.Itoa(b.Port))
	}
	sort.Strings(bs)
	return strings.Join([]string{rr.Kind, rr.NS, rr.Route, rr.Host, rr.Path, rr.Type, strings.Join(bs, ",")}, "|")
}

func (c *converter) envoyCheck(routes []obj) *convCheck {
	var have []string
	for _, rt := range routes {
		for _, rr := range extractRouteRules(rt) {
			have = append(have, routeSig(rr))
		}
	}
	want := append([]string{}, c.envoyOrig...)
	sort.Strings(have)
	sort.Strings(want)
	ck := &convCheck{Summary: map[string]int{statusEquivalent: len(have)}}
	var notes []string
	if strings.Join(have, "\n") != strings.Join(want, "\n") {
		notes = append(notes, "the generated route rules differ from the input route rules")
	}
	ck.Notes = notes
	ck.OK = len(notes) == 0
	if !ck.OK {
		ck.Summary = map[string]int{statusDifferent: 1}
	}
	return ck
}

// matching returns the routes a policy attaches to.
func (c *converter) envoyMatching(p obj, routes []*convRes, t envoyTarget) []*convRes {
	_, pns := metaOf(p)
	var out []*convRes
	for _, r := range routes {
		if r.NS != pns && pns != "" {
			continue
		}
		switch t.kind {
		case kindHTTPRoute, kindGRPCRoute:
			if r.Kind == t.kind && r.Name == t.name {
				out = append(out, r)
			}
		case "Gateway":
			for _, pr := range asList(dig(r.Obj, "spec", "parentRefs")) {
				if asStr(asMap(pr)["name"]) == t.name {
					out = append(out, r)
					break
				}
			}
		}
	}
	return out
}

func (c *converter) envoyPolicy(p obj, routes []*convRes) {
	src := envoySrc(p)
	spec := asMap(p["spec"])
	var targets []*convRes
	var sections []string
	for _, t := range envoyTargets(p) {
		ms := c.envoyMatching(p, routes, t)
		if len(ms) == 0 {
			c.record(convItem{Source: src, Key: "targetRefs", Value: t.kind + " " + t.name, Status: convTodo,
				Reason: "the target is not among the converted routes or their Gateways; nothing was changed for it"})
			continue
		}
		for _, m := range ms {
			targets = append(targets, m)
			sections = append(sections, t.section)
		}
	}
	if len(targets) == 0 {
		return
	}
	todo := func(key, value, reason string) {
		line := c.todo(src, key, value, reason)
		for _, t := range targets {
			t.Comments = append(t.Comments, line)
		}
	}
	// applyRules runs fn for every rule the policy applies to, on every target.
	applyRules := func(fn func(route *convRes, rule obj, idx int)) {
		for i, t := range targets {
			rules := asList(dig(t.Obj, "spec", "rules"))
			any := false
			for j, r := range rules {
				rm := asMap(r)
				if sections[i] == "" || asStr(rm["name"]) == sections[i] {
					fn(t, rm, j)
					any = true
				}
			}
			if !any && sections[i] != "" {
				for j, r := range rules {
					fn(t, asMap(r), j)
				}
			}
		}
	}
	httpOnly := func(key, value string) bool {
		for _, t := range targets {
			if t.Kind != kindHTTPRoute {
				todo(key, value, "this setting converts to an HTTPRoute field or filter and "+t.Kind+" "+t.Name+" is a "+t.Kind)
				return false
			}
		}
		return true
	}
	switch asStr(p["kind"]) {
	case "BackendTrafficPolicy":
		c.envoyBackendTraffic(src, spec, applyRules, todo, httpOnly)
	case "SecurityPolicy":
		c.envoySecurity(src, spec, applyRules, todo, httpOnly)
	case "ClientTrafficPolicy":
		for _, k := range sortedKeys(spec) {
			switch k {
			case "targetRef", "targetRefs", "targetSelectors":
				continue
			case "clientIPDetection":
				todo(k, "", "client address detection is a gateway option: setura gateway run --trusted-proxies lists the proxies whose X-Forwarded-For is trusted")
			case "tls":
				todo(k, "", "listener TLS options belong on the Gateway listener (tls.options) or in the gateway's TLS flags")
			case "timeout":
				todo(k, "", "client side timeouts (idle, request received) are connection settings of the data plane, not route fields; see docs/resilience.md for the gateway's timeouts")
			default:
				todo(k, "", "client connection settings have no Gateway API equivalent")
			}
		}
	}
}

type envoyApply func(fn func(route *convRes, rule obj, idx int))

func envoyDuration(v any) (string, bool) {
	s := fmt.Sprint(v)
	if s == "" || s == "<nil>" {
		return "", false
	}
	return durationOf(s)
}

func (c *converter) envoyBackendTraffic(src string, spec obj, apply envoyApply, todo func(k, v, r string), httpOnly func(k, v string) bool) {
	for _, k := range sortedKeys(spec) {
		switch k {
		case "targetRef", "targetRefs", "targetSelectors":
		case "timeout":
			t := asMap(spec[k])
			for _, tk := range sortedKeys(t) {
				for _, f := range sortedKeys(asMap(t[tk])) {
					path := "timeout." + tk + "." + f
					v := fmt.Sprint(asMap(t[tk])[f])
					if tk == "http" && f == "requestTimeout" {
						d, ok := envoyDuration(v)
						if !ok {
							todo(path, v, "the value is not a duration Setura can read")
						} else if httpOnly(path, v) {
							apply(func(r *convRes, rule obj, _ int) {
								rule["timeouts"] = mergeObj(asMap(rule["timeouts"]), obj{"request": d})
							})
							c.done(src, path, v, "rule timeouts.request")
						}
						continue
					}
					todo(path, v, "HTTPRoute timeouts cover the request and the backend request only; connection and idle timeouts are data plane settings")
				}
			}
		case "retry":
			rt := asMap(spec[k])
			retry := obj{}
			attempts := 2
			if n, ok := num(rt["numRetries"]); ok {
				attempts = int(n)
			}
			retry["attempts"] = attempts
			if codes := asList(dig(rt, "retryOn", "httpStatusCodes")); len(codes) > 0 {
				retry["codes"] = codes
			}
			if d, ok := envoyDuration(dig(rt, "perRetry", "timeout")); ok {
				retry["perTryTimeout"] = d
			}
			if d, ok := envoyDuration(dig(rt, "perRetry", "backOff", "baseInterval")); ok {
				retry["backoff"] = d
			}
			if httpOnly(k, "") {
				apply(func(r *convRes, rule obj, _ int) { rule["retry"] = deepCopy(retry) })
				c.done(src, k, fmt.Sprintf("numRetries=%d", attempts), "rule retry (attempts, codes, backoff, perTryTimeout)")
				for _, trig := range asList(dig(rt, "retryOn", "triggers")) {
					if t := fmt.Sprint(trig); t != "connect-failure" && t != "retriable-status-codes" && t != "5xx" {
						todo(k+".retryOn.triggers", t, "the gateway retries connection failures and the listed status codes only; this trigger has no equivalent")
					}
				}
			}
		case "rateLimit":
			hint := "the Setura gateway rate limit is gateway-wide (setura gateway run --rate-limit N/s|m|h), not per route"
			for _, rl := range asList(dig(asMap(spec[k]), "local", "rules")) {
				if n, ok := num(dig(rl, "limit", "requests")); ok {
					unit := map[string]string{"Second": "s", "Minute": "m", "Hour": "h"}[asStr(dig(rl, "limit", "unit"))]
					if unit != "" {
						hint += "; this policy allows " + strconv.Itoa(int(n)) + "/" + unit + " (--rate-limit " + strconv.Itoa(int(n)) + "/" + unit + ")"
					}
					break
				}
			}
			todo(k, "", hint)
		case "circuitBreaker", "healthCheck":
			todo(k, "", "configured with gateway flags, not per route; see docs/resilience.md")
		case "loadBalancer":
			todo(k, "", "the Setura gateway balances weighted backendRefs itself; consistent hash, least request and similar have no field")
		default:
			todo(k, "", "no per-policy equivalent in Gateway API or the Setura gateway")
		}
	}
}

func mergeObj(a, b obj) obj {
	if a == nil {
		a = obj{}
	}
	for k, v := range b {
		a[k] = v
	}
	return a
}

func (c *converter) envoySecurity(src string, spec obj, apply envoyApply, todo func(k, v, r string), httpOnly func(k, v string) bool) {
	addFilter := func(f obj) {
		apply(func(r *convRes, rule obj, _ int) {
			rule["filters"] = append(asList(rule["filters"]), deepCopy(f))
		})
	}
	setAuth := func(field string, v any) {
		apply(func(r *convRes, rule obj, _ int) {
			rule["#auth"] = mergeObj(asMap(rule["#auth"]), obj{field: deepCopy(v)})
		})
	}
	for _, k := range sortedKeys(spec) {
		sp := asMap(spec[k])
		switch k {
		case "targetRef", "targetRefs", "targetSelectors":
		case "cors":
			if !httpOnly(k, "") {
				continue
			}
			cors := obj{}
			var origins []any
			for _, o := range asList(sp["allowOrigins"]) {
				origins = append(origins, fmt.Sprint(o))
			}
			cors["allowOrigins"] = origins
			for _, f := range []string{"allowMethods", "allowHeaders", "exposeHeaders", "allowCredentials"} {
				if v, ok := sp[f]; ok {
					cors[f] = v
				}
			}
			if v, ok := sp["maxAge"]; ok {
				if d, ok := durationOf(fmt.Sprint(v)); ok {
					cors["maxAge"] = int(durationSeconds(d))
				}
			}
			addFilter(obj{"type": "CORS", "cors": cors})
			c.done(src, k, "", "CORS filter on every targeted rule")
		case "jwt":
			if !httpOnly(k, "") {
				continue
			}
			provs := asList(sp["providers"])
			for i, pv := range provs {
				pm := asMap(pv)
				if i > 0 {
					todo("jwt.providers["+strconv.Itoa(i)+"]", asStr(pm["name"]), "an auth block accepts one JWT issuer; add this provider by splitting the rules or merging issuers by hand")
					continue
				}
				jwt := obj{}
				if v := asStr(pm["issuer"]); v != "" {
					jwt["issuer"] = v
				}
				if a := asList(pm["audiences"]); len(a) > 0 {
					jwt["audience"] = a
				}
				if v := asStr(dig(pm, "remoteJWKS", "uri")); v != "" {
					jwt["jwksUri"] = v
				}
				ch := obj{}
				for _, m := range asList(pm["claimToHeaders"]) {
					mm := asMap(m)
					ch[asStr(mm["header"])] = asStr(mm["claim"])
				}
				if len(ch) > 0 {
					jwt["claimHeaders"] = ch
				}
				setAuth("jwt", jwt)
				c.done(src, "jwt.providers["+asStr(pm["name"])+"]", asStr(pm["issuer"]), "setura.zyvor.dev/auth jwt")
				for _, f := range []string{"extractFrom", "recomputeRoute", "localJWKS", "audiences"} {
					if _, ok := pm[f]; ok && f != "audiences" {
						todo("jwt.providers."+f, asStr(pm["name"]), "no equivalent: the gateway reads the token from Authorization: Bearer and fetches the JWKS from the URL")
					}
				}
				if len(asList(pm["audiences"])) == 0 {
					todo("jwt.providers.audiences", asStr(pm["name"]), "no audience is set; always set one (lint rule SET016)")
				}
			}
		case "basicAuth":
			if !httpOnly(k, "") {
				continue
			}
			setAuth("basic", obj{"users": []any{}})
			todo(k, asStr(dig(sp, "users", "name")), "the basic auth block has no users: Envoy reads htpasswd entries from a Secret, Setura stores pbkdf2-sha256 hashes; create each user with `setura gateway hash --kind password`")
		case "authorization":
			allow, deny := []any{}, []any{}
			ok := true
			for _, r := range asList(sp["rules"]) {
				rm := asMap(r)
				cidrs := asList(dig(rm, "principal", "clientCIDRs"))
				if len(cidrs) == 0 || len(asMap(rm["principal"])) != 1 {
					ok = false
					break
				}
				if strings.EqualFold(asStr(rm["action"]), "Allow") {
					allow = append(allow, cidrs...)
				} else {
					deny = append(deny, cidrs...)
				}
			}
			if !ok || !httpOnly(k, "") {
				todo(k, "", "only rules on principal.clientCIDRs convert (to ipAllow and ipDeny); JWT claim and scope rules need a policy engine")
				continue
			}
			if len(allow) > 0 && strings.EqualFold(asStr(sp["defaultAction"]), "Deny") {
				setAuth("ipAllow", allow)
			} else if len(allow) > 0 {
				todo(k, "", "an Allow rule with defaultAction Allow permits everyone; there is nothing to enforce")
			}
			if len(deny) > 0 {
				setAuth("ipDeny", deny)
			}
			c.done(src, k, "", "setura.zyvor.dev/auth ipAllow / ipDeny")
		case "extAuth":
			if !httpOnly(k, "") {
				continue
			}
			proto, body := "HTTP", asMap(sp["http"])
			if g := asMap(sp["grpc"]); g != nil {
				proto, body = "GRPC", g
			}
			refs := asList(body["backendRefs"])
			if len(refs) == 0 {
				refs = []any{body["backendRef"]}
			}
			bm := asMap(refs[0])
			if bm == nil {
				todo(k, "", "the policy has no backendRef (a Service is required by ExternalAuth)")
				continue
			}
			port, _ := num(bm["port"])
			ea := obj{"protocol": proto, "backendRef": backendRef(asStr(bm["name"]), asStr(bm["namespace"]), int(port), -1)}
			if proto == "HTTP" {
				h := obj{}
				if p := asStr(body["path"]); p != "" {
					h["path"] = p
				}
				if hs := asList(body["headersToBackend"]); len(hs) > 0 {
					h["allowedResponseHeaders"] = hs
				}
				if len(h) > 0 {
					ea["http"] = h
				}
			}
			addFilter(obj{"type": "ExternalAuth", "externalAuth": ea})
			c.done(src, k, proto, "ExternalAuth filter")
		default:
			todo(k, "", "no equivalent in Gateway API or the Setura gateway (apiKeyAuth, oidc, wasm and similar are not converted)")
		}
	}
}

// envoyFinishAuth moves the temporary "#auth" rule markers into route
// annotations, as the gateway reads them.
func (c *converter) envoyFinishAuth(r *convRes) {
	rules := asList(dig(r.Obj, "spec", "rules"))
	var ann map[string]any
	for i, rl := range rules {
		rm := asMap(rl)
		a, ok := rm["#auth"]
		if !ok {
			continue
		}
		delete(rm, "#auth")
		if ann == nil {
			meta := asMap(r.Obj["metadata"])
			if asMap(meta["annotations"]) == nil {
				meta["annotations"] = obj{}
			}
			ann = asMap(meta["annotations"])
		}
		ann["setura.zyvor.dev/auth.rule-"+strconv.Itoa(i+1)] = string(jsonCompact(a))
	}
	// Comments that name the same line twice are noise.
	seen := map[string]bool{}
	var cs []string
	for _, cm := range r.Comments {
		if !seen[cm] {
			seen[cm] = true
			cs = append(cs, cm)
		}
	}
	r.Comments = cs
}
