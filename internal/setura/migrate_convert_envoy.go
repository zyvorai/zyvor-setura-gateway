package setura

import (
	"sort"
	"strconv"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// Envoy Gateway to Setura. The Gateway API objects (Gateways, HTTPRoutes,
// GRPCRoutes) are carried over; the Envoy policies attached to them are
// translated onto the route rules (and Gateway listeners) they target by
// builtin.TranslateEnvoyPolicy, the same translation the controller runs with
// --envoy-compat, so the two cannot drift. What a manifest cannot hold
// (backend settings, gateway flags) and what Setura ignores become TODOs.

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
	c.envoyRouteFilters(objs, routes)
	for _, p := range ofKind(objs, "BackendTrafficPolicy", "SecurityPolicy", "ClientTrafficPolicy") {
		c.envoyPolicy(p, routes)
	}
	// Auth annotations are written once the rule indexes are final.
	for _, r := range routes {
		c.envoyFinishAuth(r)
	}
	return nil
}

// envoyRouteFilters resolves ExtensionRef filters that name an HTTPRouteFilter:
// a direct response becomes the rule's direct-response annotation; anything
// else stays as it is (Setura refuses the route) with a TODO.
func (c *converter) envoyRouteFilters(objs []obj, routes []*convRes) {
	filters := map[string]obj{}
	for _, o := range ofKind(objs, "HTTPRouteFilter") {
		name, ns := metaOf(o)
		if ns == "" {
			ns = c.ns
		}
		filters[ns+"/"+name] = o
	}
	for _, r := range routes {
		if r.Kind != kindHTTPRoute {
			continue
		}
		for _, rl := range asList(dig(r.Obj, "spec", "rules")) {
			rule := asMap(rl)
			var keep []any
			for _, f := range asList(rule["filters"]) {
				fm := asMap(f)
				ref := asMap(fm["extensionRef"])
				if asStr(fm["type"]) != "ExtensionRef" || asStr(ref["kind"]) != "HTTPRouteFilter" || asStr(ref["group"]) != builtin.EnvoyGroup {
					keep = append(keep, f)
					continue
				}
				fo := filters[r.NS+"/"+asStr(ref["name"])]
				if fo == nil {
					r.Comments = append(r.Comments, c.todo("HTTPRoute "+r.NS+"/"+r.Name, "extensionRef", asStr(ref["name"]), "the HTTPRouteFilter is not among the input objects"))
					keep = append(keep, f)
					continue
				}
				src := envoySrc(fo)
				tr := builtin.TranslateHTTPRouteFilter(asMap(fo["spec"]), r.NS)
				clean := tr.Block != nil || tr.Inject != nil
				for _, n := range tr.Notes {
					clean = clean && n.Applied()
				}
				for _, n := range tr.Notes {
					if n.Ignored || !n.Applied() {
						reason := n.Reason
						if reason == "" {
							reason = "no Setura equivalent"
						}
						r.Comments = append(r.Comments, c.todo(src, n.Field, n.Value, reason))
					}
				}
				if !clean {
					keep = append(keep, f) // Setura refuses the ExtensionRef: serving without it would change the route
					continue
				}
				if tr.Block != nil {
					rule["#ext"] = mergeObj(asMap(rule["#ext"]), obj{builtin.DirectResponseKey: deepCopy(tr.Block)})
					delete(rule, "backendRefs")
					c.done(src, "directResponse", "", envoyTargetText("directResponse", ""))
				}
				if tr.Inject != nil {
					rule["#auth"] = mergeObj(asMap(rule["#auth"]), obj{"inject": []any{deepCopy(tr.Inject)}})
					c.done(src, "credentialInjection", "", envoyTargetText("credentialInjection", ""))
				}
			}
			if len(keep) == 0 {
				delete(rule, "filters")
			} else {
				rule["filters"] = keep
			}
		}
	}
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
	kind := asStr(p["kind"])
	type target struct {
		res     *convRes
		section string
	}
	var targets []target
	var gateways []*convRes
	for _, t := range envoyTargets(p) {
		ms := c.envoyMatching(p, routes, t)
		if t.kind == "Gateway" {
			_, pns := metaOf(p)
			for _, g := range c.res {
				if g.Kind == "Gateway" && g.Name == t.name && (g.NS == pns || pns == "") {
					gateways = append(gateways, g)
				}
			}
		}
		if len(ms) == 0 && !(t.kind == "Gateway" && len(gateways) > 0) {
			c.record(convItem{Source: src, Key: "targetRefs", Value: t.kind + " " + t.name, Status: convTodo,
				Reason: "the target is not among the converted routes or their Gateways; nothing was changed for it"})
			continue
		}
		for _, m := range ms {
			targets = append(targets, target{m, t.section})
		}
	}
	if len(targets) == 0 && len(gateways) == 0 {
		return
	}
	// One translation per kind of route: GRPCRoute rules take auth only.
	for _, tk := range []string{kindHTTPRoute, kindGRPCRoute} {
		var res []*convRes
		var sections []string
		for _, t := range targets {
			if t.res.Kind == tk {
				res = append(res, t.res)
				sections = append(sections, t.section)
			}
		}
		if len(res) == 0 || kind == "ClientTrafficPolicy" {
			continue
		}
		tr := builtin.TranslateEnvoyPolicy(kind, spec, c.envoyOptions(p, tk))
		c.envoyApply(src, tr, res, sections)
	}
	if kind == "ClientTrafficPolicy" {
		tr := builtin.TranslateEnvoyPolicy(kind, spec, c.envoyOptions(p, "Gateway"))
		c.envoyListeners(src, tr, p, gateways)
	}
}

// envoyOptions reads the translation options of a policy from its annotations.
func (c *converter) envoyOptions(p obj, targetKind string) builtin.EnvoyOptions {
	name, ns := metaOf(p)
	if ns == "" {
		ns = c.ns
	}
	ann := map[string]string{}
	for k, v := range asMap(asMap(p["metadata"])["annotations"]) {
		ann[k] = asStr(v)
	}
	return builtin.EnvoyOptionsFor(ann, ns, name, targetKind)
}

// envoyApply writes a translation into the targeted route rules (and the
// comments of the routes) and records what happened to every field.
func (c *converter) envoyApply(src string, tr *builtin.EnvoyTranslation, targets []*convRes, sections []string) {
	todo := func(key, value, reason string) {
		line := c.todo(src, key, value, reason)
		for _, t := range targets {
			t.Comments = append(t.Comments, line)
		}
	}
	// apply runs fn for every rule the policy applies to, on every target.
	apply := func(fn func(route *convRes, rule obj, idx int)) {
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
	for _, k := range sortedKeys(tr.Rule) {
		v := tr.Rule[k]
		switch k {
		case "timeouts", "retry":
			apply(func(r *convRes, rule obj, _ int) {
				if k == "timeouts" {
					rule[k] = mergeObj(asMap(rule[k]), deepCopy(v).(obj))
				} else {
					rule[k] = deepCopy(v)
				}
			})
		default: // setura.zyvor.dev/rate-limit, fault, direct-response: route annotations, one per rule
			apply(func(r *convRes, rule obj, _ int) {
				rule["#ext"] = mergeObj(asMap(rule["#ext"]), obj{k: deepCopy(v)})
			})
		}
	}
	// A load balancer is a backend setting in the controller; a manifest holds it as the rule's
	// setura.zyvor.dev/load-balancer annotation (HTTPRoute rules only).
	moved := map[string]bool{}
	if lb := tr.Backend["loadBalancer"]; lb != nil {
		any := false
		apply(func(r *convRes, rule obj, _ int) {
			if r.Kind == kindHTTPRoute {
				rule["#ext"] = mergeObj(asMap(rule["#ext"]), obj{builtin.LoadBalancerKey: deepCopy(lb)})
				any = true
			}
		})
		moved["loadBalancer"] = any
	}
	if len(tr.Filters) > 0 {
		apply(func(r *convRes, rule obj, _ int) {
			for _, f := range tr.Filters {
				rule["filters"] = append(asList(rule["filters"]), deepCopy(f))
			}
		})
	}
	for _, k := range sortedKeys(tr.Auth) {
		v := tr.Auth[k]
		apply(func(r *convRes, rule obj, _ int) {
			rule["#auth"] = mergeObj(asMap(rule["#auth"]), obj{k: deepCopy(v)})
		})
	}
	if tr.APIKey != nil {
		todo("apiKeyAuth", "", "the converter cannot read the Secret: store each key as a hash with `setura gateway hash --kind apikey` in an auth apiKey block (the controller with --envoy-compat does this from the Secret)")
	}
	if len(tr.FailClosed) > 0 {
		todo("security", strings.Join(tr.FailClosed, ", "), "these guards cannot be translated: the converted routes are NOT protected by them; the controller with --envoy-compat refuses the traffic instead")
	}
	c.envoyNotes(src, tr.Notes, todo, moved)
}

// envoyNotes turns the field notes into report items: one converted line per
// top-level field, a TODO for everything ignored or without a manifest field.
func (c *converter) envoyNotes(src string, notes []builtin.FieldNote, todo func(key, value, reason string), moved map[string]bool) {
	doneKeys := map[string]bool{}
	for _, n := range notes {
		top, _, _ := strings.Cut(n.Field, ".")
		switch {
		case moved[top] && !n.Ignored && n.Applied():
			if !doneKeys[top] {
				doneKeys[top] = true
				c.done(src, top, "", envoyTargetText(top, n.Setura))
			}
		case n.Ignored:
			reason := n.Reason
			if reason == "" {
				reason = "no Setura equivalent"
			}
			todo(n.Field, n.Value, reason)
		case n.Where == "backend" || n.Where == "listener" || n.Where == "frontend":
			todo(n.Field, n.Value, "has no field in a manifest: the controller (--envoy-compat) translates it to "+n.Setura+"; offline set it in a config file or with the gateway flags (see docs/envoy-compat.md)")
		case !doneKeys[top]:
			doneKeys[top] = true
			c.done(src, top, "", envoyTargetText(top, n.Setura))
		}
	}
}

// envoyTargetText names what a converted top-level field became.
func envoyTargetText(top, fallback string) string {
	if t, ok := map[string]string{
		"retry":               "rule retry (attempts, codes, backoff, perTryTimeout)",
		"timeout":             "rule timeouts.request",
		"rateLimit":           "rule setura.zyvor.dev/rate-limit (route annotation)",
		"faultInjection":      "rule setura.zyvor.dev/fault (route annotation, ttl 24h)",
		"mirrors":             "RequestMirror filter on every targeted rule",
		"cors":                "CORS filter on every targeted rule",
		"jwt":                 "setura.zyvor.dev/auth jwt",
		"extAuth":             "ExternalAuth filter",
		"authorization":       "setura.zyvor.dev/auth ipAllow / ipDeny",
		"directResponse":      "rule setura.zyvor.dev/direct-response (route annotation)",
		"loadBalancer":        "rule setura.zyvor.dev/load-balancer (route annotation)",
		"compression":         "rule setura.zyvor.dev/compress (route annotation)",
		"requestBuffer":       "rule setura.zyvor.dev/limits maxRequestBody (route annotation)",
		"oidc":                "setura.zyvor.dev/auth oidc",
		"credentialInjection": "setura.zyvor.dev/auth inject",
		"tls":                 "Gateway listener tls.options and spec.tls.frontend",
	}[top]; ok {
		return t
	}
	return fallback
}

// envoyListeners applies a ClientTrafficPolicy to the Gateways it targets:
// listener TLS version bounds and client certificate validation.
func (c *converter) envoyListeners(src string, tr *builtin.EnvoyTranslation, p obj, gateways []*convRes) {
	todo := func(key, value, reason string) {
		line := c.todo(src, key, value, reason)
		for _, g := range gateways {
			g.Comments = append(g.Comments, line)
		}
	}
	section := ""
	if ts := envoyTargets(p); len(ts) > 0 {
		section = ts[0].section
	}
	for _, g := range gateways {
		for _, l := range asList(dig(g.Obj, "spec", "listeners")) {
			lm := asMap(l)
			if section != "" && asStr(lm["name"]) != section {
				continue
			}
			if asMap(lm["tls"]) != nil && len(tr.Listener) > 0 {
				tls := asMap(lm["tls"])
				opts := asMap(tls["options"])
				if opts == nil {
					opts = obj{}
					tls["options"] = opts
				}
				if v, ok := tr.Listener["tlsMinVersion"].(string); ok {
					opts[builtin.TLSMinVersionOption] = v
				}
				if v, ok := tr.Listener["tlsMaxVersion"].(string); ok {
					opts[builtin.TLSMaxVersionOption] = v
				}
				if v, ok := tr.Listener["tlsCipherSuites"].(string); ok {
					opts[builtin.TLSCipherSuitesOption] = v
				}
				if v, ok := tr.Listener["tlsSessionResumption"].(string); ok {
					opts[builtin.TLSSessionResumptionOption] = v
				}
			}
		}
		if len(tr.Frontend) > 0 {
			spec := asMap(g.Obj["spec"])
			tls := asMap(spec["tls"])
			if tls == nil {
				tls = obj{}
				spec["tls"] = tls
			}
			val := deepCopy(tr.Frontend).(obj)
			if allow, ok := val[builtin.ClientAllowKey]; ok {
				// the Gateway API schema has no such field: the allow-list is a Gateway annotation
				delete(val, builtin.ClientAllowKey)
				meta := asMap(g.Obj["metadata"])
				if asMap(meta["annotations"]) == nil {
					meta["annotations"] = obj{}
				}
				asMap(meta["annotations"])[builtin.ClientAllowKey] = string(jsonCompact(allow))
			}
			tls["frontend"] = obj{"default": obj{"validation": val}}
		}
	}
	done := map[string]bool{}
	for _, n := range tr.Notes {
		top, _, _ := strings.Cut(n.Field, ".")
		switch {
		case n.Where == "listener" && strings.HasPrefix(n.Field, "connection.") && !n.Ignored:
			todo(n.Field, n.Value, "has no field in a manifest: the controller (--envoy-compat) translates it to "+n.Setura+"; offline use --max-connections, or a limits block on the listener of a snapshot file")
		case n.Ignored && n.Applied():
			todo(n.Field, n.Value, n.Reason)
		case n.Ignored:
			reason := n.Reason
			if reason == "" {
				reason = "no Setura equivalent"
			}
			todo(n.Field, n.Value, reason)
		case !done[top]:
			done[top] = true
			c.done(src, top, "", envoyTargetText(top, n.Setura))
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

// envoyFinishAuth moves the temporary "#auth" rule markers into route
// annotations, as the gateway reads them.
func (c *converter) envoyFinishAuth(r *convRes) {
	rules := asList(dig(r.Obj, "spec", "rules"))
	var ann map[string]any
	annotations := func() map[string]any {
		if ann == nil {
			meta := asMap(r.Obj["metadata"])
			if asMap(meta["annotations"]) == nil {
				meta["annotations"] = obj{}
			}
			ann = asMap(meta["annotations"])
		}
		return ann
	}
	for i, rl := range rules {
		rm := asMap(rl)
		if a, ok := rm["#auth"]; ok {
			delete(rm, "#auth")
			annotations()["setura.zyvor.dev/auth.rule-"+strconv.Itoa(i+1)] = string(jsonCompact(a))
		}
		if e, ok := rm["#ext"]; ok {
			delete(rm, "#ext")
			for _, k := range sortedKeys(asMap(e)) {
				annotations()[k+".rule-"+strconv.Itoa(i+1)] = string(jsonCompact(asMap(e)[k]))
			}
		}
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
