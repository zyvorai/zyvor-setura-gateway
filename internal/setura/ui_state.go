package setura

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// UIStateSchema identifies the document served at /api/state by "setura ui".
// New top-level sections may be added; the page ignores sections it does not
// know and hides sections that are absent (health, history, traffic, reload).
const UIStateSchema = "setura.ui/v1"

// UIInput is everything the dashboard can show besides the declared specs.
// Every field is optional.
type UIInput struct {
	Mode    string // snapshot, cluster, gateway or watch
	Source  string // human label, for example the snapshot file name
	Now     time.Time
	Redact  bool
	Stats   any // gateway Stats.Snapshot(): per-route and per-backend counters
	Health  any // {"targets":[{url,ok,stage,backend,ms,since}]}
	History any // {"points":[...]} filled by a later release
	Reload  any // {"generation":n,"ok":bool,"time":"...","error":"..."}
	// Connections is {"enabled":true,"capacity":N} when the gateway keeps a
	// connections table; the rows are served separately and never enter the
	// state document.
	Connections any
}

// ruleHelp is the plain-language explanation shown for each lint rule.
var ruleHelp = map[string]struct{ Title, Why, Fix string }{
	"SET001": {"No gateway serves this route", "The route has no parentRefs, so no Gateway will ever pick it up.", "Add a parentRef that names the Gateway (and listener) that should serve it."},
	"SET002": {"All traffic is dropped", "Every backend in this rule has weight 0, so matching requests have nowhere to go.", "Give at least one backendRef a weight above 0, or remove the rule."},
	"SET003": {"Matching requests get an error", "This rule has no backends and no redirect, so matching requests receive a 500.", "Add a backendRef or a RequestRedirect filter to the rule."},
	"SET004": {"Cross-namespace backend needs permission", "The backend lives in another namespace and that namespace has not granted access.", "Create a ReferenceGrant in the backend's namespace that allows this route to reference it."},
	"SET005": {"Listener name does not exist", "The parentRef points at a listener (sectionName) the Gateway does not declare.", "Fix the sectionName, or add a listener with that name to the Gateway."},
	"SET006": {"Hostnames never meet", "The route's hostnames do not overlap the hostname of the listener it attaches to, so it never matches.", "Align the route hostnames with the listener hostname, or attach to a different listener."},
	"SET007": {"Secure listener has no certificate", "An HTTPS or TLS listener needs tls configuration to serve traffic.", "Add tls.certificateRefs to the listener, or change its protocol to HTTP."},
	"SET008": {"Two listeners collide", "Two listeners on one Gateway share a name, or the same port, protocol and hostname.", "Give each listener a unique name and a distinct port or hostname."},
	"SET009": {"Another route shadows this one", "Two routes match the same hostname and path on the same parent, so only one of them is used.", "Make the matches distinct (path, header or hostname), or delete the duplicate."},
	"SET010": {"gRPC route can never serve", "The GRPCRoute has no parentRefs or no rules.", "Add a parentRef and at least one rule."},
	"SET011": {"Hostnames never meet", "The route's hostnames do not overlap the hostname of the listener it attaches to.", "Align the route hostnames with the listener hostname."},
	"SET012": {"Grant permits nothing", "This ReferenceGrant has an empty from or to list.", "Fill in both lists, or delete the grant."},
	"SET013": {"Listener refuses this route", "The listener's allowedRoutes does not admit this route's namespace or kind.", "Widen allowedRoutes on the listener, or move the route to an allowed namespace."},
	"SET014": {"Backend weights are invalid", "A weight is negative or too large, or the rule mixes Service and non-Service backends.", "Use weights from 0 up, and keep one kind of backend per rule."},
	"SET016": {"Auth policy is weak", "A JWT policy has no audience, so tokens issued for other services by the same issuer pass, or its JWKS is fetched over plain http.", "Set jwt.audience to this service's identifier and serve the JWKS over https (see docs/security.md)."},
	"SET017": {"Secret stored in clear text", "An API key or basic auth password is written in the config instead of a hash.", "Store a hash made with setura gateway hash and remove the clear text."},
	"SET018": {"Auth block is invalid", "The auth block or annotation cannot be parsed or compiled, or it names a rule that does not exist. The route is not served.", "Fix the JSON (see docs/security.md)."},
	"SET015": {"Shadow-diff block is invalid", "The shadow-diff block or annotation cannot be parsed, or it names a rule that has no RequestMirror filter.", "Fix the JSON (see docs/shadow.md), or add a RequestMirror filter to that rule."},
	"SET040": {"AI block is invalid", "The AI block or annotation cannot be parsed or validated, or it names a rule that does not exist. The route is not served.", "Fix the JSON (see docs/ai-gateway.md)."},
	"SET041": {"Budget has no identity", "A token budget counts per identity, and the identity the route asks for (API key name, subject or JWT claim) cannot exist without a matching auth policy on the rule. Requests are refused with 401.", "Add the auth policy that provides the identity, or use header:NAME behind a trusted layer."},
	"SET042": {"Identity is client controlled", "The budget or cache identity is a request header. Whoever calls the gateway sets it, so a client can spend another tenant's budget or dodge its own.", "Use an authenticated identity (apikey, subject, claim), or make sure a trusted layer in front sets and overwrites the header."},
	"SET043": {"Provider key sent in clear text", "An AI provider is called over plain http with an API key and the host is not loopback or a cluster address.", "Use an https baseURL."},
	"SET044": {"AI route is open", "The AI route has no auth policy, so anyone who can reach the gateway can spend your provider budget.", "Add an auth policy (API keys or JWT) to the rule."},
	"SET045": {"Cache shared across clients", "The prompt cache scope is the route on a route that authenticates, so a cached answer to one client's prompt can be returned to another.", "Use the default scope (identity) unless every client may see every answer."},
	"SET046": {"Cost budget without prices", "monthlyCost needs a price table. Without prices on the route, only a gateway started with --ai-prices can compute cost.", "Add prices to the AI block, or start the gateway with --ai-prices."},
	"SET070": {"Traffic shaping block is invalid", "The compress, grpc-web or bandwidth block or annotation cannot be parsed or validated (an unknown field, brotli or zstd, a bad size or rate), or it names a rule that does not exist. The route is not served.", "Fix the JSON (see docs/traffic-shaping.md)."},
	"SET071": {"Rate limit depends on Redis", "The shared rate limit either answers 503 to every request while Redis is down (failOpen false) or stops limiting at all (fallback none).", "Keep the default (fail open to a per-replica bucket), or accept the outage behaviour knowingly (see docs/shared-rate-limits.md)."},
	"SET072": {"Rate limit key is client controlled", "The shared limit counts per a request header. Whoever calls the gateway sets it, so a client can use a fresh value for every request and never be limited.", "Count per client IP or per route, or authenticate the caller and put a trusted layer in front that sets the header."},
	"SET073": {"Compressing compressed data", "The compress block lists a content type whose bytes are already compressed, so the CPU is spent for no saving.", "Remove the type from the list."},
	"SET074": {"Browsers cannot call this gRPC-web route", "gRPC-web exists for browsers, which need a CORS grant. The rule has neither allowOrigins in its grpc-web block nor a CORS filter.", "Add allowOrigins to the grpc-web block or a CORS filter to the rule."},
	"SET075": {"Retries do not apply to gRPC-web", "Bridged gRPC-web calls are streamed to the backend once; the rule's retry policy and mirror are not used for them.", "Remove them or send these calls to a plain gRPC route."},
	"SET076": {"Per-IP limit is unreachable", "maxConnectionsPerIP is higher than maxConnections, so the total limit always triggers first.", "Lower maxConnectionsPerIP or raise maxConnections."},
	"SET090": {"Filters the Gateway API rejects", "A rule combines URLRewrite with RequestRedirect, repeats a core filter, leaves a filter's configuration block out, uses ReplacePrefixMatch next to an Exact or regex match, or sets a redirect scheme other than http or https. A conforming controller marks the route not Accepted (IncompatibleFilters).", "Split the rule, keep one filter of each type, add the missing block, or make every match a PathPrefix."},
	"SET047": {"backendRefs are ignored", "A rule with an AI block serves its providers; its backendRefs are never used.", "Remove the backendRefs."},
	"SET050": {"Load-balancer block is invalid", "The load-balancer block or annotation cannot be parsed or validated, or it names a rule that does not exist. The route is not served.", "Fix the JSON (see docs/load-balancing.md)."},
	"SET051": {"Hash does not pin the client", "consistentHash picks the endpoint inside one backend. The rule splits traffic across several backends, or has session persistence that overrides it, so a client is not always sent to the same endpoint.", "Use one backendRef, or drop sessionPersistence."},
	"SET052": {"Backend declaration is invalid", "A backend has an endpoint that is not an address, a name or a unix socket, a bad weight, zone or priority, or an invalid dns or loadBalancer block.", "Fix the backend (see docs/load-balancing.md)."},
	"SET053": {"Backend is not declared", "A backendRef of kind Backend names a backend that is not in the snapshot backends section or the setura.zyvor.dev/backends annotation.", "Declare the backend."},
	"SET080": {"Envoy Gateway fields are ignored", "The policy sets fields Setura has no equivalent for, so they have no effect.", "See docs/envoy-gateway-compat.md for each field's Setura equivalent."},
	"SET081": {"Envoy Gateway policy has no target", "The policy targets a Gateway or route that is not in the snapshot, so nothing is changed by it.", "Fix the targetRef, or delete the policy."},
	"SET082": {"Envoy Gateway policies conflict", "Two policies of one kind target the same object at the same level. The oldest wins and the others are Conflicted.", "Merge them into one policy, or target different objects or sections."},
	"SET083": {"Envoy Gateway guard is not enforced", "The security policy has a field Setura cannot enforce (basicAuth, oidc, JWT or header authorization rules), so the controller refuses the targeted traffic.", "Replace the field with one Setura supports (see docs/envoy-gateway-compat.md), or opt out with the annotation setura.zyvor.dev/compat-fail-open."},
	"SET019": {"Gateway API 1.5 setting is invalid", "A CORS or ExternalAuth filter, session persistence, a backend timeout or a BackendTLSPolicy is configured in a way the built-in gateway refuses, so the route (or policy) is not accepted.", "Fix the setting named in the message (see docs/gateway-api-1-5.md)."},
}

func routeKindLabel(resource string) string {
	if resource == grpcRoute {
		return "GRPCRoute"
	}
	return "HTTPRoute"
}

func matchText(m obj) string {
	var parts []string
	if p := asMap(m["path"]); p != nil {
		v := str(p, "value", "/")
		switch str(p, "type", "PathPrefix") {
		case "Exact":
			parts = append(parts, "path is exactly "+v)
		case "RegularExpression":
			parts = append(parts, "path matches regex "+v)
		default:
			parts = append(parts, "path starts with "+v)
		}
	}
	if v := asStr(m["method"]); v != "" {
		parts = append(parts, v)
	}
	for _, h := range asList(m["headers"]) {
		hm := asMap(h)
		parts = append(parts, fmt.Sprintf("header %s = %s", asStr(hm["name"]), asStr(hm["value"])))
	}
	for _, q := range asList(m["queryParams"]) {
		qm := asMap(q)
		parts = append(parts, fmt.Sprintf("query %s = %s", asStr(qm["name"]), asStr(qm["value"])))
	}
	if len(parts) == 0 {
		return "every request"
	}
	return strings.Join(parts, " · ")
}

func headerNames(v any) []string {
	var names []string
	m := asMap(v)
	for _, k := range []string{"set", "add"} {
		for _, h := range asList(m[k]) {
			names = append(names, asStr(asMap(h)["name"]))
		}
	}
	for _, r := range asList(m["remove"]) {
		names = append(names, asStr(r))
	}
	return names
}

// filterText describes a filter without ever echoing header values.
func filterText(f obj) obj {
	typ := asStr(f["type"])
	text := typ
	switch typ {
	case "RequestHeaderModifier", "ResponseHeaderModifier":
		key := "requestHeaderModifier"
		verb := "Changes request headers"
		if typ == "ResponseHeaderModifier" {
			key, verb = "responseHeaderModifier", "Changes response headers"
		}
		text = verb
		if n := headerNames(f[key]); len(n) > 0 {
			text += ": " + strings.Join(n, ", ") + " (values hidden)"
		}
	case "RequestRedirect":
		r := asMap(f["requestRedirect"])
		code := "302"
		if c, ok := num(r["statusCode"]); ok {
			code = fmt.Sprint(int(c))
		}
		to := str(r, "hostname", "same host")
		if p := asMap(r["path"]); p != nil {
			to += " " + str(p, "replacePrefixMatch", str(p, "replaceFullPath", ""))
		}
		text = "Redirects (" + code + ") to " + strings.TrimSpace(to)
	case "URLRewrite":
		r := asMap(f["urlRewrite"])
		var bits []string
		if h := asStr(r["hostname"]); h != "" {
			bits = append(bits, "host "+h)
		}
		if p := asMap(r["path"]); p != nil {
			bits = append(bits, "path "+str(p, "replacePrefixMatch", str(p, "replaceFullPath", "")))
		}
		text = "Rewrites " + strings.Join(bits, " and ")
	case "RequestMirror":
		text = "Mirrors a copy of each request"
	}
	return obj{"type": typ, "text": text}
}

func fnum(v any) float64 { f, _ := num(v); return f }

// counters extracts requests and server errors from a stats counter object.
func counters(v any) (requests, errors float64) {
	m := asMap(v)
	if m == nil {
		return 0, 0
	}
	return fnum(m["requests"]), fnum(asMap(m["status"])["5xx"])
}

// BuildUIState turns a route snapshot (nil in watch mode) and optional live
// inputs into the JSON document the dashboard renders. It never includes
// header values, secrets or endpoints.
func BuildUIState(snapshot obj, in UIInput) (obj, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	var stats obj
	if in.Stats != nil {
		raw, _ := json.Marshal(in.Stats)
		_ = json.Unmarshal(raw, &stats)
	}
	routeStats, backendStats := asMap(stats["routes"]), asMap(stats["backends"])

	ns := ""
	gateways, routes := []any{}, []any{}
	findingsBy := map[string][]obj{}
	var allFindings []obj
	backendSet := map[string]bool{}
	listeners := 0
	if snapshot != nil {
		report, err := Lint(snapshot)
		if err != nil {
			return nil, err
		}
		ns = asStr(snapshot["namespace"])
		for _, f := range asList(report["findings"]) {
			fm := asMap(f)
			help := ruleHelp[asStr(fm["id"])]
			fi := obj{"id": fm["id"], "severity": fm["severity"], "resource": fm["resource"], "message": fm["message"],
				"title": help.Title, "why": help.Why, "fix": help.Fix}
			allFindings = append(allFindings, fi)
			findingsBy[asStr(fm["resource"])] = append(findingsBy[asStr(fm["resource"])], fi)
		}
		specs := asMap(snapshot["resources"])
		for _, key := range sortedKeys(specs) {
			spec := asMap(specs[key])
			resource, name, _ := strings.Cut(key, "/")
			switch resource {
			case gateway:
				var ls []any
				for _, l := range asList(spec["listeners"]) {
					lm := asMap(l)
					ls = append(ls, obj{"name": lm["name"], "port": lm["port"], "protocol": lm["protocol"], "hostname": lm["hostname"], "routes": 0})
				}
				listeners += len(ls)
				gateways = append(gateways, obj{"id": "Gateway/" + ns + "/" + name, "name": name, "namespace": ns,
					"class": spec["gatewayClassName"], "listeners": ls})
			case route, grpcRoute:
				kind := routeKindLabel(resource)
				id := kind + "/" + ns + "/" + name
				hostnames := []any{}
				for _, h := range asList(spec["hostnames"]) {
					hostnames = append(hostnames, h)
				}
				var parents []any
				for _, p := range asList(spec["parentRefs"]) {
					pm := asMap(p)
					parents = append(parents, obj{"gateway": pm["name"], "listener": pm["sectionName"]})
				}
				var rules []any
				rt := obj{"id": id, "kind": kind, "name": name, "namespace": ns, "hostnames": hostnames, "parents": parents}
				var rTotal, rErr float64
				for i, r := range asList(spec["rules"]) {
					rule := asMap(r)
					var matches, filters, backends []any
					for _, m := range asList(rule["matches"]) {
						matches = append(matches, matchText(asMap(m)))
					}
					if len(matches) == 0 {
						matches = []any{"every request"}
					}
					for _, f := range asList(rule["filters"]) {
						filters = append(filters, filterText(asMap(f)))
					}
					var sum float64
					type ref struct {
						m obj
						w float64
					}
					var refs []ref
					for _, b := range asList(rule["backendRefs"]) {
						bm := asMap(b)
						w := 1.0
						if x, ok := num(bm["weight"]); ok {
							w = x
						}
						if w < 0 {
							w = 0
						}
						sum += w
						refs = append(refs, ref{bm, w})
					}
					for _, r := range refs {
						bns := str(r.m, "namespace", ns)
						bkey := fmt.Sprintf("%s/%s:%d", bns, asStr(r.m["name"]), int(fnum(r.m["port"])))
						backendSet[bns+"/"+asStr(r.m["name"])] = true
						share := 0.0
						if sum > 0 {
							share = r.w / sum
						}
						b := obj{"name": r.m["name"], "namespace": bns, "port": r.m["port"], "weight": r.w, "share": share}
						if c, ok := backendStats[bkey]; ok {
							req, e := counters(c)
							b["requests"], b["errors"] = req, e
						}
						backends = append(backends, b)
					}
					rules = append(rules, obj{"index": i + 1, "matches": matches, "filters": filters, "backends": backends})
				}
				rt["rules"] = rules
				if c, ok := routeStats[ns+"/"+name]; ok {
					rTotal, rErr = counters(c)
					rt["traffic"] = obj{"requests": rTotal, "errors": rErr}
				}
				fs := findingsBy[id]
				if fs == nil {
					fs = []obj{}
				}
				rt["findings"] = fs
				status := "ok"
				if len(fs) > 0 {
					status = "attention"
				}
				rt["status"] = status
				routes = append(routes, rt)
			}
		}
		// attach counts to listeners
		for _, g := range gateways {
			gm := asMap(g)
			for _, l := range asList(gm["listeners"]) {
				lm := asMap(l)
				n := 0
				for _, r := range routes {
					for _, p := range asList(asMap(r)["parents"]) {
						pm := asMap(p)
						if pm["gateway"] == gm["name"] && (pm["listener"] == nil || pm["listener"] == lm["name"]) {
							n++
							break
						}
					}
				}
				lm["routes"] = n
			}
		}
	}

	attention := 0
	for _, r := range routes {
		if asMap(r)["status"] == "attention" {
			attention++
		}
	}
	errs, warns := 0, 0
	for _, f := range allFindings {
		if f["severity"] == SeverityError {
			errs++
		} else {
			warns++
		}
	}
	failing, targets := 0, 0
	if h := asMap(in.Health); h != nil {
		for _, t := range asList(h["targets"]) {
			targets++
			if asMap(t)["ok"] == false {
				failing++
			}
		}
	}
	status, headline, detail := "ok", "All routes healthy", ""
	switch {
	case snapshot == nil && targets == 0:
		status, headline = "unknown", "Waiting for the first probe"
	case snapshot == nil && failing == 0:
		headline = "All targets passing"
	case snapshot == nil:
		status, headline = "attention", plural(failing, "target needs", "targets need")+" attention"
	case len(routes) == 0:
		status, headline, detail = "unknown", "No routes yet", "Add an HTTPRoute to the snapshot and it will appear here."
	case attention > 0 || failing > 0:
		n := attention + failing
		status, headline = "attention", plural(n, "route needs", "routes need")+" attention"
		detail = fmt.Sprintf("%d %s, %d %s", errs, pluralWord(errs, "error", "errors"), warns, pluralWord(warns, "warning", "warnings"))
	}
	summary := obj{"status": status, "headline": headline, "detail": detail, "gateways": len(gateways), "listeners": listeners,
		"routes": len(routes), "backends": len(backendSet), "attention": attention, "errors": errs, "warnings": warns}

	state := obj{"schema": UIStateSchema, "generated": in.Now.UTC().Format(time.RFC3339), "mode": in.Mode, "source": in.Source,
		"namespace": ns, "summary": summary, "gateways": gateways, "routes": routes, "findings": findingList(allFindings),
		"readOnly": true}
	if stats != nil {
		state["traffic"] = obj{"requests": stats["requests"], "unmatched": stats["unmatched"]}
	}
	if in.Health != nil {
		state["health"] = in.Health
	}
	if in.History != nil {
		state["history"] = in.History
	}
	if in.Reload != nil {
		state["reload"] = in.Reload
	}
	if in.Connections != nil {
		state["connections"] = in.Connections
	}
	return scrub(state, in.Redact), nil
}

func findingList(f []obj) []any {
	out := make([]any, 0, len(f))
	for _, x := range f {
		out = append(out, x)
	}
	return out
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

var secretKey = []string{"secret", "token", "password", "passwd", "authorization", "apikey", "api_key", "privatekey", "private_key", "credential"}

// unmasked keys carry structure or timestamps rather than user data.
var unmasked = map[string]bool{"schema": true, "generated": true, "time": true, "since": true, "mode": true, "severity": true,
	"status": true, "kind": true, "headline": true, "detail": true, "title": true, "why": true, "fix": true, "type": true,
	"level": true, "protocol": true, "stage": true}

// scrub removes keys that look like secrets and, when redact is set, masks
// hostnames, IPs and namespaces with the same Redactor the AI report uses.
func scrub(state obj, redact bool) obj {
	var r *Redactor
	if redact {
		r = NewRedactor(ReportNamespaces(state))
	}
	var walk func(key string, v any) any
	walk = func(key string, v any) any {
		switch t := v.(type) {
		case map[string]any:
			out := obj{}
			for k, x := range t {
				lk := strings.ToLower(k)
				drop := false
				for _, s := range secretKey {
					if strings.Contains(lk, s) {
						drop = true
					}
				}
				if !drop {
					out[k] = walk(k, x)
				}
			}
			return out
		case []obj:
			l := make([]any, len(t))
			for i, x := range t {
				l[i] = walk(key, x)
			}
			return l
		case []any:
			l := make([]any, len(t))
			for i, x := range t {
				l[i] = walk(key, x)
			}
			return l
		case string:
			if r != nil && !unmasked[key] {
				return r.Mask(t, false)
			}
		}
		return v
	}
	return asMap(walk("", state))
}
