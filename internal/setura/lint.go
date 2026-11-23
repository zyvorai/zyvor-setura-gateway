package setura

import (
	"fmt"
	"sort"
	"strings"
)

const lintSchema = "setura.lint/v1"

// Finding severities.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

// Rules documents every lint rule. The IDs are stable and safe to reference
// from CI configuration.
var Rules = []struct{ ID, Severity, Summary string }{
	{"SET001", SeverityError, "HTTPRoute has no parentRefs, so no Gateway will ever serve it"},
	{"SET002", SeverityError, "every backendRef in a rule has weight 0, so matching requests are dropped"},
	{"SET003", SeverityWarning, "rule has no backendRefs and no redirect filter, so matching requests get a 500"},
	{"SET004", SeverityWarning, "backendRef points at another namespace and needs a ReferenceGrant there (error when the snapshot captured ReferenceGrants and none matches)"},
	{"SET005", SeverityError, "parentRef names a listener (sectionName) the Gateway does not declare"},
	{"SET006", SeverityWarning, "route hostnames do not intersect the hostname of the listener it attaches to"},
	{"SET007", SeverityError, "HTTPS or TLS listener has no tls configuration"},
	{"SET008", SeverityError, "two listeners on one Gateway share a name or the same port, protocol and hostname"},
	{"SET009", SeverityWarning, "two routes match the same hostname and path on the same parent, so one shadows the other"},
	{"SET010", SeverityError, "GRPCRoute has no parentRefs or no rules, so it can never serve traffic"},
	{"SET011", SeverityWarning, "GRPCRoute or TLSRoute hostnames do not intersect the hostname of the listener it attaches to"},
	{"SET012", SeverityWarning, "ReferenceGrant has an empty from or to list and permits nothing"},
	{"SET013", SeverityError, "listener allowedRoutes (namespaces or kinds) does not admit the attaching route"},
	{"SET014", SeverityError, "route rule has a negative or overflowing backendRef weight, or mixes Service and non-Service backendRefs"},
	{"SET015", SeverityError, "shadow-diff block (RequestMirror extension or setura.zyvor.dev/shadow-diff annotation) is invalid or targets no RequestMirror"},
	{"SET019", SeverityError, "route rule or BackendTLSPolicy uses a Gateway API 1.5 feature the built-in gateway refuses: malformed CORS filter, ExternalAuth without protocol or backendRef, invalid session persistence, backendRequest longer than request timeout, BackendTLSPolicy without hostname or CA source"},
	{"SET016", SeverityWarning, "auth policy accepts any audience (jwt without audience) or fetches its JWKS over plain http"},
	{"SET017", SeverityWarning, "auth policy stores an API key or a basic auth password in clear text instead of a hash"},
	{"SET018", SeverityError, "auth block (rule extension or setura.zyvor.dev/auth annotation) is invalid or targets no rule"},
	{"SET040", SeverityError, "AI block (rule extension or setura.zyvor.dev/ai annotation) is invalid or targets no rule"},
	{"SET041", SeverityError, "AI token budget has no identity to count against: the identity (apikey, subject or claim) needs an auth policy on the rule that provides it"},
	{"SET042", SeverityWarning, "AI budget or cache identity is a request header the client sets itself, so a client can pick another tenant's identity"},
	{"SET043", SeverityWarning, "AI provider is called over plain http with an API key outside the cluster or loopback, so the key crosses the network in clear text"},
	{"SET044", SeverityWarning, "AI route has no auth policy: everyone who can reach the gateway spends the provider key"},
	{"SET045", SeverityWarning, "AI prompt cache is shared across identities (scope route) on a route that authenticates, so one client's answer can be served to another"},
	{"SET046", SeverityWarning, "AI monthlyCost budget has no price table on the route (prices); without --ai-prices on the gateway the cost is always 0 and the budget never fires"},
	{"SET047", SeverityWarning, "AI rule also has backendRefs, which are ignored: an AI rule serves its providers"},
}

func ruleSeverity(id string) string {
	for _, r := range Rules {
		if r.ID == id {
			return r.Severity
		}
	}
	return SeverityWarning
}

// hostsOverlap reports whether two Gateway API hostnames can match one name.
func hostsOverlap(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	suffix := func(wild, name string) bool {
		return strings.HasPrefix(wild, "*.") && strings.HasSuffix(strings.TrimPrefix(name, "*"), strings.TrimPrefix(wild, "*"))
	}
	return suffix(a, b) || suffix(b, a)
}

// Lint statically analyzes a Setura route snapshot. It reads declared specs
// only; ReferenceGrants are known only when the snapshot captured them.
func Lint(snapshot obj) (obj, error) {
	if snapshot["schema"] != snapshotSchema {
		return nil, userError("expected a Setura route snapshot")
	}
	specs := asMap(snapshot["resources"])
	if specs == nil {
		return nil, userError("invalid snapshot namespace or resources")
	}
	ns := asStr(snapshot["namespace"])
	var findings []obj
	add := func(id, resource, message string) {
		findings = append(findings, obj{"id": id, "severity": ruleSeverity(id), "resource": resource, "message": message})
	}

	type listener struct {
		hostname, protocol string
		tls                bool
	}
	gateways := map[string]map[string]listener{} // gateway -> listener name -> listener
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != gateway {
			continue
		}
		id := "Gateway/" + ns + "/" + name
		names, shapes := map[string]bool{}, map[string]string{}
		gateways[name] = map[string]listener{}
		for _, l := range asList(asMap(specs[key])["listeners"]) {
			lm := asMap(l)
			ln := asStr(lm["name"])
			l := listener{hostname: asStr(lm["hostname"]), protocol: asStr(lm["protocol"]), tls: lm["tls"] != nil}
			if names[ln] {
				add("SET008", id, fmt.Sprintf("listener name %q is declared more than once", ln))
			}
			names[ln] = true
			shape := fmt.Sprint(lm["port"], "/", l.protocol, "/", l.hostname)
			if other, dup := shapes[shape]; dup && other != ln {
				add("SET008", id, fmt.Sprintf("listeners %q and %q share port, protocol and hostname", other, ln))
			}
			shapes[shape] = ln
			if (l.protocol == "HTTPS" || l.protocol == "TLS") && !l.tls {
				add("SET007", id, fmt.Sprintf("listener %q uses %s without a tls block", ln, l.protocol))
			}
			gateways[name][ln] = l
		}
	}

	// shadow tracks (parent, host, match) -> first route to claim it.
	shadow := map[string]string{}
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != route {
			continue
		}
		id := "HTTPRoute/" + ns + "/" + name
		spec := asMap(specs[key])
		parents := asList(spec["parentRefs"])
		if len(parents) == 0 {
			add("SET001", id, "spec.parentRefs is empty")
		}
		var hosts []string
		for _, h := range asList(spec["hostnames"]) {
			hosts = append(hosts, asStr(h))
		}
		if len(hosts) == 0 {
			hosts = []string{""}
		}

		for i, r := range asList(spec["rules"]) {
			rule := asMap(r)
			refs := asList(rule["backendRefs"])
			where := fmt.Sprintf("rule %d", i+1)
			allZero := len(refs) > 0
			for _, b := range refs {
				ref := asMap(b)
				if w, ok := num(ref["weight"]); !ok || w != 0 {
					allZero = false
				}
				if rn := str(ref, "namespace", ns); rn != ns {
					if sev := refGrantSeverity(snapshot, ns, "HTTPRoute", ref); sev != "" {
						findings = append(findings, obj{"id": "SET004", "severity": sev, "resource": id,
							"message": fmt.Sprintf("%s: backendRef %s/%s needs a ReferenceGrant in namespace %s", where, rn, asStr(ref["name"]), rn)})
					}
				}
			}
			if allZero {
				add("SET002", id, where+": all backendRefs have weight 0")
			}
			if len(refs) == 0 && !hasAIBlock(spec, i, rule) {
				redirect := false
				for _, f := range asList(rule["filters"]) {
					t := asStr(asMap(f)["type"])
					redirect = redirect || t == "RequestRedirect"
				}
				if !redirect {
					add("SET003", id, where+": no backendRefs and no RequestRedirect filter")
				}
			}
		}

		for _, p := range parents {
			parent := asMap(p)
			if str(parent, "group", group) != group || str(parent, "kind", "Gateway") != "Gateway" {
				continue
			}
			pname, pns := asStr(parent["name"]), str(parent, "namespace", ns)
			gl, declared := gateways[pname]
			if pns != ns || !declared {
				continue // not declared in this snapshot; cannot judge
			}
			section, hasSection := parent["sectionName"].(string)
			var attached []listener
			if hasSection {
				l, ok := gl[section]
				if !ok {
					add("SET005", id, fmt.Sprintf("parentRef %s names listener %q, which Gateway %s does not declare", pname, section, pname))
					continue
				}
				attached = []listener{l}
			} else {
				for _, n := range sortedKeys(gl) {
					attached = append(attached, gl[n])
				}
			}
			overlap := false
			for _, l := range attached {
				for _, h := range hosts {
					overlap = overlap || hostsOverlap(h, l.hostname)
				}
			}
			if !overlap && len(attached) > 0 {
				add("SET006", id, fmt.Sprintf("hostnames %v do not intersect the listener hostname on Gateway %s", hosts, pname))
			}
			// Shadowing: identical parent + host + path + method claimed twice.
			for _, r := range asList(spec["rules"]) {
				matches := asList(asMap(r)["matches"])
				if len(matches) == 0 {
					matches = []any{obj{}}
				}
				for _, m := range matches {
					mm := asMap(m)
					path := asMap(mm["path"])
					pt, pv := str(path, "type", "PathPrefix"), str(path, "value", "/")
					for _, h := range hosts {
						k := fmt.Sprint(pname, "#", section, "|", h, "|", pt, "|", pv, "|", mm["method"], "|", mm["headers"], "|", mm["queryParams"])
						if first, seen := shadow[k]; seen && first != id {
							add("SET009", id, fmt.Sprintf("%s %q on host %q is already matched by %s", pt, pv, h, first))
						} else if !seen {
							shadow[k] = id
						}
					}
				}
			}
		}
	}

	findings = append(findings, extraRules(snapshot, specs, ns)...)
	findings = append(findings, shadowRules(specs, ns)...)
	findings = append(findings, gw15Rules(specs, ns)...)
	findings = append(findings, authRules(specs, ns)...)
	findings = append(findings, aiRules(specs, ns)...)
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a["resource"] != b["resource"] {
			return a["resource"].(string) < b["resource"].(string)
		}
		return a["id"].(string) < b["id"].(string)
	})
	errors, warnings := 0, 0
	out := make([]any, len(findings))
	for i, f := range findings {
		out[i] = f
		if f["severity"] == SeverityError {
			errors++
		} else {
			warnings++
		}
	}
	return obj{"schema": lintSchema, "namespace": ns, "ok": errors == 0, "errors": errors, "warnings": warnings, "findings": out}, nil
}

// LintText renders lint findings one per line, grouped by severity order.
func LintText(report obj) string {
	var b strings.Builder
	for _, f := range asList(report["findings"]) {
		m := asMap(f)
		fmt.Fprintf(&b, "%-7s %s  %s  %s\n", strings.ToUpper(asStr(m["severity"])), m["id"], m["resource"], m["message"])
	}
	e, _ := num(report["errors"])
	w, _ := num(report["warnings"])
	fmt.Fprintf(&b, "%d error(s), %d warning(s)\n", int(e), int(w))
	return b.String()
}
