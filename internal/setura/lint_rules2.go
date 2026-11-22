package setura

import (
	"fmt"
	"math"
	"strings"
)

// Additional route kinds and ReferenceGrants captured by snapshots.
const (
	grpcRoute = "grpcroutes." + group
	tlsRoute  = "tlsroutes." + group
	refGrant  = "referencegrants." + group
)

// routeKinds maps a snapshot resource prefix to its Kubernetes kind.
var routeKinds = []struct{ resource, kind string }{
	{route, "HTTPRoute"}, {grpcRoute, "GRPCRoute"}, {tlsRoute, "TLSRoute"}, {tcpRoute, "TCPRoute"}, {udpRoute, "UDPRoute"},
}

// captureExtras adds GRPCRoutes, TLSRoutes, ReferenceGrants and gateways in
// other namespaces to a snapshot. Each is best effort because the CRDs are
// optional; "captured" lists what was read successfully so lint can tell an
// absent grant from an unread one.
func captureExtras(c *Cluster, namespace string, resources obj) (captured []any, foreign obj) {
	for _, k := range append([]string{grpcRoute, tlsRoute}, gw15Kinds...) {
		list, err := c.getMap(namespace, k)
		if err != nil {
			continue
		}
		captured = append(captured, strings.TrimSuffix(k, "."+group))
		for _, it := range asList(list["items"]) {
			m := asMap(it)
			if name := asStr(asMap(m["metadata"])["name"]); name != "" {
				resources[k+"/"+name] = withShadowAnnotations(m)
			}
		}
	}
	targets := map[string]bool{namespace: true}
	type gwRef struct{ ns, name string }
	var gws []gwRef
	for key, spec := range resources {
		resource, _, _ := strings.Cut(key, "/")
		for _, rk := range routeKinds {
			if resource != rk.resource {
				continue
			}
			for _, r := range asList(asMap(spec)["rules"]) {
				for _, b := range asList(asMap(r)["backendRefs"]) {
					if n := str(asMap(b), "namespace", namespace); n != namespace {
						targets[n] = true
					}
				}
			}
			for _, p := range asList(asMap(spec)["parentRefs"]) {
				pm := asMap(p)
				if n := str(pm, "namespace", namespace); n != namespace && str(pm, "kind", "Gateway") == "Gateway" && str(pm, "group", group) == group {
					gws = append(gws, gwRef{n, asStr(pm["name"])})
				}
			}
		}
	}
	grants, ok := obj{}, true
	for _, n := range sortedKeys(toObj(targets)) {
		list, err := c.getMap(n, refGrant)
		if err != nil {
			ok = false
			break
		}
		for _, it := range asList(list["items"]) {
			m := asMap(it)
			if name := asStr(asMap(m["metadata"])["name"]); name != "" {
				grants[refGrant+"/"+n+"/"+name] = m["spec"]
			}
		}
	}
	if ok {
		captured = append(captured, "referencegrants")
		for k, v := range grants {
			resources[k] = v
		}
	}
	for _, g := range gws {
		if g.name == "" {
			continue
		}
		if m, err := c.getMap(g.ns, gateway+"/"+g.name); err == nil && m["spec"] != nil {
			if foreign == nil {
				foreign = obj{}
			}
			foreign[gateway+"/"+g.ns+"/"+g.name] = m["spec"]
		}
	}
	return captured, foreign
}

func toObj(set map[string]bool) obj {
	o := obj{}
	for k := range set {
		o[k] = true
	}
	return o
}

func grantsCaptured(snapshot obj) bool {
	if _, ok := snapshot["referenceGrants"].([]any); ok {
		return true // the gateway file format lists grants at the top level
	}
	for key := range asMap(snapshot["resources"]) {
		if strings.HasPrefix(key, refGrant+"/") {
			return true // a snapshot that carries grants knows them
		}
	}
	for _, c := range asList(snapshot["captured"]) {
		if c == "referencegrants" {
			return true
		}
	}
	return false
}

type lintGrant struct {
	ns   string
	spec obj
}

// lintGrants lists every ReferenceGrant in the snapshot: resources named
// referencegrants.* and the gateway file's top-level referenceGrants array.
func lintGrants(snapshot obj, ns string) []lintGrant {
	var out []lintGrant
	for key, spec := range asMap(snapshot["resources"]) {
		resource, rest, _ := strings.Cut(key, "/")
		if resource != refGrant {
			continue
		}
		gns := ns
		if a, _, found := strings.Cut(rest, "/"); found {
			gns = a
		}
		out = append(out, lintGrant{gns, asMap(spec)})
	}
	for _, g := range asList(snapshot["referenceGrants"]) {
		gm := asMap(g)
		out = append(out, lintGrant{str(asMap(gm["metadata"]), "namespace", ns), asMap(gm["spec"])})
	}
	return out
}

// refGrantSeverity decides how to report a cross-namespace backendRef from a
// route of fromKind in ns. It returns "" when a captured ReferenceGrant allows
// it, a warning when grants were not captured, and an error when they were and
// none matches.
func refGrantSeverity(snapshot obj, ns, fromKind string, ref obj) string {
	if !grantsCaptured(snapshot) {
		return SeverityWarning
	}
	rn := str(ref, "namespace", ns)
	g, k, n := str(ref, "group", ""), str(ref, "kind", "Service"), asStr(ref["name"])
	for _, gr := range lintGrants(snapshot, ns) {
		if gr.ns != rn {
			continue
		}
		fromOK := false
		for _, f := range asList(gr.spec["from"]) {
			fm := asMap(f)
			fromOK = fromOK || (str(fm, "group", "") == group && str(fm, "kind", "") == fromKind && str(fm, "namespace", "") == ns)
		}
		for _, t := range asList(gr.spec["to"]) {
			tm := asMap(t)
			if fromOK && str(tm, "group", "") == g && str(tm, "kind", "") == k {
				if tn := asStr(tm["name"]); tn == "" || tn == n {
					return ""
				}
			}
		}
	}
	return SeverityError
}

type gwListener struct {
	name, hostname string
	spec           obj
}

// findGateway resolves a parentRef to a Gateway declared in the snapshot or
// captured as a foreign (other namespace) Gateway.
func findGateway(snapshot obj, ns, pns, pname string) (listeners []gwListener, gwNS string, ok bool) {
	var spec any
	if pns == ns {
		spec, ok = asMap(snapshot["resources"])[gateway+"/"+pname]
	} else {
		spec, ok = asMap(snapshot["foreign"])[gateway+"/"+pns+"/"+pname]
	}
	if !ok {
		return nil, "", false
	}
	for _, l := range asList(asMap(spec)["listeners"]) {
		lm := asMap(l)
		listeners = append(listeners, gwListener{asStr(lm["name"]), asStr(lm["hostname"]), lm})
	}
	return listeners, pns, true
}

// attachable reports why a listener refuses routes of kind from namespace
// routeNS, or "" when it accepts them (or cannot be judged).
func attachable(l gwListener, kind, routeNS, gwNS string) string {
	allowed := asMap(l.spec["allowedRoutes"])
	if allowed == nil {
		return ""
	}
	if from := str(asMap(allowed["namespaces"]), "from", "Same"); from == "Same" && routeNS != gwNS {
		return fmt.Sprintf("allowedRoutes.namespaces.from is Same and the route is in namespace %s, not %s", routeNS, gwNS)
	}
	if kinds := asList(allowed["kinds"]); len(kinds) > 0 {
		for _, k := range kinds {
			km := asMap(k)
			if str(km, "group", group) == group && asStr(km["kind"]) == kind {
				return ""
			}
		}
		return fmt.Sprintf("allowedRoutes.kinds does not include %s", kind)
	}
	return ""
}

// extraRules evaluates SET010-SET014 over every route kind in the snapshot.
func extraRules(snapshot obj, specs obj, ns string) []obj {
	var findings []obj
	add := func(id, resource, message string) {
		findings = append(findings, obj{"id": id, "severity": ruleSeverity(id), "resource": resource, "message": message})
	}
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource == refGrant {
			spec := asMap(specs[key])
			if len(asList(spec["from"])) == 0 || len(asList(spec["to"])) == 0 {
				add("SET012", "ReferenceGrant/"+name, "grant has an empty from or to list and permits nothing")
			}
			continue
		}
		kind := ""
		for _, rk := range routeKinds {
			if resource == rk.resource {
				kind = rk.kind
			}
		}
		if kind == "" {
			continue
		}
		id := kind + "/" + ns + "/" + name
		spec := asMap(specs[key])
		parents := asList(spec["parentRefs"])
		rules := asList(spec["rules"])
		if kind == "GRPCRoute" {
			if len(parents) == 0 {
				add("SET010", id, "spec.parentRefs is empty")
			}
			if len(rules) == 0 {
				add("SET010", id, "spec.rules is empty")
			}
		}
		var hosts []string
		for _, h := range asList(spec["hostnames"]) {
			hosts = append(hosts, asStr(h))
		}
		if len(hosts) == 0 {
			hosts = []string{""}
		}

		for i, r := range rules {
			refs := asList(asMap(r)["backendRefs"])
			where := fmt.Sprintf("rule %d", i+1)
			var sum float64
			kinds := map[string]bool{}
			for _, b := range refs {
				ref := asMap(b)
				w, has := num(ref["weight"])
				if has {
					switch {
					case w < 0:
						add("SET014", id, fmt.Sprintf("%s: backendRef %s has negative weight %v", where, asStr(ref["name"]), w))
					case w > 1000000:
						add("SET014", id, fmt.Sprintf("%s: backendRef %s weight %v exceeds 1000000", where, asStr(ref["name"]), w))
					default:
						sum += w
					}
				}
				k := str(ref, "kind", "Service")
				if g := str(ref, "group", ""); g != "" || k != "Service" {
					k = "other:" + g + ":" + k
				}
				kinds[k] = true
				if rn := str(ref, "namespace", ns); rn != ns && kind != "HTTPRoute" {
					if sev := refGrantSeverity(snapshot, ns, kind, ref); sev != "" {
						findings = append(findings, obj{"id": "SET004", "severity": sev, "resource": id,
							"message": fmt.Sprintf("%s: backendRef %s/%s needs a ReferenceGrant in namespace %s", where, rn, asStr(ref["name"]), rn)})
					}
				}
			}
			if sum > math.MaxInt32 {
				add("SET014", id, fmt.Sprintf("%s: backendRef weights sum to %.0f, which overflows int32", where, sum))
			}
			if len(kinds) > 1 {
				add("SET014", id, where+": backendRefs mix Service and non-Service kinds")
			}
		}

		for _, p := range parents {
			parent := asMap(p)
			if str(parent, "group", group) != group || str(parent, "kind", "Gateway") != "Gateway" {
				continue
			}
			pname, pns := asStr(parent["name"]), str(parent, "namespace", ns)
			listeners, gwNS, ok := findGateway(snapshot, ns, pns, pname)
			if !ok {
				continue
			}
			attached := listeners
			if section, has := parent["sectionName"].(string); has {
				attached = nil
				for _, l := range listeners {
					if l.name == section {
						attached = append(attached, l)
					}
				}
			}
			if len(attached) == 0 {
				continue
			}
			if kind != "HTTPRoute" {
				overlap := false
				for _, l := range attached {
					for _, h := range hosts {
						overlap = overlap || hostsOverlap(h, l.hostname)
					}
				}
				if !overlap {
					add("SET011", id, fmt.Sprintf("hostnames %v do not intersect the listener hostname on Gateway %s", hosts, pname))
				}
			}
			var reasons []string
			for _, l := range attached {
				reason := attachable(l, kind, ns, gwNS)
				if reason == "" {
					reasons = nil
					break
				}
				reasons = append(reasons, fmt.Sprintf("listener %q: %s", l.name, reason))
			}
			if len(reasons) > 0 {
				add("SET013", id, fmt.Sprintf("cannot attach to Gateway %s/%s: %s", pns, pname, strings.Join(reasons, "; ")))
			}
		}
	}
	return findings
}
