package setura

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	group   = "gateway.networking.k8s.io"
	gateway = "gateways." + group
	route   = "httproutes." + group
)

// Doctor checks the RBAC permissions Setura needs.
func Doctor(c *Cluster, namespace, proxy string) (obj, error) {
	type check struct{ ns, verb, resource, sub string }
	checks := []any{}
	ok := true
	for _, ch := range []check{
		{namespace, "get", gateway, ""}, {namespace, "get", route, ""},
		{namespace, "get", "services", ""}, {namespace, "list", "endpointslices.discovery.k8s.io", ""},
		{proxy, "list", "services", ""}, {proxy, "get", "services", ""},
		{proxy, "list", "pods", ""}, {proxy, "get", "pods", ""},
		{proxy, "create", "pods", "portforward"},
	} {
		ns, err := label(ch.ns)
		if err != nil {
			return nil, err
		}
		cmd := append(c.cmd(), "-n", ns, "auth", "can-i", ch.verb, ch.resource, "--request-timeout=10s")
		if ch.sub != "" {
			cmd = append(cmd, "--subresource", ch.sub)
		}
		out, errs, code, err := c.Exec(cmd)
		if err != nil {
			return nil, err
		}
		answer := strings.TrimSpace(out)
		state := "unknown"
		if code == 0 && answer == "yes" {
			state = "allowed"
		} else if answer == "no" {
			state = "denied"
		}
		ok = ok && state == "allowed"
		checks = append(checks, obj{"namespace": ch.ns, "verb": ch.verb, "resource": ch.resource,
			"subresource": ch.sub, "state": state, "detail": strings.TrimSpace(errs)})
	}
	return obj{"ok": ok, "checks": checks}, nil
}

// Capabilities lists GatewayClasses and controller-reported features.
func Capabilities(c *Cluster, namespace string) ([]obj, error) {
	list, err := c.getMap(namespace, "gatewayclasses."+group)
	if err != nil {
		return nil, err
	}
	rows := []obj{}
	for _, it := range asList(list["items"]) {
		status := asMap(dig(it, "status"))
		var features any
		if sf, ok := status["supportedFeatures"]; ok {
			names := []string{}
			for _, f := range asList(sf) {
				names = append(names, asStr(req(asMap(f), "name")))
			}
			sort.Strings(names)
			features = names
		}
		conds := status["conditions"]
		if conds == nil {
			conds = []any{}
		}
		rows = append(rows, obj{"class": req(asMap(req(asMap(it), "metadata")), "name"),
			"controller": req(asMap(req(asMap(it), "spec")), "controllerName"),
			"conditions": conds, "reported_features": features})
	}
	sort.Slice(rows, func(i, j int) bool { return asStr(rows[i]["class"]) < asStr(rows[j]["class"]) })
	return rows, nil
}

// Exposure inventories Service exposure and overlapping LoadBalancer ports.
func Exposure(c *Cluster, namespace string) (obj, error) {
	list, err := c.getMap(namespace, "services")
	if err != nil {
		return nil, err
	}
	rows := []obj{}
	for _, s := range asList(list["items"]) {
		spec := asMap(req(asMap(s), "spec"))
		addresses := []any{}
		for _, e := range asList(dig(s, "status", "loadBalancer", "ingress")) {
			em := asMap(e)
			if ip := str(em, "ip", ""); ip != "" {
				addresses = append(addresses, ip)
			} else if h := str(em, "hostname", ""); h != "" {
				addresses = append(addresses, h)
			} else {
				addresses = append(addresses, nil)
			}
		}
		ports := []any{}
		for _, p := range asList(spec["ports"]) {
			pm := asMap(p)
			ports = append(ports, obj{"port": req(pm, "port"), "protocol": str(pm, "protocol", "TCP"), "nodePort": pm["nodePort"]})
		}
		hasIngress := false
		for _, a := range addresses {
			if a != nil {
				hasIngress = true
			}
		}
		typ := asStr(req(spec, "type"))
		ext := spec["externalIPs"]
		if ext == nil {
			ext = []any{}
		}
		rows = append(rows, obj{"service": req(asMap(req(asMap(s), "metadata")), "name"), "type": typ, "ports": ports,
			"loadBalancerClass": spec["loadBalancerClass"], "ingress": addresses, "externalIPs": ext,
			"awaiting_ingress": typ == "LoadBalancer" && !hasIngress})
	}
	owners := map[string][]string{}
	for _, r := range rows {
		if r["type"] == "LoadBalancer" {
			for _, p := range r["ports"].([]any) {
				pm := p.(obj)
				port, _ := num(pm["port"])
				k := fmt.Sprintf("%d/%s", int(port), pm["protocol"])
				owners[k] = append(owners[k], asStr(r["service"]))
			}
		}
	}
	overlap := obj{}
	for k, v := range owners {
		if len(v) > 1 {
			sort.Strings(v)
			overlap[k] = v
		}
	}
	svcs := make([]any, len(rows))
	for i, r := range rows {
		svcs[i] = r
	}
	return obj{"namespace": namespace, "services": svcs, "overlapping_lb_ports": overlap}, nil
}

// RouteState evaluates the single matching parent status of a route.
func RouteState(o obj, gw, namespace, listener, controller string) obj {
	var matches []obj
	for _, p := range asList(dig(o, "status", "parents")) {
		parent := asMap(p)
		ref := asMap(req(parent, "parentRef"))
		if str(ref, "group", group) == group && str(ref, "kind", "Gateway") == "Gateway" &&
			ref["name"] == gw && str(ref, "namespace", asStr(dig(o, "metadata", "namespace"))) == namespace &&
			(listener == "" || ref["sectionName"] == listener) &&
			(controller == "" || req(parent, "controllerName") == controller) {
			matches = append(matches, parent)
		}
	}
	if len(matches) != 1 {
		return obj{"ok": false, "reason": fmt.Sprintf("found %d matching parent reports; expected one", len(matches))}
	}
	gen := dig(o, "metadata", "generation")
	conds := map[string]obj{}
	for _, c := range asList(matches[0]["conditions"]) {
		cm := asMap(c)
		conds[asStr(cm["type"])] = cm
	}
	evidence := obj{}
	ok := true
	for _, key := range []string{"Accepted", "ResolvedRefs"} {
		c := conds[key]
		current := eq(c["observedGeneration"], gen)
		evidence[key] = obj{"status": c["status"], "reason": c["reason"], "current": current}
		ok = ok && current && c["status"] == "True"
	}
	return obj{"ok": ok, "generation": gen, "controller": matches[0]["controllerName"], "conditions": evidence}
}

// GateOptions configures Gate.
type GateOptions struct {
	Route, URL, Backend, Gateway, GatewayNamespace, Controller, Listener, Address, CA, Namespace string
	Attempts, Streak                                                                             int
	Interval                                                                                     float64
}

// Gate requires current parent status and consecutive successful probes.
func Gate(c *Cluster, a GateOptions) (obj, error) {
	if !(1 <= a.Streak && a.Streak <= a.Attempts && a.Attempts <= 100) || math.IsNaN(a.Interval) || a.Interval < 0 || a.Interval > 60 {
		return nil, userError("require 1 <= streak <= attempts <= 100 and interval between 0 and 60")
	}
	name, err := label(a.Route)
	if err != nil {
		return nil, err
	}
	resource := route + "/" + name
	gwNS := a.GatewayNamespace
	if gwNS == "" {
		gwNS = a.Namespace
	}
	history := []any{}
	consecutive := 0
	var previous [2]any
	identityOf := func(o obj) [2]any {
		return [2]any{req(asMap(req(o, "metadata")), "uid"), req(asMap(req(o, "metadata")), "generation")}
	}
	for attempt := 0; attempt < a.Attempts; attempt++ {
		o, err := c.getMap(a.Namespace, resource)
		if err != nil {
			return nil, err
		}
		identity := identityOf(o)
		state := RouteState(o, a.Gateway, gwNS, a.Listener, a.Controller)
		var result any
		var rep *Report
		if state["ok"] == true {
			opts := NewProbe(a.URL)
			opts.Address, opts.Backend, opts.CA = a.Address, a.Backend, a.CA
			if rep, err = Probe(opts); err != nil {
				return nil, err
			}
			result = rep
		}
		stable := false
		if rep != nil && rep.OK {
			latest, err := c.getMap(a.Namespace, resource)
			if err != nil {
				return nil, err
			}
			stable = identityOf(latest) == identity && reflect.DeepEqual(RouteState(latest, a.Gateway, gwNS, a.Listener, a.Controller), state)
		}
		if identity != previous {
			consecutive = 0
		}
		if stable {
			consecutive++
		} else {
			consecutive = 0
		}
		previous = identity
		history = append(history, obj{"attempt": attempt + 1, "parent": state, "probe": result,
			"confirmed_after_probe": stable, "streak": consecutive})
		if consecutive >= a.Streak {
			return obj{"ok": true, "attempts": history}, nil
		}
		if attempt+1 < a.Attempts {
			time.Sleep(time.Duration(a.Interval * float64(time.Second)))
		}
	}
	return obj{"ok": false, "attempts": history}, nil
}

// Compare probes one URL through DNS and/or specific IP addresses.
func Compare(url string, targets []string, backend, ca string, status int) (obj, error) {
	seen := map[string]bool{}
	uniq := []string{}
	for _, t := range targets {
		if !seen[t] {
			seen[t] = true
			uniq = append(uniq, t)
		}
	}
	if len(uniq) > 16 {
		return nil, userError("at most 16 targets per comparison")
	}
	for _, t := range uniq {
		if t != "dns" && net.ParseIP(t) == nil {
			return nil, userErrorf("%s does not appear to be an IPv4 or IPv6 address", pyRepr(t))
		}
	}
	results := obj{}
	ok := true
	for _, t := range uniq {
		opts := NewProbe(url)
		opts.Status, opts.Backend, opts.CA = status, backend, ca
		if t != "dns" {
			opts.Address = t
		}
		r, err := Probe(opts)
		if err != nil {
			return nil, err
		}
		results[t] = r
		ok = ok && r.OK
	}
	return obj{"ok": ok, "targets": results}, nil
}

const snapshotSchema = "setura.route-specs/v1"

// Snapshot captures Gateway and HTTPRoute specs.
func Snapshot(c *Cluster, namespace string) (obj, error) {
	resources := obj{}
	for _, kind := range []string{gateway, route} {
		list, err := c.getMap(namespace, kind)
		if err != nil {
			return nil, err
		}
		for _, it := range asList(list["items"]) {
			m := asMap(it)
			resources[kind+"/"+asStr(req(asMap(req(m, "metadata")), "name"))] = req(m, "spec")
		}
	}
	snap := obj{"schema": snapshotSchema, "namespace": namespace, "resources": resources}
	captured, foreign := captureExtras(c, namespace, resources)
	if len(captured) > 0 {
		snap["captured"] = captured
	}
	if len(foreign) > 0 {
		snap["foreign"] = foreign
	}
	return snap, nil
}

func readSnapshot(path string) (obj, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	m := asMap(nil)
	if err := json.Unmarshal(raw, &v); err == nil {
		m = asMap(v)
	}
	if m == nil || m["schema"] != snapshotSchema || asMap(m["resources"]) == nil {
		return nil, userError("invalid Setura route snapshot")
	}
	return m, nil
}

// Diff compares two snapshots.
func Diff(before, after string) (obj, error) {
	left, err := readSnapshot(before)
	if err != nil {
		return nil, err
	}
	right, err := readSnapshot(after)
	if err != nil {
		return nil, err
	}
	a, b := asMap(left["resources"]), asMap(right["resources"])
	added, removed := []string{}, []string{}
	changed := obj{}
	for _, k := range sortedKeys(b) {
		if _, ok := a[k]; !ok {
			added = append(added, k)
		}
	}
	for _, k := range sortedKeys(a) {
		if bv, ok := b[k]; !ok {
			removed = append(removed, k)
		} else if !eq(a[k], bv) {
			changed[k] = obj{"before": a[k], "after": bv}
		}
	}
	return obj{"before_namespace": left["namespace"], "after_namespace": right["namespace"],
		"added": added, "removed": removed, "changed": changed, "equal": eq(a, b)}, nil
}

type junitFailure struct {
	Type string `xml:"type,attr"`
	Text string `xml:",chardata"`
}
type junitCase struct {
	Name    string        `xml:"name,attr"`
	Time    string        `xml:"time,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
}
type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Cases    []junitCase `xml:"testcase"`
}

// WriteJUnit writes check results as JUnit XML.
func WriteJUnit(rows []*Report, path string) error {
	suite := junitSuite{Name: "Setura routes", Tests: len(rows)}
	for _, r := range rows {
		c := junitCase{Name: r.URL, Time: fmt.Sprint(r.ElapsedMS / 1000)}
		if !r.OK {
			suite.Failures++
			for _, name := range stages {
				if s := r.Steps[name]; s.State() == "failed" {
					c.Failure = &junitFailure{Type: name, Text: pyDumps(stepMap(*s))}
					break
				}
			}
		}
		suite.Cases = append(suite.Cases, c)
	}
	body, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append([]byte(xml.Header), append(body, '\n')...), 0o644)
}

func stepMap(s Step) obj {
	m := obj{}
	for _, p := range s {
		m[p.K] = p.V
	}
	return m
}

// Listeners shows listener attachment, protocol and condition evidence.
func Listeners(c *Cluster, namespace, gw string) (obj, error) {
	name, err := label(gw)
	if err != nil {
		return nil, err
	}
	o, err := c.getMap(namespace, gateway+"/"+name)
	if err != nil {
		return nil, err
	}
	status := asMap(o["status"])
	observed := map[string]obj{}
	for _, l := range asList(status["listeners"]) {
		lm := asMap(l)
		observed[asStr(lm["name"])] = lm
	}
	gen := dig(o, "metadata", "generation")
	result := []any{}
	for _, l := range asList(dig(o, "spec", "listeners")) {
		requested := asMap(l)
		row := observed[asStr(req(requested, "name"))]
		conds := []any{}
		for _, c := range asList(row["conditions"]) {
			cm := asMap(c)
			cc := obj{}
			for k, v := range cm {
				cc[k] = v
			}
			cc["current"] = eq(cm["observedGeneration"], gen)
			conds = append(conds, cc)
		}
		result = append(result, obj{"spec": requested, "attached_routes": row["attachedRoutes"],
			"supported_kinds": row["supportedKinds"], "conditions": conds})
	}
	addrs := status["addresses"]
	if addrs == nil {
		addrs = []any{}
	}
	return obj{"gateway": gw, "generation": gen, "addresses": addrs, "listeners": result}, nil
}
