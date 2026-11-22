package setura

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
)

//go:embed map.html
var mapTemplate string

// BuildTopology builds a directed graph of declared Gateway API relationships.
func BuildTopology(snapshot obj) (obj, error) {
	ns, ok := snapshot["namespace"].(string)
	specs := asMap(snapshot["resources"])
	if snapshot["schema"] != snapshotSchema {
		return nil, userError("expected a Setura route snapshot")
	}
	if !ok || specs == nil {
		return nil, userError("invalid snapshot namespace or resources")
	}
	nodes := map[string]obj{}
	order := []string{}
	edges := []any{}

	node := func(kind, namespace, name string, details obj) string {
		key := kind + "/" + namespace + "/" + name
		item, ok := nodes[key]
		if !ok {
			item = obj{"id": key, "kind": kind, "namespace": namespace, "name": name}
			nodes[key] = item
			order = append(order, key)
		}
		for k, v := range details {
			item[k] = v
		}
		return key
	}
	edge := func(from, to, relation string, props obj) {
		e := obj{"from": from, "to": to, "relation": relation}
		for k, v := range props {
			e[k] = v
		}
		edges = append(edges, e)
	}
	hasEdge := func(from, to string) bool {
		for _, e := range edges {
			if m := e.(obj); m["from"] == from && m["to"] == to {
				return true
			}
		}
		return false
	}

	for _, key := range sortedKeys(specs) {
		spec := asMap(specs[key])
		resource, name, _ := strings.Cut(key, "/")
		switch resource {
		case gateway:
			gw := node("Gateway", ns, name, obj{"declared": true, "gatewayClass": spec["gatewayClassName"]})
			for _, l := range asList(spec["listeners"]) {
				entry := asMap(l)
				ln := node("Listener", ns, name+"#"+asStr(req(entry, "name")), obj{
					"declared": true, "port": req(entry, "port"), "protocol": req(entry, "protocol"), "hostname": entry["hostname"]})
				edge(gw, ln, "listens", nil)
			}
		case route:
			hostnames := spec["hostnames"]
			if hostnames == nil {
				hostnames = []any{}
			}
			rt := node("HTTPRoute", ns, name, obj{"declared": true, "hostnames": hostnames})
			for _, p := range asList(spec["parentRefs"]) {
				parent := asMap(p)
				pns, pname := str(parent, "namespace", ns), asStr(req(parent, "name"))
				var source string
				if str(parent, "group", group) == group && str(parent, "kind", "Gateway") == "Gateway" {
					gw := node("Gateway", pns, pname, nil)
					source = gw
					if sn, ok := parent["sectionName"]; ok {
						source = node("Listener", pns, pname+"#"+asStr(sn), nil)
						if !hasEdge(gw, source) {
							edge(gw, source, "listens", nil)
						}
					}
				} else {
					source = node("Parent", pns, str(parent, "group", group)+":"+str(parent, "kind", "Gateway")+":"+pname, nil)
				}
				edge(source, rt, "parentRef", obj{"port": parent["port"]})
			}
			for i, r := range asList(spec["rules"]) {
				rule := asMap(r)
				matches := rule["matches"]
				if matches == nil {
					matches = []any{}
				}
				filters := []any{}
				for _, f := range asList(rule["filters"]) {
					filters = append(filters, req(asMap(f), "type"))
				}
				ruleID := node("Rule", ns, fmt.Sprintf("%s#%d", name, i+1), obj{"matches": matches, "filters": filters})
				edge(rt, ruleID, "contains", nil)
				for _, b := range asList(rule["backendRefs"]) {
					ref := asMap(b)
					g, k := str(ref, "group", ""), str(ref, "kind", "Service")
					bn := asStr(req(ref, "name"))
					kind := "Backend"
					if g == "" && k == "Service" {
						kind = "Service"
					} else {
						bn = g + ":" + k + ":" + bn
					}
					backend := node(kind, str(ref, "namespace", ns), bn, nil)
					weight, has := ref["weight"]
					if !has {
						weight = float64(1)
					}
					edge(ruleID, backend, "backendRef", obj{"weight": weight, "port": ref["port"]})
				}
			}
		}
	}
	list := make([]any, len(order))
	for i, k := range order {
		list[i] = nodes[k]
	}
	return obj{"schema": "setura.topology/v1", "namespace": ns, "nodes": list, "edges": edges}, nil
}

// Impact finds upstream routes that depend on a node.
func Impact(graph obj, target string) (obj, error) {
	found := false
	for _, n := range asList(graph["nodes"]) {
		if asMap(n)["id"] == target {
			found = true
		}
	}
	if !found {
		return nil, userErrorf("unknown node %s; use map --format json to list node IDs", pyRepr(target))
	}
	upstream := map[string][]string{}
	for _, e := range asList(graph["edges"]) {
		em := asMap(e)
		w := 1.0
		if v, ok := num(em["weight"]); ok {
			w = v
		}
		if w > 0 {
			to := asStr(em["to"])
			upstream[to] = append(upstream[to], asStr(em["from"]))
		}
	}
	seen := map[string]bool{target: true}
	pending := []string{target}
	for len(pending) > 0 {
		cur := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, p := range upstream[cur] {
			if !seen[p] {
				seen[p] = true
				pending = append(pending, p)
			}
		}
	}
	up, routes := []string{}, []string{}
	for k := range seen {
		if k == target {
			continue
		}
		up = append(up, k)
		if strings.HasPrefix(k, "HTTPRoute/") {
			routes = append(routes, k)
		}
	}
	sort.Strings(up)
	sort.Strings(routes)
	return obj{"target": target, "upstream": up, "dependent_routes": routes}, nil
}

// Page renders the interactive topology map as a self-contained HTML page.
func Page(graph obj) (string, error) {
	payload, err := json.Marshal(graph) // escapes <, > and & as \u00XX
	if err != nil {
		return "", err
	}
	out := strings.ReplaceAll(mapTemplate, "NAMESPACE_LABEL", html.EscapeString(asStr(graph["namespace"])))
	return strings.ReplaceAll(out, "GRAPH_PAYLOAD", string(payload)), nil
}
