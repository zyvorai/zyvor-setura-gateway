package setura

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// LintPlans adds the plan file findings (SET020-SET022) to a lint report:
//
//	SET020  the plan file does not parse or validate the way the gateway reads it
//	SET021  a plan or the unmetered list names a route no HTTPRoute in the snapshot has
//	SET022  identities maps an API key name that no route's apiKey policy declares
//
// resource is how the file is named in findings.
func LintPlans(report obj, raw []byte, resource string, snapshot obj) obj {
	var findings []obj
	add := func(id, msg string) {
		findings = append(findings, obj{"id": id, "severity": ruleSeverity(id), "resource": resource, "message": msg})
	}
	ps, err := builtin.ParsePlans(raw)
	if err != nil {
		add("SET020", err.Error())
	} else {
		specs := asMap(snapshot["resources"])
		ns := asStr(snapshot["namespace"])
		var routes []string
		keys := map[string]bool{}
		for _, key := range sortedKeys(specs) {
			kind, name, _ := strings.Cut(key, "/")
			if kind != route {
				continue
			}
			routes = append(routes, ns+"/"+name)
			collectAPIKeyNames(asMap(specs[key]), keys)
		}
		for _, bad := range ps.UnknownRoutes(routes) {
			add("SET021", "route "+bad+" matches no HTTPRoute in the snapshot, so it never applies")
		}
		ids := make([]string, 0, len(ps.File.Identities))
		for id := range ps.File.Identities {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if name, ok := strings.CutPrefix(id, "apikey:"); ok && !keys[name] {
				add("SET022", fmt.Sprintf("identities[%q] maps an API key that no route's apiKey policy declares, so no request can present it", id))
			}
		}
	}
	if len(findings) == 0 {
		return report
	}
	all := asList(report["findings"])
	for _, f := range findings {
		all = append(all, f)
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := asMap(all[i]), asMap(all[j])
		if a["resource"] != b["resource"] {
			return asStr(a["resource"]) < asStr(b["resource"])
		}
		return asStr(a["id"]) < asStr(b["id"])
	})
	errs, warns := 0, 0
	for _, f := range all {
		if asMap(f)["severity"] == SeverityError {
			errs++
		} else {
			warns++
		}
	}
	report["findings"], report["errors"], report["warnings"], report["ok"] = all, errs, warns, errs == 0
	return report
}

// collectAPIKeyNames gathers the key names of every apiKey policy of a route:
// inline rule blocks and annotations.
func collectAPIKeyNames(spec obj, into map[string]bool) {
	take := func(raw []byte) {
		if p, err := builtin.ParseAuthBlock(raw); err == nil && p.APIKey != nil {
			for _, k := range p.APIKey.Keys {
				into[k.Name] = true
			}
		}
	}
	for _, r := range asList(spec["rules"]) {
		if block, ok := asMap(r)[builtin.AuthKey]; ok {
			raw, _ := json.Marshal(block)
			take(raw)
		}
	}
	ann := asMap(spec[builtin.SeturaAnnotationsKey])
	for k, v := range ann {
		if s, ok := v.(string); ok && strings.HasPrefix(k, builtin.AuthKey) {
			take([]byte(s))
		}
	}
}
