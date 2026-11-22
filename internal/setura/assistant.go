package setura

import (
	"fmt"
	"strconv"
	"strings"
)

var hints = map[string]string{
	"dns":     "Check the hostname in the resolver used by the probing host.",
	"tcp":     "Check the destination port and whether the listener or forward is running.",
	"tls":     "Check certificate trust, validity and the requested hostname.",
	"http":    "Compare the returned status with the route's expected status.",
	"backend": "Check backend weights and the release identity header on the responding application.",
	"assert":  "Compare the response headers, body or latency with the route's declared expectations.",
}

// Fact is one bounded observation extracted from a diagnostic report.
type Fact struct {
	ID          string  `json:"id"`
	Subject     string  `json:"subject"`
	Observation string  `json:"observation"`
	NextCheck   *string `json:"next_check"`
}

// Evidence extracts bounded diagnostic facts from a saved Setura JSON report.
func Evidence(report any) ([]Fact, error) {
	var facts []Fact
	add := func(subject, observation, next string) {
		f := Fact{ID: "E" + strconv.Itoa(len(facts)+1), Subject: subject, Observation: observation}
		if next != "" {
			f.NextCheck = &next
		}
		facts = append(facts, f)
	}
	var visit func(data any, subject string) error
	visit = func(data any, subject string) error {
		if list, ok := data.([]any); ok {
			for i, item := range list {
				if err := visit(item, fmt.Sprintf("%s case %d", subject, i+1)); err != nil {
					return err
				}
			}
			return nil
		}
		m, ok := data.(map[string]any)
		if !ok {
			return userError("unsupported diagnostic report")
		}
		_, hasSteps := m["steps"]
		_, hasOK := m["ok"]
		_, hasTargets := m["targets"]
		_, hasAttempts := m["attempts"]
		_, hasParents := m["parents"]
		_, hasBackends := m["backends"]
		_, hasDeps := m["dependent_routes"]
		_, hasUp := m["upstream"]
		switch {
		case hasSteps && hasOK:
			steps := asMap(m["steps"])
			order := append([]string{}, stages...)
			for _, k := range sortedKeys(steps) {
				known := false
				for _, s := range stages {
					known = known || s == k
				}
				if !known {
					order = append(order, k)
				}
			}
			for _, stage := range order {
				item, present := steps[stage]
				if !present {
					continue
				}
				if im := asMap(item); im["state"] == "failed" {
					reason := "unspecified"
					if r, ok := im["reason"]; ok {
						reason = fmt.Sprint(r)
					}
					hint := hints[stage]
					if stage == "tls" && strings.Contains(reason, "client certificate") {
						hint = "Check --cert/--key and the client CA bundle trusted by the gateway listener."
					}
					add(subject, stage+" failed: "+reason, hint)
				} else if stage == "tls" {
					tlsFacts(im, func(o string) { add(subject, o, "") })
				}
			}
			if m["ok"] == true {
				add(subject, "The recorded request passed its configured assertions.", "")
			}
		case hasTargets:
			targets := asMap(m["targets"])
			for _, addr := range sortedKeys(targets) {
				if err := visit(targets[addr], "target "+addr); err != nil {
					return err
				}
			}
		case hasAttempts:
			attempts := asList(m["attempts"])
			if len(attempts) == 0 {
				return userError("empty gate history")
			}
			last := asMap(attempts[len(attempts)-1])
			parent := asMap(req(last, "parent"))
			streak, _ := num(req(last, "streak"))
			add(subject, fmt.Sprintf("Final gate result: %s; consecutive passes: %d.", pyBool(m["ok"]), int(streak)), "")
			if parent["ok"] != true {
				add(subject, "Parent gate failed: "+pyDumps(parent),
					"Read the selected parent's Accepted and ResolvedRefs conditions and observed generation.")
			}
			if p := last["probe"]; p != nil {
				if err := visit(p, "final request"); err != nil {
					return err
				}
				if asMap(p)["ok"] == true && last["confirmed_after_probe"] != true {
					add(subject, "The route state could not be confirmed after the successful probe.",
						"Check whether the route was replaced or reconciled during the attempt.")
				}
			}
		case hasParents && hasBackends:
			parents := asList(m["parents"])
			if len(parents) == 0 {
				add(subject, "No parent status entries were reported.", "Inspect the parent reference and controller.")
			}
			for _, e := range parents {
				entry := asMap(e)
				for _, c := range asList(entry["conditions"]) {
					cm := asMap(c)
					if t := cm["type"]; t == "Accepted" || t == "ResolvedRefs" {
						add(asStr(asMap(entry["parent"])["name"]), fmt.Sprintf("%s=%v, current=%s, reason=%v.", t, cm["status"], pyBool(cm["current"]), cm["reason"]), "")
					}
				}
			}
			for _, b := range asList(m["backends"]) {
				row := asMap(b)
				name := asStr(row["namespace"]) + "/" + asStr(asMap(row["reference"])["name"])
				_, e1 := row["observation_error"]
				_, e2 := row["observation"]
				if e1 || e2 {
					add(name, "Endpoint inventory unavailable.", "Check read permissions and backend kind.")
				}
				if v, ok := row["service_port_found"]; ok {
					add(name, "Referenced Service port present: "+pyBool(v), "")
				}
				if v, ok := row["endpoint_records_by_ready_condition"]; ok {
					add(name, "Service-wide endpoint record counts: "+pyDumps(v), "")
				}
			}
		case m["schema"] == "setura.topology/v1":
			for _, e := range asList(m["edges"]) {
				edge := asMap(e)
				relation := asStr(edge["relation"])
				detail := relation + " to " + asStr(edge["to"])
				if relation == "backendRef" {
					detail += fmt.Sprintf(" on port %s with configured weight %s", pyNone(edge["port"]), pyNone(edge["weight"]))
				}
				add(asStr(edge["from"]), detail, "")
			}
		case m["schema"] == lintSchema:
			for _, f := range asList(m["findings"]) {
				fm := asMap(f)
				add(asStr(fm["resource"]), fmt.Sprintf("%s %s: %s", asStr(fm["id"]), asStr(fm["severity"]), asStr(fm["message"])), "")
			}
			if len(asList(m["findings"])) == 0 {
				add(subject, "Static lint found no issues in the declared specs.", "")
			}
		case hasDeps && hasUp:
			add(asStr(m["target"]), "Declared upstream HTTPRoutes with positive-weight paths: "+pyDumps(m["dependent_routes"]),
				"Probe affected routes to establish runtime impact.")
		case isBenchLike(m):
			add(subject, benchObservation(m), "")
		default:
			return userError("expected explain --json, check, compare, gate, inspect, map --format json, or impact output")
		}
		return nil
	}
	if err := visit(report, "report"); err != nil {
		return nil, err
	}
	if len(facts) == 0 {
		return nil, userError("report contains no supported observations")
	}
	return facts, nil
}

func pyBool(v any) string {
	if v == true {
		return "True"
	}
	return "False"
}

func pyNone(v any) string {
	if v == nil {
		return "None"
	}
	if f, ok := v.(float64); ok {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// Finding is one model interpretation citing evidence IDs.
type Finding struct {
	Interpretation string   `json:"interpretation"`
	EvidenceIDs    []string `json:"evidence_ids"`
	Suggestions    []string `json:"suggested_commands,omitempty"`
}
