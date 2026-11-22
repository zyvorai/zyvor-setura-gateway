package setura

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
)

const sarifSchemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

func sarifLevel(sev string) string {
	if sev == SeverityError {
		return "error"
	}
	return "warning"
}

func sarifDriver(rules []any) obj {
	return obj{"name": "setura", "version": Version, "informationUri": "https://github.com/zyvorai/zyvor-setura-gateway", "rules": rules}
}

func sarifDoc(driver obj, results []any) obj {
	return obj{"version": "2.1.0", "$schema": sarifSchemaURL,
		"runs": []any{obj{"tool": obj{"driver": driver}, "results": results}}}
}

func marshalSARIF(doc obj) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// LintSARIF renders a lint report as SARIF 2.1.0. Overridden severities are
// reflected in each result level.
func LintSARIF(report obj, locs ManifestIndex) ([]byte, error) {
	rules := make([]any, len(Rules))
	index := map[string]int{}
	for i, r := range Rules {
		index[r.ID] = i
		rules[i] = obj{
			"id": r.ID, "name": r.ID,
			"shortDescription":     obj{"text": r.Summary},
			"fullDescription":      obj{"text": r.Summary},
			"help":                 obj{"text": r.Summary + ". See docs/ci.md and `setura lint --rules`."},
			"defaultConfiguration": obj{"level": sarifLevel(r.Severity)},
		}
	}
	results := []any{}
	for _, f := range asList(report["findings"]) {
		m := asMap(f)
		resource := asStr(m["resource"])
		kind, _, _ := strings.Cut(resource, "/")
		loc := obj{"logicalLocations": []any{obj{"name": resource[strings.LastIndex(resource, "/")+1:], "fullyQualifiedName": resource, "kind": kind}}}
		if l := locs.Find(resource, asStr(report["namespace"])); l.File != "" {
			loc["physicalLocation"] = obj{"artifactLocation": obj{"uri": l.File}, "region": obj{"startLine": l.Line}}
		}
		results = append(results, obj{
			"ruleId": m["id"], "ruleIndex": index[asStr(m["id"])],
			"level":               sarifLevel(asStr(m["severity"])),
			"message":             obj{"text": asStr(m["message"])},
			"locations":           []any{loc},
			"partialFingerprints": obj{"setura/v1": Fingerprint(m)},
		})
	}
	return marshalSARIF(sarifDoc(sarifDriver(rules), results))
}

// CheckSARIF renders failed probe stages as SARIF results. file is the check
// file the cases came from.
func CheckSARIF(rows []*Report, file string) ([]byte, error) {
	rules := make([]any, len(stages))
	index := map[string]int{}
	for i, s := range stages {
		id := "SETCHK-" + strings.ToUpper(s)
		index[s] = i
		rules[i] = obj{
			"id": id, "name": id,
			"shortDescription":     obj{"text": "probe stage " + s + " failed"},
			"help":                 obj{"text": "The " + s + " stage of a setura probe failed; see the message for the observed reason."},
			"defaultConfiguration": obj{"level": "error"},
		}
	}
	results := []any{}
	for _, r := range rows {
		if r.OK {
			continue
		}
		name, s := failedStage(r)
		if name == "" {
			name = stages[len(stages)-1]
		}
		loc := obj{"logicalLocations": []any{obj{"name": r.URL, "fullyQualifiedName": r.URL, "kind": "url"}}}
		if file != "" {
			loc["physicalLocation"] = obj{"artifactLocation": obj{"uri": strings.ReplaceAll(file, "\\", "/")}, "region": obj{"startLine": 1}}
		}
		results = append(results, obj{
			"ruleId": "SETCHK-" + strings.ToUpper(name), "ruleIndex": index[name], "level": "error",
			"message":   obj{"text": r.URL + ": " + name + " failed: " + stageReason(s)},
			"locations": []any{loc},
		})
	}
	return marshalSARIF(sarifDoc(sarifDriver(rules), results))
}

func writeFile(path string, b []byte) error { return os.WriteFile(path, b, 0o644) }
