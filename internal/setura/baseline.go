package setura

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

const baselineSchema = "setura.lint-baseline/v1"

// LintOptions adjusts a lint report after analysis.
type LintOptions struct {
	Disable  []string          // rule IDs to drop
	Override map[string]string // rule ID -> severity
	Baseline map[string]bool   // fingerprints to ignore
}

// Fingerprint is a stable identity for a finding: rule id, resource and a
// hash of the message.
func Fingerprint(f obj) string {
	sum := sha256.Sum256([]byte(asStr(f["message"])))
	return asStr(f["id"]) + ":" + asStr(f["resource"]) + ":" + hex.EncodeToString(sum[:])[:12]
}

func knownRule(id string) bool {
	for _, r := range Rules {
		if r.ID == id {
			return true
		}
	}
	return false
}

// ParseDisable parses comma separated rule IDs (flag may repeat).
func ParseDisable(vals []string) ([]string, error) {
	var out []string
	for _, v := range vals {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id == "" {
				continue
			}
			if !knownRule(id) {
				return nil, userErrorf("unknown lint rule %q", id)
			}
			out = append(out, id)
		}
	}
	return out, nil
}

// ParseOverrides parses RULE=error|warning pairs.
func ParseOverrides(vals []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p == "" {
				continue
			}
			id, sev, ok := strings.Cut(p, "=")
			id, sev = strings.TrimSpace(id), strings.TrimSpace(sev)
			if !ok || !knownRule(id) || (sev != SeverityError && sev != SeverityWarning) {
				return nil, userErrorf("invalid --severity-override %q; want RULE=error|warning", p)
			}
			out[id] = sev
		}
	}
	return out, nil
}

// ReadBaseline loads a baseline file.
func ReadBaseline(path string) (map[string]bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b struct {
		Schema       string   `json:"schema"`
		Fingerprints []string `json:"fingerprints"`
	}
	if err := json.Unmarshal(raw, &b); err != nil || b.Schema != baselineSchema {
		return nil, userError("invalid Setura lint baseline")
	}
	set := map[string]bool{}
	for _, fp := range b.Fingerprints {
		set[fp] = true
	}
	return set, nil
}

// WriteBaseline records every finding of the report.
func WriteBaseline(report obj, path string) error {
	var fps []string
	for _, f := range asList(report["findings"]) {
		fps = append(fps, Fingerprint(asMap(f)))
	}
	sort.Strings(fps)
	if fps == nil {
		fps = []string{}
	}
	body, err := json.MarshalIndent(obj{"schema": baselineSchema, "fingerprints": fps}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

// ApplyLintOptions returns a copy of the report with disabled rules removed,
// severities overridden and baselined findings suppressed. Counts are
// recomputed; "suppressed" reports how many baselined findings were hidden.
func ApplyLintOptions(report obj, o LintOptions) obj {
	off := map[string]bool{}
	for _, id := range o.Disable {
		off[id] = true
	}
	findings, errs, warns, suppressed := []any{}, 0, 0, 0
	for _, f := range asList(report["findings"]) {
		m := asMap(f)
		if off[asStr(m["id"])] {
			continue
		}
		c := obj{}
		for k, v := range m {
			c[k] = v
		}
		if sev, ok := o.Override[asStr(c["id"])]; ok {
			c["severity"] = sev
		}
		if o.Baseline[Fingerprint(c)] {
			suppressed++
			continue
		}
		if c["severity"] == SeverityError {
			errs++
		} else {
			warns++
		}
		findings = append(findings, c)
	}
	res := obj{}
	for k, v := range report {
		res[k] = v
	}
	res["findings"], res["errors"], res["warnings"], res["ok"] = findings, errs, warns, errs == 0
	if suppressed > 0 {
		res["suppressed"] = suppressed
	}
	return res
}

func lintSummary(report obj) string {
	if n, _ := num(report["suppressed"]); n > 0 {
		return fmt.Sprintf("%d finding(s) suppressed by baseline\n", int(n))
	}
	return ""
}

func fingerprintSet(report obj) map[string]bool {
	set := map[string]bool{}
	for _, f := range asList(report["findings"]) {
		set[Fingerprint(asMap(f))] = true
	}
	return set
}
