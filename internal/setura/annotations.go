package setura

import (
	"fmt"
	"strings"
)

// escapeData escapes a GitHub workflow command message.
func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// escapeProperty escapes a GitHub workflow command property value.
func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

// annotation renders one workflow command, e.g. ::error title=SET002::msg.
func annotation(level, title, file string, line int, message string) string {
	props := []string{}
	if file != "" {
		props = append(props, "file="+escapeProperty(file))
		if line > 0 {
			props = append(props, fmt.Sprintf("line=%d", line))
		}
	}
	if title != "" {
		props = append(props, "title="+escapeProperty(title))
	}
	cmd := "::" + level
	if len(props) > 0 {
		cmd += " " + strings.Join(props, ",")
	}
	return cmd + "::" + escapeData(message) + "\n"
}

// LintAnnotations renders lint findings as GitHub Actions annotations.
func LintAnnotations(report obj, locs ManifestIndex) string {
	var b strings.Builder
	for _, f := range asList(report["findings"]) {
		m := asMap(f)
		level := "warning"
		if m["severity"] == SeverityError {
			level = "error"
		}
		loc := locs.Find(asStr(m["resource"]), asStr(report["namespace"]))
		b.WriteString(annotation(level, asStr(m["id"]), loc.File, loc.Line, asStr(m["resource"])+": "+asStr(m["message"])))
	}
	return b.String()
}

// failedStage returns the first failed stage of a probe report.
func failedStage(r *Report) (string, Step) {
	for _, name := range stages {
		if s := r.Steps[name]; s != nil && s.State() == "failed" {
			return name, *s
		}
	}
	return "", nil
}

func stageReason(s Step) string {
	if r := asStr(s.Get("reason")); r != "" {
		return r
	}
	if r := asStr(s.Get("error")); r != "" {
		return r
	}
	return pyDumps(stepMap(s))
}

// CheckAnnotations renders failed probes as GitHub Actions annotations.
func CheckAnnotations(rows []*Report, file string) string {
	var b strings.Builder
	for _, r := range rows {
		if r.OK {
			continue
		}
		name, s := failedStage(r)
		if name == "" {
			name = "probe"
		}
		b.WriteString(annotation("error", "setura "+name, file, 0, r.URL+": "+name+" failed: "+stageReason(s)))
	}
	return b.String()
}
