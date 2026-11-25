package setura

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Thresholds for "setura bench", in the style of k6: "p95<200",
// "p(99.9)<=1500ms", "error_rate<0.01", "rps>=50". Latencies are plain numbers
// in milliseconds (an "ms" suffix is optional). Every threshold must hold for
// the run to pass.

const maxThresholds = 32

var thresholdRe = regexp.MustCompile(`^\s*(p\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)|p([0-9]+(?:\.[0-9]+)?)|min|avg|mean|med|max|rps|requests|errors|error_rate)\s*(<=|>=|==|!=|<|>)\s*([0-9]+(?:\.[0-9]+)?)\s*(ms)?\s*$`)

// Threshold is one parsed expression.
type Threshold struct {
	Expr   string
	metric string  // "p", "min", "avg", "max", "rps", "requests", "errors" or "error_rate"
	pct    float64 // for "p"
	op     string
	want   float64
}

// ParseThresholds parses --threshold values.
func ParseThresholds(items []string) ([]Threshold, error) {
	if len(items) > maxThresholds {
		return nil, userErrorf("at most %d --threshold values are allowed", maxThresholds)
	}
	var out []Threshold
	for _, it := range items {
		m := thresholdRe.FindStringSubmatch(it)
		bad := func(why string) error {
			return userErrorf("--threshold %q: %s", clipStr(it, 60), why)
		}
		if m == nil {
			return nil, bad(`expected METRIC OP NUMBER, for example "p95<200", "avg<100ms", "error_rate<0.01" or "rps>=50" (metrics: min, avg, med, p(N), max, rps, requests, errors, error_rate)`)
		}
		t := Threshold{Expr: strings.TrimSpace(it), metric: m[1], op: m[4]}
		var err error
		if t.want, err = strconv.ParseFloat(m[5], 64); err != nil || math.IsInf(t.want, 0) {
			return nil, bad("the number is out of range")
		}
		switch {
		case m[2] != "" || m[3] != "":
			t.metric = "p"
			if t.pct, err = strconv.ParseFloat(m[2]+m[3], 64); err != nil || t.pct < 0 || t.pct > 100 {
				return nil, bad("a percentile is between 0 and 100")
			}
		case m[1] == "med":
			t.metric, t.pct = "p", 50
		case m[1] == "mean":
			t.metric = "avg"
		}
		latency := t.metric == "p" || t.metric == "min" || t.metric == "avg" || t.metric == "max"
		if m[6] != "" && !latency {
			return nil, bad("the ms suffix applies to latency metrics only")
		}
		if t.metric == "error_rate" && t.want > 1 {
			return nil, bad("error_rate is a share from 0 to 1, not a percentage")
		}
		out = append(out, t)
	}
	return out, nil
}

type benchStats struct {
	latencies []float64 // sorted, milliseconds
	sum       float64
	failures  int
	seconds   float64
}

func (s benchStats) value(t Threshold) (float64, bool) {
	n := len(s.latencies)
	switch t.metric {
	case "requests":
		return float64(n), true
	case "errors":
		return float64(s.failures), n > 0
	}
	if n == 0 {
		return 0, false
	}
	switch t.metric {
	case "p":
		return percentile(s.latencies, t.pct), true
	case "min":
		return s.latencies[0], true
	case "max":
		return s.latencies[n-1], true
	case "avg":
		return s.sum / float64(n), true
	case "rps":
		return float64(n) / s.seconds, s.seconds > 0
	case "error_rate":
		return float64(s.failures) / float64(n), true
	}
	return 0, false
}

// evalThresholds returns one result per threshold and the failures as text. A
// threshold with nothing to measure fails.
func evalThresholds(ts []Threshold, s benchStats) (results []any, violations []string) {
	for _, t := range ts {
		got, have := s.value(t)
		ok := false
		if have {
			switch t.op {
			case "<":
				ok = got < t.want
			case "<=":
				ok = got <= t.want
			case ">":
				ok = got > t.want
			case ">=":
				ok = got >= t.want
			case "==":
				ok = got == t.want
			case "!=":
				ok = got != t.want
			}
		}
		row := obj{"expr": t.Expr, "ok": ok}
		shown := "no samples"
		if have {
			v := math.Round(got*10000) / 10000
			row["observed"] = v
			shown = fmt.Sprintf("observed %v", v)
		}
		results = append(results, row)
		if !ok {
			violations = append(violations, fmt.Sprintf("threshold %q failed: %s", t.Expr, shown))
		}
	}
	return results, violations
}
