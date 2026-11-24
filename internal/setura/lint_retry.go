package setura

import (
	"fmt"
	"strings"
	"time"
)

// maxRetryAttempts mirrors the gateway's limit on retry.attempts.
const maxRetryAttempts = 10

// retryRules evaluates SET091 and SET092 on the `retry` block of each
// HTTPRoute rule. The gateway refuses a route whose retry block fails
// SET091, so the checks follow its compile rules.
func retryRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		if resource != route {
			continue
		}
		id := "HTTPRoute/" + ns + "/" + name
		add := func(rid string, i int, msg string) {
			findings = append(findings, obj{"id": rid, "severity": ruleSeverity(rid), "resource": id,
				"message": fmt.Sprintf("rule %d: %s", i+1, msg)})
		}
		for i, r := range asList(asMap(specs[key])["rules"]) {
			rt, has := asMap(r)["retry"]
			if !has {
				continue
			}
			rm := asMap(rt)
			if rm == nil {
				add("SET091", i, "retry must be an object")
				continue
			}
			for _, c := range asList(rm["codes"]) {
				if n, ok := num(c); !ok || n < 400 || n > 599 || n != float64(int(n)) {
					add("SET091", i, fmt.Sprintf("retry.codes: %v is not a status code in 400-599", c))
				}
			}
			if v, ok := rm["attempts"]; ok {
				n, isNum := num(v)
				switch {
				case !isNum || n != float64(int(n)) || n < 0 || n > maxRetryAttempts:
					add("SET091", i, fmt.Sprintf("retry.attempts: %v is not a whole number in 0-%d", v, maxRetryAttempts))
				case n == 0:
					add("SET092", i, "retry.attempts is 0, so the retry block never retries; remove it or set attempts to 1 or more")
				}
			}
			if v, ok := rm["backoff"]; ok {
				if d, err := time.ParseDuration(asStr(v)); err != nil || d < 0 {
					add("SET091", i, fmt.Sprintf("retry.backoff: %v is not a duration such as 25ms (zero or more)", v))
				}
			}
			if v, ok := rm["perTryTimeout"]; ok {
				if d, err := time.ParseDuration(asStr(v)); err != nil || d <= 0 {
					add("SET091", i, fmt.Sprintf("retry.perTryTimeout: %v is not a positive duration such as 2s", v))
				}
			}
			if v, ok := rm["jitter"]; ok {
				if n, isNum := num(v); !isNum || n < 0 || n > 1 {
					add("SET091", i, fmt.Sprintf("retry.jitter: %v is outside 0-1", v))
				}
			}
		}
	}
	return findings
}
