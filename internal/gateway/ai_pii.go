package gateway

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// PII modes.
const (
	PIIRedact = "redact"
	PIIBlock  = "block"
	PIIReport = "report"
)

type piiRule struct {
	name    string
	re      *regexp.Regexp
	repl    string
	confirm func(match string) bool // nil accepts every regexp match
}

type compiledPII struct {
	mode  string
	rules []piiRule
}

var builtinPII = map[string]func() piiRule{
	"email": func() piiRule {
		return piiRule{name: "email", re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}`), repl: "[REDACTED:email]"}
	},
	"phone": func() piiRule {
		return piiRule{name: "phone", repl: "[REDACTED:phone]", re: regexp.MustCompile(
			`\+\d{10,15}\b|(?:\+\d{1,3}[ .\-]?)?(?:\(\d{2,4}\)[ .\-]?|\b\d{2,4}[ .\-])\d{3,4}[ .\-]\d{3,4}\b`), confirm: phoneOK}
	},
	"card": func() piiRule {
		return piiRule{name: "card", repl: "[REDACTED:card]", re: regexp.MustCompile(`\b\d(?:[ \-]?\d){12,18}\b`), confirm: luhnOK}
	},
	"ssn": func() piiRule {
		return piiRule{name: "ssn", repl: "[REDACTED:ssn]", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), confirm: ssnOK}
	},
}

// builtinPIIOrder is the order built-in rules run in: the card rule goes
// before the phone rule so a card number is not eaten as a phone number.
var builtinPIIOrder = []string{"card", "ssn", "email", "phone"}

// luhnOK reports whether the digits of s (13 to 19 of them) pass the Luhn check.
func luhnOK(s string) bool {
	var digits []int
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			digits = append(digits, int(c-'0'))
		case c == ' ' || c == '-':
		default:
			return false
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum > 0 && sum%10 == 0
}

// ssnOK rejects the number ranges the SSA never issues.
func ssnOK(s string) bool {
	area, group, serial := s[0:3], s[4:6], s[7:11]
	return area != "000" && area != "666" && area[0] != '9' && group != "00" && serial != "0000"
}

func compilePII(p *AIPII) (*compiledPII, error) {
	c := &compiledPII{mode: p.Mode}
	switch c.mode {
	case "":
		c.mode = PIIRedact
	case PIIRedact, PIIBlock, PIIReport:
	default:
		return nil, fmt.Errorf("pii.mode %q is not redact, block or report", p.Mode)
	}
	names := p.Rules
	if names == nil { // not given: all built-in rules; an empty list means custom rules only
		names = builtinPIIOrder
	}
	want := map[string]bool{}
	for _, n := range names {
		if builtinPII[n] == nil {
			return nil, fmt.Errorf("pii.rules: %q is not one of email, phone, card, ssn", n)
		}
		want[n] = true
	}
	for _, n := range builtinPIIOrder {
		if want[n] {
			c.rules = append(c.rules, builtinPII[n]())
		}
	}
	if len(p.Custom) > aiMaxCustomPIIRules {
		return nil, fmt.Errorf("pii.custom: at most %d rules", aiMaxCustomPIIRules)
	}
	seen := map[string]bool{}
	for i, cu := range p.Custom {
		if !aiNameRe.MatchString(cu.Name) || builtinPII[cu.Name] != nil || seen[cu.Name] {
			return nil, fmt.Errorf("pii.custom[%d]: name %q must be unique, simple and not a built-in rule name", i, cu.Name)
		}
		seen[cu.Name] = true
		if cu.Pattern == "" || len(cu.Pattern) > aiMaxPIIPatternBytes {
			return nil, fmt.Errorf("pii.custom[%d]: pattern must be 1-%d bytes", i, aiMaxPIIPatternBytes)
		}
		re, err := regexp.Compile(cu.Pattern) // RE2: linear time, no catastrophic backtracking
		if err != nil {
			return nil, fmt.Errorf("pii.custom[%d] %s: %v", i, cu.Name, err)
		}
		repl := cu.Replacement
		if repl == "" {
			repl = "[REDACTED:" + cu.Name + "]"
		}
		c.rules = append(c.rules, piiRule{name: cu.Name, re: re, repl: repl})
	}
	if len(c.rules) == 0 {
		return nil, fmt.Errorf("pii: no rules")
	}
	return c, nil
}

// piiSkipKeys are JSON keys whose string values are structure, not prompt text.
var piiSkipKeys = map[string]bool{
	"role": true, "type": true, "id": true, "name": true, "tool_call_id": true, "model": true,
	"url": true, "data": true, "media_type": true, "detail": true, "tool_use_id": true,
}

// piiScanKeys are the request fields that carry prompt text.
var piiScanKeys = []string{"messages", "prompt", "input", "system"}

// piiResult counts what one request matched, per rule. It never keeps the matched text.
type piiResult map[string]int

func (r piiResult) total() int {
	n := 0
	for _, v := range r {
		n += v
	}
	return n
}

// summary is "email=2,card=1" in rule name order, or "" when empty.
func (r piiResult) summary() string {
	names := make([]string, 0, len(r))
	for k := range r {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, k := range names {
		parts[i] = fmt.Sprintf("%s=%d", k, r[k])
	}
	return strings.Join(parts, ",")
}

// apply scans the prompt fields of body. In redact mode the matched text is
// replaced in place. changed says whether body was modified.
func (c *compiledPII) apply(body map[string]any) (res piiResult, changed bool) {
	res = piiResult{}
	for _, k := range piiScanKeys {
		if v, ok := body[k]; ok {
			nv, ch := c.walk(v, res, "")
			if ch {
				body[k], changed = nv, true
			}
		}
	}
	return res, changed
}

func (c *compiledPII) walk(v any, res piiResult, key string) (any, bool) {
	switch t := v.(type) {
	case string:
		if piiSkipKeys[key] {
			return v, false
		}
		out := t
		for _, r := range c.rules {
			out = r.re.ReplaceAllStringFunc(out, func(m string) string {
				if r.confirm != nil && !r.confirm(m) {
					return m
				}
				res[r.name]++
				if c.mode != PIIRedact {
					return m
				}
				return r.repl
			})
		}
		return out, out != t
	case []any:
		changed := false
		for i, e := range t {
			if ne, ch := c.walk(e, res, key); ch {
				t[i], changed = ne, true
			}
		}
		return t, changed
	case map[string]any:
		changed := false
		for k, e := range t {
			if ne, ch := c.walk(e, res, k); ch {
				t[k], changed = ne, true
			}
		}
		return t, changed
	}
	return v, false
}

// phoneOK rejects three groups of four digits: that is the shape of a card
// number (which the card rule decides on) more than of a telephone number.
func phoneOK(s string) bool {
	g := strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '.' || r == '-' })
	return !(len(g) == 3 && len(g[0]) == 4 && len(g[1]) == 4 && len(g[2]) == 4)
}
