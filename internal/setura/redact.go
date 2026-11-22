package setura

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	redactToken  = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{1,4}|(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?\.)+[A-Za-z][A-Za-z0-9-]*|[A-Za-z0-9_][A-Za-z0-9_-]*`)
	redactIPv4   = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)
	redactQuoted = regexp.MustCompile(`'([^']*)'`)
	placeholder  = regexp.MustCompile(`\b(?:ip|host|ns|value)-\d+\b`)
)

// Redactor replaces sensitive tokens with stable placeholders (host-1, ip-1,
// ns-1, value-1) and can reverse the substitution on a model's answer. The
// mapping lives only in memory and is never sent anywhere.
type Redactor struct {
	forward    map[string]string
	reverse    map[string]string
	counts     map[string]int
	namespaces map[string]bool
}

// NewRedactor masks the given namespaces in addition to IPs and hostnames.
func NewRedactor(namespaces []string) *Redactor {
	r := &Redactor{forward: map[string]string{}, reverse: map[string]string{}, counts: map[string]int{}, namespaces: map[string]bool{}}
	for _, n := range namespaces {
		if n != "" {
			r.namespaces[n] = true
		}
	}
	return r
}

func (r *Redactor) name(kind, original string) string {
	key := kind + "\x00" + original
	if p, ok := r.forward[key]; ok {
		return p
	}
	r.counts[kind]++
	p := kind + "-" + strconv.Itoa(r.counts[kind])
	r.forward[key], r.reverse[p] = p, original
	return p
}

// Mask redacts one string. Quoted values (header values, identities) are
// masked only when quoteValues is set.
func (r *Redactor) Mask(s string, quoteValues bool) string {
	if quoteValues {
		s = redactQuoted.ReplaceAllStringFunc(s, func(m string) string {
			return "'" + r.name("value", m[1:len(m)-1]) + "'"
		})
	}
	return redactToken.ReplaceAllStringFunc(s, func(tok string) string {
		switch {
		case placeholder.MatchString(tok) && placeholder.FindString(tok) == tok:
			return tok
		case redactIPv4.MatchString(tok) || strings.Contains(tok, ":") && !strings.Contains(tok, " "):
			return r.name("ip", tok)
		case strings.Contains(tok, "."):
			return r.name("host", strings.ToLower(tok))
		case r.namespaces[tok]:
			return r.name("ns", tok)
		}
		return tok
	})
}

// Facts returns redacted copies of facts; IDs are preserved.
func (r *Redactor) Facts(facts []Fact) []Fact {
	out := make([]Fact, len(facts))
	for i, f := range facts {
		quoted := strings.Contains(f.Observation, "header") || strings.HasPrefix(f.Observation, "backend failed") ||
			strings.HasPrefix(f.Observation, "assert failed")
		out[i] = Fact{ID: f.ID, Subject: r.Mask(f.Subject, false), Observation: r.Mask(f.Observation, quoted)}
		if f.NextCheck != nil {
			n := r.Mask(*f.NextCheck, false)
			out[i].NextCheck = &n
		}
	}
	return out
}

// Rehydrate restores original values in text containing placeholders.
func (r *Redactor) Rehydrate(s string) string {
	return placeholder.ReplaceAllStringFunc(s, func(p string) string {
		if o, ok := r.reverse[p]; ok {
			return o
		}
		return p
	})
}

// ReportNamespaces collects namespace values from a decoded JSON report.
func ReportNamespaces(report any) []string {
	set := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, x := range t {
				if s, ok := x.(string); ok && (k == "namespace" || strings.HasSuffix(k, "_namespace")) {
					set[s] = true
				}
				walk(x)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(report)
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// LimitEvidence keeps at most n facts deterministically: failures and
// warnings first, then the remainder in report order; original order and IDs
// are preserved. n <= 0 disables the limit. It returns the number omitted.
func LimitEvidence(facts []Fact, n int) ([]Fact, int) {
	if n <= 0 || len(facts) <= n {
		return facts, 0
	}
	idx := make([]int, len(facts))
	for i := range idx {
		idx[i] = i
	}
	urgent := func(f Fact) bool {
		o := strings.ToLower(f.Observation)
		return strings.Contains(o, "failed") || strings.Contains(o, "warning") || strings.Contains(o, "unavailable") ||
			strings.Contains(o, "could not")
	}
	sort.SliceStable(idx, func(a, b int) bool { return urgent(facts[idx[a]]) && !urgent(facts[idx[b]]) })
	keep := idx[:n]
	sort.Ints(keep)
	out := make([]Fact, 0, n)
	for _, i := range keep {
		out = append(out, facts[i])
	}
	return out, len(facts) - n
}
