package gateway

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// rulePolicy summarises what a rule does besides choosing a backend, in a
// form that compares equal exactly when the data path behaves the same:
// retries, the request timeout and the mirrors with their shadow-diff.
func rulePolicy(rule *CRule) (retry, timeout string, mirrors []string) {
	if c := rule.Retry; c != nil {
		codes := make([]int, 0, len(c.Codes))
		for code := range c.Codes {
			codes = append(codes, code)
		}
		sort.Ints(codes)
		cs := make([]string, len(codes))
		for i, code := range codes {
			cs[i] = fmt.Sprint(code)
		}
		retry = fmt.Sprintf("%d retries, %s backoff, codes [%s]", c.Attempts, c.Backoff, strings.Join(cs, " "))
	}
	timeout = durLabel(rule.Timeout)
	for _, m := range rule.Mirrors {
		s := fmt.Sprintf("%s %d%%", m.B.Key, m.Percent)
		if on, sample := m.Shadow.effective(0); on {
			s += fmt.Sprintf(" shadow-diff %d%%", sample)
		}
		mirrors = append(mirrors, s)
	}
	sort.Strings(mirrors)
	return
}

// resolveTLS decides, for a TLS passthrough connection with this server
// name, what the data path would do: pick the most specific TLSRoute hostname
// and a weighted backend. Nothing inside the connection is inspected.
func (t *Table) resolveTLS(spec ReqSpec) Decision {
	d := Decision{Outcome: OutcomeNoListener, Status: http.StatusNotFound, Kind: "tls"}
	host := strings.ToLower(strings.TrimSuffix(spec.SNI, "."))
	var ports []int
	if spec.Port != 0 {
		ports = []int{spec.Port}
	} else {
		for p, g := range t.Ports {
			if g.Passthrough {
				ports = append(ports, p)
			}
		}
		sort.Ints(ports)
	}
	var l *RTListener
	for _, p := range ports {
		if g := t.Ports[p]; g != nil && g.Passthrough {
			if l = g.pickListener(host); l != nil {
				break
			}
		}
	}
	if l == nil {
		return d
	}
	d.Listener, d.Outcome = l.Key, OutcomeNoRoute
	e := l.selectTLS(host)
	if e == nil {
		return d
	}
	d.Route, d.Rule = e.RouteKey, 0
	d.Status, d.Outcome = http.StatusInternalServerError, OutcomeNoBackend
	total, valid := 0, 0
	agg := map[string]int{}
	for _, c := range e.Refs {
		total += c.Weight
		if c.B != nil {
			valid += c.Weight
		}
		if c.Weight > 0 {
			k := NoBackendKey
			if c.B != nil {
				k = c.B.Key
			}
			agg[k] += c.Weight
		}
	}
	if total <= 0 {
		return d
	}
	for _, k := range sortedKeys(agg) {
		d.Backends = append(d.Backends, WeightedBackend{Key: k, Weight: agg[k], Percent: float64(agg[k]) * 100 / float64(total)})
	}
	if valid > 0 {
		d.Outcome, d.Status = OutcomeRouted, http.StatusOK
	}
	return d
}
