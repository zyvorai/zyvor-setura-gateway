package gateway

import (
	"encoding/json"
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

// ruleExtras describes the rewrite, the other filters and the auth policy of
// the rule that serves a request, in a form that compares equal exactly when
// the data path behaves the same.
func ruleExtras(rule *CRule, r *http.Request, m *CMatch) (rewrite string, filters []string, auth string) {
	var rw []string
	scan := func(scope string, fs []Filter) {
		for _, f := range fs {
			switch f.Type {
			case "URLRewrite":
				if f.URLRewrite == nil {
					continue
				}
				var p []string
				if h := f.URLRewrite.Hostname; h != "" {
					p = append(p, "host "+h)
				}
				if pm := f.URLRewrite.Path; pm != nil {
					p = append(p, fmt.Sprintf("path %s -> %s", r.URL.Path, rewritePath(r.URL.Path, pm, m)))
				}
				rw = append(rw, scope+strings.Join(p, ", "))
			case "RequestHeaderModifier", "ResponseHeaderModifier", "CORS", "ExternalAuth":
				var v any
				switch f.Type {
				case "RequestHeaderModifier":
					v = f.RequestHeaderModifier
				case "ResponseHeaderModifier":
					v = f.ResponseHeaderModifier
				case "CORS":
					v = f.CORS
				default:
					v = f.ExternalAuth
				}
				b, _ := json.Marshal(v)
				if len(b) > 200 {
					b = append(b[:200], "..."...)
				}
				filters = append(filters, scope+f.Type+" "+string(b))
			}
		}
	}
	scan("", rule.Rule.Filters)
	for _, ref := range rule.Refs {
		scan("backendRef "+ref.Name+": ", ref.Filters)
	}
	sort.Strings(rw)
	sort.Strings(filters)
	rewrite = strings.Join(rw, "; ")
	var kinds []string
	if p := rule.Rule.Auth; p != nil && (p.Enabled == nil || *p.Enabled) {
		if p.JWT != nil {
			kinds = append(kinds, "jwt")
		}
		if p.OIDC != nil {
			kinds = append(kinds, "oidc")
		}
		if p.APIKey != nil {
			kinds = append(kinds, "apiKey")
		}
		if p.Basic != nil {
			kinds = append(kinds, "basic")
		}
		if len(p.IPAllow) > 0 {
			kinds = append(kinds, "ipAllow")
		}
		if len(p.IPDeny) > 0 {
			kinds = append(kinds, "ipDeny")
		}
		if p.RequireClientCert {
			kinds = append(kinds, "clientCert")
		}
		if p.Authorization != nil {
			kinds = append(kinds, "authorization")
		}
		if p.CSRF != nil {
			kinds = append(kinds, "csrf")
		}
		if len(p.Inject) > 0 {
			kinds = append(kinds, "inject")
		}
	}
	for _, f := range rule.Rule.Filters {
		if f.Type == "ExternalAuth" {
			kinds = append(kinds, "externalAuth")
			break
		}
	}
	return rewrite, filters, strings.Join(kinds, ",")
}
