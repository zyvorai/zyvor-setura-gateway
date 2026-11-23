package gateway

import (
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// TraceAuth is the traffic-security decision for the request: which policy
// applies and whether the credentials supplied with --header would pass it.
// It is computed by the same evaluate the data path runs.
type TraceAuth struct {
	Applies   bool     `json:"applies"`
	Policy    string   `json:"policy,omitempty"`
	Decision  string   `json:"decision"` // allow, deny or unknown
	Status    int      `json:"status,omitempty"`
	Method    string   `json:"method,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Reason    string   `json:"reason,omitempty"`
	Challenge []string `json:"www_authenticate,omitempty"`
	// Headers are the identity headers the backend would receive.
	Headers []string `json:"upstream_headers,omitempty"`
	Note    string   `json:"note,omitempty"`
}

// describe summarises a policy without any secret in it.
func (p *AuthPolicy) describe() string {
	var parts []string
	if p.JWT != nil {
		d := "jwt"
		if p.JWT.Issuer != "" {
			d += " issuer " + p.JWT.Issuer
		}
		if len(p.JWT.Audience) > 0 {
			d += " audience " + strings.Join(p.JWT.Audience, "|")
		} else {
			d += " (no audience check)"
		}
		if p.JWT.JWKSURI != "" {
			d += " keys from " + redactURL(p.JWT.JWKSURI)
		} else {
			d += " inline keys"
		}
		parts = append(parts, d)
	}
	if p.APIKey != nil {
		where := p.APIKey.Header
		if where == "" && p.APIKey.Query == "" {
			where = "X-API-Key"
		}
		if p.APIKey.Query != "" {
			if where != "" {
				where += " or "
			}
			where += "query " + p.APIKey.Query
		}
		parts = append(parts, fmt.Sprintf("api key in %s (%d keys)", where, len(p.APIKey.Keys)))
	}
	if p.Basic != nil {
		parts = append(parts, fmt.Sprintf("basic auth (%d users)", len(p.Basic.Users)))
	}
	if n := len(p.IPAllow); n > 0 {
		parts = append(parts, fmt.Sprintf("ip allow list (%d)", n))
	}
	if n := len(p.IPDeny); n > 0 {
		parts = append(parts, fmt.Sprintf("ip deny list (%d)", n))
	}
	if p.RequireClientCert {
		parts = append(parts, "verified client certificate")
	}
	if len(parts) == 0 {
		return "empty policy"
	}
	return strings.Join(parts, "; ")
}

// credentialNames are the header and query names a policy reads credentials
// from, for redaction.
func (p *AuthPolicy) credentialNames() (headers, query []string) {
	if p.APIKey != nil {
		if p.APIKey.Header != "" {
			headers = append(headers, p.APIKey.Header)
		} else if p.APIKey.Query == "" {
			headers = append(headers, "X-API-Key")
		}
		if p.APIKey.Query != "" {
			query = append(query, p.APIKey.Query)
		}
	}
	return
}

// explainAuth applies the same identity preparation and the same evaluate as
// the data path, so the upstream request shown has the identity headers a
// backend would see. The TLS handshake cannot be simulated: a policy that
// needs a client certificate answers "unknown".
func (tr *Trace) explainAuth(w *TraceWinner, e *Entry, q ExplainRequest, r *http.Request) {
	var rule *Rule
	if !e.GRPC {
		rule = e.Rule.Rule
	}
	prepareIdentity(r, rule, nil)
	if rule == nil || rule.Auth == nil || rule.Auth.c == nil {
		w.Auth = &TraceAuth{Decision: "allow", Reason: "no auth policy applies to this rule"}
		return
	}
	p := rule.Auth
	h, qs := p.credentialNames()
	tr.credHeaders, tr.credQuery = h, qs
	ta := &TraceAuth{Applies: true, Policy: p.describe()}
	w.Auth = ta
	if !p.c.enabled {
		ta.Applies, ta.Decision, ta.Reason = false, "allow", "the policy is switched off (enabled: false)"
		return
	}
	now := q.Now
	if q.Server.AuthClock != nil {
		now = q.Server.AuthClock()
	}
	if now.IsZero() {
		now = time.Now()
	}
	ip, _ := netip.ParseAddr(q.Remote)
	res := p.c.evaluate(authInput{r: r, clientIP: ip, now: now, offline: !q.Live})
	tr.authRes = &res
	ta.Decision, ta.Status, ta.Method, ta.Subject, ta.Reason, ta.Challenge = res.Decision, res.Status, res.Method, res.Subject, res.Reason, res.Challenges
	switch res.Decision {
	case "allow":
		res.apply(r)
		for k := range r.Header {
			if len(k) > len(authHeaderPrefix) && strings.HasPrefix(k, authHeaderPrefix) {
				ta.Headers = append(ta.Headers, k)
			}
		}
		for hname := range res.headers {
			ta.Headers = append(ta.Headers, http.CanonicalHeaderKey(hname))
		}
		sort.Strings(ta.Headers)
		ta.Note = "the request is admitted and the headers above are set for the backend"
	case "deny":
		ta.Note = fmt.Sprintf("the gateway answers %d and the request never reaches a backend", res.Status)
	default:
		ta.Note = "the outcome depends on what this offline view cannot see"
	}
}

// redactRequest hides credentials in the echoed request. It runs when Explain
// returns, after every stage that needed the real values.
func (tr *Trace) redactRequest() {
	tr.Request.Header = redactedHeaders(tr.Request.Header, tr.credHeaders...)
	tr.Request.RawQuery = redactQuery(tr.Request.RawQuery, tr.credQuery...)
	if tr.Winner == nil {
		return
	}
	for i := range tr.Winner.Backends {
		up := tr.Winner.Backends[i].Request
		if up == nil {
			continue
		}
		if base, q, ok := strings.Cut(up.URL, "?"); ok {
			up.URL = base + "?" + redactQuery(q, tr.credQuery...)
		}
		for k, v := range up.Headers {
			for _, h := range tr.credHeaders {
				if strings.EqualFold(h, k) && v != "" {
					up.Headers[k] = redacted
				}
			}
		}
	}
}
