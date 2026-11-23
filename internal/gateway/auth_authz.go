package gateway

import (
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
)

// AuthzPolicy is the authorization step of an auth policy: after the request
// is authenticated, the rules are tried in order and the first one that
// matches decides (allow or deny). A request no rule matches gets
// DefaultAction, which is deny when it is not set. See docs/authorization.md.
type AuthzPolicy struct {
	DefaultAction string      `json:"defaultAction,omitempty"` // allow or deny (default deny)
	Rules         []AuthzRule `json:"rules"`
}

// AuthzRule is one allow or deny rule. It matches when any of its principals
// matches (no principals: any caller) and any of its operations matches (no
// operations: any request).
type AuthzRule struct {
	Name       string           `json:"name,omitempty"`
	Action     string           `json:"action"` // allow or deny
	Principals []AuthzPrincipal `json:"principals,omitempty"`
	Operations []AuthzOperation `json:"operations,omitempty"`
}

// AuthzPrincipal describes who may match. Every field that is set must match.
type AuthzPrincipal struct {
	// Claims match the verified JWT or OIDC claims (dotted names reach into objects).
	Claims []AuthzClaim `json:"claims,omitempty"`
	// Scopes: the caller has every one of them (claims scope, space separated, and scp).
	Scopes []string `json:"scopes,omitempty"`
	// APIKeys: the caller authenticated with one of these API key names.
	APIKeys []string `json:"apiKeys,omitempty"`
	// ClientCertSAN and ClientCertCN: the verified client certificate has one
	// of these SANs ("DNS:host", "URI:spiffe://...", or the bare value) or subject CNs.
	ClientCertSAN []string `json:"clientCertSan,omitempty"`
	ClientCertCN  []string `json:"clientCertCn,omitempty"`
	// CIDRs: the client address is in one of these networks.
	CIDRs []string `json:"cidrs,omitempty"`
	// Authenticated true: any authenticated caller; false: only anonymous ones
	// (a policy with no credential method).
	Authenticated *bool `json:"authenticated,omitempty"`
}

// AuthzClaim matches one claim. An array claim matches when any element
// satisfies every condition given.
type AuthzClaim struct {
	Name    string   `json:"name"`
	Exact   string   `json:"exact,omitempty"`
	Prefix  string   `json:"prefix,omitempty"`
	In      []string `json:"in,omitempty"` // the value equals one of these
	Present *bool    `json:"present,omitempty"`
}

// AuthzOperation describes what may be done. Every field that is set must match.
type AuthzOperation struct {
	Methods []string      `json:"methods,omitempty"`
	Paths   []AuthzString `json:"paths,omitempty"` // any of
	Headers []AuthzHeader `json:"headers,omitempty"`
}

// AuthzString is an exact, prefix or regular expression (RE2, whole value) match.
type AuthzString struct {
	Exact  string `json:"exact,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Regex  string `json:"regex,omitempty"`
}

// AuthzHeader matches a request header.
type AuthzHeader struct {
	Name    string `json:"name"`
	Exact   string `json:"exact,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	Regex   string `json:"regex,omitempty"`
	Present *bool  `json:"present,omitempty"`
}

// authzMatch says which rule decided; it is shown by "setura why".
type authzMatch struct {
	Rule    string // rule name, or "#N" for an unnamed rule, or "default"
	Action  string
	Default bool
}

type tri int

const (
	triNo tri = iota
	triYes
	triUnknown
)

func triAnd(a, b tri) tri {
	if a == triNo || b == triNo {
		return triNo
	}
	if a == triUnknown || b == triUnknown {
		return triUnknown
	}
	return triYes
}

type cStr struct {
	exact, prefix string
	re            *regexp.Regexp
	hasExact      bool
	hasPrefix     bool
}

func compileStr(where, exact, prefix, regex string) (*cStr, error) {
	n := 0
	for _, s := range []string{exact, prefix, regex} {
		if s != "" {
			n++
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("%s: give exactly one of exact, prefix, regex", where)
	}
	s := &cStr{exact: exact, prefix: prefix, hasExact: exact != "", hasPrefix: prefix != ""}
	if regex != "" {
		if len(regex) > 512 {
			return nil, fmt.Errorf("%s: regex is longer than 512 characters", where)
		}
		re, err := regexp.Compile(`^(?:` + regex + `)$`)
		if err != nil {
			return nil, fmt.Errorf("%s: regex: %v", where, err)
		}
		s.re = re
	}
	return s, nil
}

func (s *cStr) match(v string) bool {
	switch {
	case s.hasExact:
		return v == s.exact
	case s.hasPrefix:
		return strings.HasPrefix(v, s.prefix)
	}
	return s.re.MatchString(v)
}

type cClaim struct {
	name    string
	exact   string
	prefix  string
	in      []string
	present *bool
}

type cPrincipal struct {
	claims   []cClaim
	scopes   []string
	apiKeys  map[string]bool
	sans     []string
	cns      []string
	cidrs    []netip.Prefix
	authed   *bool
	hasKeys  bool
	hasCerts bool
}

type cHeader struct {
	name    string
	str     *cStr
	present *bool
}

type cOperation struct {
	methods map[string]bool
	paths   []*cStr
	headers []cHeader
}

type cAuthzRule struct {
	name       string
	allow      bool
	principals []cPrincipal
	operations []cOperation
}

type compiledAuthz struct {
	rules        []cAuthzRule
	defaultAllow bool
}

func compileAuthz(p *AuthzPolicy) (*compiledAuthz, error) {
	c := &compiledAuthz{}
	switch p.DefaultAction {
	case "", "deny":
	case "allow":
		c.defaultAllow = true
	default:
		return nil, fmt.Errorf("authorization.defaultAction %q: want allow or deny", p.DefaultAction)
	}
	if len(p.Rules) > 256 {
		return nil, fmt.Errorf("authorization: at most 256 rules")
	}
	for i, r := range p.Rules {
		w := fmt.Sprintf("authorization.rules[%d]", i)
		cr := cAuthzRule{name: r.Name}
		if cr.name == "" {
			cr.name = fmt.Sprintf("#%d", i+1)
		}
		switch r.Action {
		case "allow":
			cr.allow = true
		case "deny":
		default:
			return nil, fmt.Errorf("%s.action %q: want allow or deny", w, r.Action)
		}
		for j, pr := range r.Principals {
			pw := fmt.Sprintf("%s.principals[%d]", w, j)
			cp := cPrincipal{scopes: pr.Scopes, sans: pr.ClientCertSAN, cns: pr.ClientCertCN, authed: pr.Authenticated}
			for _, cl := range pr.Claims {
				if cl.Name == "" {
					return nil, fmt.Errorf("%s.claims: name is required", pw)
				}
				if cl.Exact == "" && cl.Prefix == "" && len(cl.In) == 0 && cl.Present == nil {
					return nil, fmt.Errorf("%s.claims[%s]: give exact, prefix, in or present", pw, cl.Name)
				}
				cp.claims = append(cp.claims, cClaim{cl.Name, cl.Exact, cl.Prefix, cl.In, cl.Present})
			}
			if len(pr.APIKeys) > 0 {
				cp.hasKeys = true
				cp.apiKeys = map[string]bool{}
				for _, k := range pr.APIKeys {
					cp.apiKeys[k] = true
				}
			}
			cp.hasCerts = len(pr.ClientCertSAN) > 0 || len(pr.ClientCertCN) > 0
			for _, s := range pr.CIDRs {
				pf, err := parsePrefixOrAddr(s)
				if err != nil {
					return nil, fmt.Errorf("%s.cidrs: %v", pw, err)
				}
				cp.cidrs = append(cp.cidrs, pf)
			}
			if len(cp.claims) == 0 && len(cp.scopes) == 0 && !cp.hasKeys && !cp.hasCerts && len(cp.cidrs) == 0 && cp.authed == nil {
				return nil, fmt.Errorf("%s: an empty principal; leave principals out to match any caller", pw)
			}
			cr.principals = append(cr.principals, cp)
		}
		for j, op := range r.Operations {
			ow := fmt.Sprintf("%s.operations[%d]", w, j)
			co := cOperation{}
			if len(op.Methods) > 0 {
				co.methods = map[string]bool{}
				for _, m := range op.Methods {
					co.methods[strings.ToUpper(m)] = true
				}
			}
			for _, ps := range op.Paths {
				cs, err := compileStr(ow+".paths", ps.Exact, ps.Prefix, ps.Regex)
				if err != nil {
					return nil, err
				}
				co.paths = append(co.paths, cs)
			}
			for _, h := range op.Headers {
				if h.Name == "" || strings.ContainsAny(h.Name, " :\r\n") {
					return nil, fmt.Errorf("%s.headers: bad header name %q", ow, h.Name)
				}
				ch := cHeader{name: h.Name, present: h.Present}
				if h.Exact != "" || h.Prefix != "" || h.Regex != "" {
					cs, err := compileStr(ow+".headers["+h.Name+"]", h.Exact, h.Prefix, h.Regex)
					if err != nil {
						return nil, err
					}
					ch.str = cs
				} else if h.Present == nil {
					return nil, fmt.Errorf("%s.headers[%s]: give exact, prefix, regex or present", ow, h.Name)
				}
				co.headers = append(co.headers, ch)
			}
			if len(co.methods) == 0 && len(co.paths) == 0 && len(co.headers) == 0 {
				return nil, fmt.Errorf("%s: an empty operation; leave operations out to match any request", ow)
			}
			cr.operations = append(cr.operations, co)
		}
		c.rules = append(c.rules, cr)
	}
	return c, nil
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, fmt.Errorf("%q is not a CIDR", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an address or CIDR", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// authzCaller is what the principals are matched against.
type authzCaller struct {
	claims    jwtClaims
	method    string // jwt, oidc, apikey, basic, none
	subject   string
	cert      *ClientCert
	certKnown bool
	ip        netip.Addr
}

func (p *cPrincipal) match(c authzCaller) tri {
	res := triYes
	if p.authed != nil {
		anon := c.method == "" || c.method == "none"
		if *p.authed == anon {
			return triNo
		}
	}
	for _, cl := range p.claims {
		res = triAnd(res, matchClaim(cl, c.claims))
		if res == triNo {
			return triNo
		}
	}
	if len(p.scopes) > 0 {
		have := map[string]bool{}
		for _, n := range []string{"scope", "scp"} {
			if v, ok := c.claims[n]; ok {
				for _, s := range claimStrings(v) {
					have[s] = true
				}
			}
		}
		for _, s := range p.scopes {
			if !have[s] {
				return triNo
			}
		}
	}
	if p.hasKeys && !(c.method == "apikey" && p.apiKeys[c.subject]) {
		return triNo
	}
	if p.hasCerts {
		switch {
		case !c.certKnown:
			res = triAnd(res, triUnknown)
		case c.cert == nil || !c.cert.Verified:
			return triNo
		default:
			ok := false
			for _, want := range p.sans {
				if certHasSAN(c.cert, want) {
					ok = true
				}
			}
			for _, want := range p.cns {
				if c.cert.leaf != nil && c.cert.leaf.Subject.CommonName == want {
					ok = true
				}
			}
			if !ok {
				return triNo
			}
		}
	}
	if len(p.cidrs) > 0 {
		if !c.ip.IsValid() {
			res = triAnd(res, triUnknown)
		} else {
			ok := false
			for _, pf := range p.cidrs {
				if pf.Contains(c.ip.Unmap()) {
					ok = true
				}
			}
			if !ok {
				return triNo
			}
		}
	}
	return res
}

func certHasSAN(c *ClientCert, want string) bool {
	for _, s := range strings.Split(c.SAN, ",") {
		if s == want || strings.TrimPrefix(strings.TrimPrefix(s, "DNS:"), "URI:") == want {
			return true
		}
	}
	if c.leaf != nil {
		for _, d := range c.leaf.DNSNames {
			if d == want || "DNS:"+d == want {
				return true
			}
		}
		for _, u := range c.leaf.URIs {
			if u.String() == want || "URI:"+u.String() == want {
				return true
			}
		}
	}
	return false
}

func matchClaim(cl cClaim, claims jwtClaims) tri {
	v, ok := claimAt(claims, cl.name)
	if cl.present != nil {
		if ok != *cl.present {
			return triNo
		}
		if cl.exact == "" && cl.prefix == "" && len(cl.in) == 0 {
			return triYes
		}
	}
	if !ok {
		return triNo
	}
	var vals []string
	if s, isStr := v.(string); isStr {
		vals = append(vals, s) // a whole-string value first: it may contain spaces
		if strings.Contains(s, " ") {
			vals = append(vals, strings.Fields(s)...)
		}
	} else {
		vals = claimStrings(v)
	}
	for _, s := range vals {
		if cl.exact != "" && s != cl.exact {
			continue
		}
		if cl.prefix != "" && !strings.HasPrefix(s, cl.prefix) {
			continue
		}
		if len(cl.in) > 0 {
			found := false
			for _, w := range cl.in {
				if s == w {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		return triYes
	}
	return triNo
}

func (o *cOperation) match(r *http.Request) bool {
	if len(o.methods) > 0 && !o.methods[strings.ToUpper(r.Method)] {
		return false
	}
	if len(o.paths) > 0 {
		ok := false
		for _, p := range o.paths {
			if p.match(r.URL.Path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for _, h := range o.headers {
		vals := r.Header.Values(h.name)
		if h.present != nil && (len(vals) > 0) != *h.present {
			return false
		}
		if h.str != nil {
			ok := false
			for _, v := range vals {
				if h.str.match(v) {
					ok = true
				}
			}
			if !ok {
				return false
			}
		}
	}
	return true
}

// decide returns the first matching rule's action. unknown is true when the
// outcome depends on something an offline evaluation cannot see.
func (c *compiledAuthz) decide(r *http.Request, caller authzCaller) (m authzMatch, unknown bool) {
	for i := range c.rules {
		rule := &c.rules[i]
		pm := triYes
		if len(rule.principals) > 0 {
			pm = triNo
			for j := range rule.principals {
				switch rule.principals[j].match(caller) {
				case triYes:
					pm = triYes
				case triUnknown:
					if pm == triNo {
						pm = triUnknown
					}
				}
				if pm == triYes {
					break
				}
			}
		}
		if pm == triNo {
			continue
		}
		om := true
		if len(rule.operations) > 0 {
			om = false
			for j := range rule.operations {
				if rule.operations[j].match(r) {
					om = true
					break
				}
			}
		}
		if !om {
			continue
		}
		if pm == triUnknown {
			return authzMatch{Rule: rule.name}, true
		}
		act := "deny"
		if rule.allow {
			act = "allow"
		}
		return authzMatch{Rule: rule.name, Action: act}, false
	}
	act := "deny"
	if c.defaultAllow {
		act = "allow"
	}
	return authzMatch{Rule: "default", Action: act, Default: true}, false
}
