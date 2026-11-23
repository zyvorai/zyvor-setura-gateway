package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AuthKey is the extension field of a rule, and the route annotation
// (setura.zyvor.dev/auth, setura.zyvor.dev/auth.rule-N), that turn on
// traffic security for it. See docs/security.md.
const AuthKey = "setura.zyvor.dev/auth"

// Header prefixes the gateway owns. Whatever a client sends under them is
// removed on every request, then the verified values are set.
const (
	authHeaderPrefix   = "X-Setura-Auth-"
	clientHeaderPrefix = "X-Setura-Client-"
)

// AuthPolicy is the traffic-security policy of one rule. The checks run in
// this order and the first failure answers the request: the client address
// lists (403), the client certificate requirement (403), then the
// credentials (401 or 403). Of jwt, apiKey and basic one valid credential is
// enough; with none configured only the first two checks apply.
type AuthPolicy struct {
	// Enabled false switches the policy off for the rule without deleting it.
	Enabled           *bool         `json:"enabled,omitempty"`
	JWT               *JWTPolicy    `json:"jwt,omitempty"`
	APIKey            *APIKeyPolicy `json:"apiKey,omitempty"`
	Basic             *BasicPolicy  `json:"basic,omitempty"`
	IPAllow           []string      `json:"ipAllow,omitempty"`
	IPDeny            []string      `json:"ipDeny,omitempty"`
	RequireClientCert bool          `json:"requireClientCert,omitempty"`
	// Realm names the protection space in WWW-Authenticate (default "setura").
	Realm string `json:"realm,omitempty"`

	annErr error
	c      *compiledAuth
}

// MarshalJSON writes the policy with every secret replaced: key and password
// hashes and clear text, and the JWKS URL's credentials. /config and any other
// dump goes through it.
func (p *AuthPolicy) MarshalJSON() ([]byte, error) {
	type plain AuthPolicy
	cp := plain(*p)
	if p.JWT != nil {
		j := *p.JWT
		if j.JWKSURI != "" {
			j.JWKSURI = redactURL(j.JWKSURI)
		}
		cp.JWT = &j
	}
	if p.APIKey != nil {
		a := *p.APIKey
		a.Keys = make([]APIKeyDef, len(p.APIKey.Keys))
		for i, k := range p.APIKey.Keys {
			a.Keys[i] = APIKeyDef{Name: k.Name}
			if k.Hash != "" {
				a.Keys[i].Hash = redacted
			}
			if k.Key != "" {
				a.Keys[i].Key = redacted
			}
		}
		cp.APIKey = &a
	}
	if p.Basic != nil {
		b := *p.Basic
		b.Users = make([]BasicUser, len(p.Basic.Users))
		for i, u := range p.Basic.Users {
			b.Users[i] = BasicUser{Name: u.Name}
			if u.Hash != "" {
				b.Users[i].Hash = redacted
			}
			if u.Password != "" {
				b.Users[i].Password = redacted
			}
		}
		cp.Basic = &b
	}
	return json.Marshal(cp)
}

// ParseAuthBlock decodes an auth policy strictly (unknown fields are errors)
// and validates it the way the gateway does when it compiles the route.
func ParseAuthBlock(raw []byte) (*AuthPolicy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p AuthPolicy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", AuthKey, err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", AuthKey)
	}
	c, err := compileAuthPolicy(&p)
	if err != nil {
		return nil, err
	}
	p.c = c
	return &p, nil
}

// AuthRuleAnnotation targets rule n (1-based): setura.zyvor.dev/auth.rule-N.
func AuthRuleAnnotation(n int) string { return AuthKey + ".rule-" + strconv.Itoa(n) }

// annotateAuth gives every rule that has no policy of its own the policy of
// its annotation: the rule specific one wins over the route wide one. A value
// that cannot be decoded becomes a policy that fails compilation, so the route
// turns invalid instead of silently serving without protection.
func annotateAuth(rules []Rule, ann map[string]string) {
	annotateAuthSlots(len(rules), func(i int) **AuthPolicy { return &rules[i].Auth }, ann)
}

// annotateAuthGRPC is annotateAuth for the rules of a GRPCRoute.
func annotateAuthGRPC(rules []GRPCRule, ann map[string]string) {
	annotateAuthSlots(len(rules), func(i int) **AuthPolicy { return &rules[i].Auth }, ann)
}

func annotateAuthSlots(n int, slot func(i int) **AuthPolicy, ann map[string]string) {
	if len(ann) == 0 {
		return
	}
	for i := 0; i < n; i++ {
		sp := slot(i)
		if *sp != nil {
			continue
		}
		key := AuthRuleAnnotation(i + 1)
		v, ok := ann[key]
		if !ok {
			key = AuthKey
			v, ok = ann[key]
		}
		if !ok {
			continue
		}
		p, err := ParseAuthBlock([]byte(v))
		if err != nil {
			p = &AuthPolicy{annErr: fmt.Errorf("annotation %s: %w", key, err)}
		}
		*sp = p
	}
}

// OrphanAuthAnnotations lists auth annotation keys that no rule uses.
func OrphanAuthAnnotations(ann map[string]string, rules int) []string {
	var out []string
	for k := range ann {
		if k == AuthKey || !strings.HasPrefix(k, AuthKey) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(k, AuthKey+".rule-"))
		if !strings.HasPrefix(k, AuthKey+".rule-") || err != nil || n < 1 || n > rules {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ---- compiled policy ----

type compiledAuth struct {
	enabled     bool
	realm       string
	acl         *ipACL
	requireCert bool
	jwt         *jwtVerifier
	apikey      *apiKeyVerifier
	basic       *basicVerifier
	ownHeaders  []string // headers the policy sets from claims, removed from the client's request
}

// compileAuth compiles the policy of a rule (a nil policy compiles to nothing).
// It is called once per rule when the routing table is built.
func compileAuth(p *AuthPolicy) error {
	if p == nil || p.c != nil {
		return nil
	}
	if p.annErr != nil {
		return p.annErr
	}
	c, err := compileAuthPolicy(p)
	if err != nil {
		return fmt.Errorf("%s: %w", AuthKey, err)
	}
	p.c = c
	return nil
}

func compileAuthPolicy(p *AuthPolicy) (*compiledAuth, error) {
	c := &compiledAuth{enabled: p.Enabled == nil || *p.Enabled, realm: p.Realm, requireCert: p.RequireClientCert}
	if c.realm == "" {
		c.realm = "setura"
	}
	var err error
	if c.acl, err = compileIPACL(p.IPAllow, p.IPDeny); err != nil {
		return nil, err
	}
	if p.JWT != nil {
		if c.jwt, err = compileJWT(p.JWT); err != nil {
			return nil, err
		}
		c.ownHeaders = append(c.ownHeaders, c.jwt.claimHd...)
	}
	if p.APIKey != nil {
		if c.apikey, err = compileAPIKey(p.APIKey); err != nil {
			return nil, err
		}
	}
	if p.Basic != nil {
		if c.basic, err = compileBasic(p.Basic); err != nil {
			return nil, err
		}
		if c.basic.realm == "setura" && p.Realm != "" {
			c.basic.realm = p.Realm
		}
	}
	return c, nil
}

// authInput is what a decision needs. The data path and the explainer both
// build one.
type authInput struct {
	r        *http.Request
	clientIP netip.Addr // invalid when unknown (the explainer without --client-ip)
	cert     *ClientCert
	// certKnown is false when the TLS handshake cannot be observed (explainer).
	certKnown bool
	now       time.Time
	offline   bool // never fetch a JWKS (explainer)
}

// authResult is the outcome of a policy for one request.
type authResult struct {
	Decision   string // allow, deny or unknown
	Status     int    // HTTP status when Decision is deny
	Method     string // credential that passed: jwt, apikey, basic, or "" / none
	Subject    string
	Reason     string // safe to log and to show: never contains a credential
	Challenges []string
	headers    map[string]string
	strip      func(*http.Request)
	claims     jwtClaims // verified JWT claims, for plan and tenant lookup
}

func (a authResult) allowed() bool { return a.Decision == "allow" }

// evaluate runs the policy. It does not modify the request.
func (c *compiledAuth) evaluate(in authInput) authResult {
	if c == nil || !c.enabled {
		return authResult{Decision: "allow", Method: "none", Reason: "no auth policy applies"}
	}
	var unknown []string
	if c.acl != nil {
		if in.clientIP.IsValid() {
			if why := c.acl.check(in.clientIP); why != "" {
				return authResult{Decision: "deny", Status: http.StatusForbidden, Reason: why}
			}
		} else {
			unknown = append(unknown, "the client address lists need a client address (give --client-ip)")
		}
	}
	if c.requireCert {
		switch {
		case !in.certKnown:
			unknown = append(unknown, "the route requires a verified client certificate, which is checked in the TLS handshake and cannot be simulated")
		case in.cert == nil || !in.cert.Verified:
			return authResult{Decision: "deny", Status: http.StatusForbidden, Reason: "a verified client certificate is required"}
		}
	}
	res := authResult{Decision: "allow", Method: "none", Reason: "no credential check is configured; the address and certificate checks passed"}
	if in.cert != nil && in.cert.Verified {
		res.Subject = in.cert.Subject
	}
	if c.jwt != nil || c.apikey != nil || c.basic != nil {
		res = c.credentials(in)
	}
	if len(unknown) > 0 && res.allowed() {
		res.Decision = "unknown"
		res.Reason = strings.Join(unknown, "; ")
	}
	return res
}

func (c *compiledAuth) credentials(in authInput) authResult {
	r := in.r
	var challenges []string
	var failures []string
	forbid := (*jwtError)(nil)
	offline := false
	if c.jwt != nil {
		ch := `Bearer realm=` + strconv.Quote(c.realm)
		if tok := bearerToken(r); tok != "" {
			claims, je := c.jwt.verify(tok, in.now, in.offline)
			switch {
			case je == nil:
				res := authResult{Decision: "allow", Method: "jwt", Reason: "JWT verified", headers: map[string]string{}, strip: c.jwt.strip, claims: claims}
				if sub, ok := claims["sub"].(string); ok {
					res.Subject = sub
				}
				for _, h := range sortedKeys(c.jwt.p.ClaimHeaders) {
					if v, ok := claimAt(claims, c.jwt.p.ClaimHeaders[h]); ok {
						if s := claimHeaderValue(v); s != "" {
							res.headers[h] = s
						}
					}
				}
				return res
			case je.code == "offline":
				offline = true
			case je.code == "":
				return authResult{Decision: "deny", Status: je.status, Reason: je.desc}
			case je.status == http.StatusForbidden:
				forbid = je
				failures = append(failures, "jwt: "+je.desc)
				ch += `, error="insufficient_scope", error_description=` + strconv.Quote(je.desc)
			default:
				failures = append(failures, "jwt: "+je.desc)
				ch += `, error="invalid_token", error_description=` + strconv.Quote(je.desc)
			}
		} else {
			failures = append(failures, "jwt: no bearer token")
		}
		challenges = append(challenges, ch)
	}
	if c.apikey != nil {
		if k := c.apikey.extract(r); k != "" {
			if name, ok := c.apikey.check(k); ok {
				return authResult{Decision: "allow", Method: "apikey", Subject: name, Reason: "API key accepted", strip: c.apikey.strip}
			}
			failures = append(failures, "apiKey: key not recognised")
		} else {
			failures = append(failures, "apiKey: no key supplied")
		}
		challenges = append(challenges, `ApiKey realm=`+strconv.Quote(c.realm))
	}
	if c.basic != nil {
		user, pw, ok := r.BasicAuth()
		if ok {
			if c.basic.check(user, pw, in.now) {
				return authResult{Decision: "allow", Method: "basic", Subject: user, Reason: "basic credentials accepted", strip: func(r *http.Request) {
					if !c.basic.forward {
						r.Header.Del("Authorization")
					}
				}}
			}
			failures = append(failures, "basic: user or password not recognised")
		} else {
			failures = append(failures, "basic: no credentials supplied")
		}
		challenges = append(challenges, c.basic.challenge())
	}
	if offline {
		return authResult{Decision: "unknown", Reason: "jwt: " + errOfflineJWKS.Error() + "; the token cannot be verified offline (point --admin at a running gateway)"}
	}
	res := authResult{Decision: "deny", Status: http.StatusUnauthorized, Challenges: challenges, Reason: strings.Join(failures, "; ")}
	if forbid != nil {
		res.Status = http.StatusForbidden
	}
	return res
}

// stripIdentity removes every header the gateway reserves for the identity it
// verified itself, plus extra (the claim headers of the route's policy), so a
// client cannot present an identity of its own choosing.
func stripIdentity(h http.Header, extra []string) {
	for k := range h {
		if len(k) >= len(authHeaderPrefix) && strings.EqualFold(k[:len(authHeaderPrefix)], authHeaderPrefix) ||
			len(k) >= len(clientHeaderPrefix) && strings.EqualFold(k[:len(clientHeaderPrefix)], clientHeaderPrefix) {
			delete(h, k)
		}
	}
	h.Del(XFCCHeader)
	for _, k := range extra {
		h.Del(k)
	}
}

// apply puts the verified identity on the request that goes upstream: the
// reserved headers, the claim headers, and the credential removal.
func (res authResult) apply(r *http.Request) {
	if res.Method != "" && res.Method != "none" {
		r.Header.Set(authHeaderPrefix+"Method", res.Method)
	}
	if res.Subject != "" {
		r.Header.Set(authHeaderPrefix+"Subject", strings.Map(func(c rune) rune {
			if c < 0x20 || c == 0x7f {
				return -1
			}
			return c
		}, res.Subject))
	}
	for h, v := range res.headers {
		r.Header.Set(h, v)
	}
	if res.strip != nil {
		res.strip(r)
	}
}

// prepareIdentity is the single place a request's identity headers are
// prepared, shared by the data path and the explainer: strip what the client
// sent, then set the verified client certificate headers.
func prepareIdentity(r *http.Request, rule *Rule, cert *ClientCert) {
	var extra []string
	if rule != nil && rule.Auth != nil && rule.Auth.c != nil {
		extra = rule.Auth.c.ownHeaders
	}
	stripIdentity(r.Header, extra)
	cert.setHeaders(r.Header)
}

// authDenied runs the rule's policy for an HTTP request and answers it when
// it fails. On success the identity headers are in place on r.
func (s *Server) authDenied(w http.ResponseWriter, r *http.Request, st *reqState, l *RTListener, rule *Rule) bool {
	return s.authCheck(r, st, l, rule, func(status int, challenges []string, certDeny bool) {
		if certDeny {
			plain(w, http.StatusMisdirectedRequest, "client certificate validation is required for this host")
			return
		}
		for _, ch := range challenges {
			w.Header().Add("WWW-Authenticate", ch)
		}
		if status == http.StatusUnauthorized {
			plain(w, status, "unauthorized")
		} else {
			plain(w, status, "forbidden")
		}
	})
}

// authCheck is the protocol independent part of authDenied: it prepares the
// identity headers, evaluates the policy, counts the outcome and calls reject
// with the HTTP-equivalent status (the gRPC path maps it to a gRPC status).
func (s *Server) authCheck(r *http.Request, st *reqState, l *RTListener, rule *Rule, reject func(status int, challenges []string, certDeny bool)) bool {
	cert, deny := s.clientCertFor(l, r)
	if deny != "" {
		s.ext.authOutcome(st.route, "denied", "client_cert")
		st.errMsg = deny
		reject(http.StatusMisdirectedRequest, nil, true)
		return true
	}
	prepareIdentity(r, rule, cert)
	var c *compiledAuth
	if rule != nil && rule.Auth != nil {
		c = rule.Auth.c
	}
	if c == nil || !c.enabled {
		return false
	}
	ip, _ := netip.ParseAddr(s.trusted.clientIP(r))
	res := c.evaluate(authInput{r: r, clientIP: ip, cert: cert, certKnown: true, now: s.authNow()})
	if res.allowed() {
		s.ext.authOutcome(st.route, "allowed", "")
		res.apply(r)
		st.auth = &res
		return false
	}
	reason := "forbidden"
	if res.Status == http.StatusUnauthorized {
		reason = "unauthenticated"
	}
	s.ext.authOutcome(st.route, "denied", reason)
	st.errMsg = "auth: " + res.Reason
	reject(res.Status, res.Challenges, false)
	return true
}

func (s *Server) authNow() time.Time {
	if s.opts.AuthClock != nil {
		return s.opts.AuthClock()
	}
	return time.Now()
}

// postApply runs after a table is swapped in: OCSP tracking of the listener
// certificates and the list of query parameters that carry credentials.
func (s *Server) postApply(t *Table) {
	s.ocspSync(t)
	s.acmeSync(t)
	s.proxySync(t)
	var names []string
	for _, r := range t.Cfg.Routes {
		for _, rule := range r.Rules {
			if rule.Auth != nil && rule.Auth.APIKey != nil && rule.Auth.APIKey.Query != "" {
				names = append(names, rule.Auth.APIKey.Query)
			}
		}
	}
	s.authQ.Store(&names)
}
