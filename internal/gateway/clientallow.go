package gateway

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Client certificate authorisation beyond CA trust: an allow-list of
// subject alternative names and subject common names, checked after the chain
// verified. A certificate from a trusted CA that matches nothing in the list
// is refused (Envoy: match_typed_subject_alt_names).

// ClientAllowKey is the Gateway annotation (and the frontend validation
// field) that carries the allow-list as a JSON object.
const ClientAllowKey = "setura.zyvor.dev/client-allow"

// ClientAllow is the allow-list. A certificate is accepted when it matches any
// SAN entry or any CN entry; an empty list allows every trusted certificate.
type ClientAllow struct {
	// SAN entries are exact names or "*.suffix" wildcards, matched
	// case-insensitively against the DNS, URI and email SANs of the leaf. A
	// "dns:", "uri:" or "email:" prefix restricts the entry to that type.
	SAN []string `json:"san,omitempty"`
	// CN entries are exact or "*.suffix" patterns for the subject common name.
	CN []string `json:"cn,omitempty"`
}

func (a *ClientAllow) empty() bool { return a == nil || len(a.SAN)+len(a.CN) == 0 }

// ParseClientAllow decodes the annotation value strictly.
func ParseClientAllow(raw []byte) (*ClientAllow, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var a ClientAllow
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%s: %w", ClientAllowKey, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", ClientAllowKey)
	}
	if _, err := a.compile(); err != nil {
		return nil, err
	}
	return &a, nil
}

// ParseClientAllowFlags builds the allow-list of --client-allow-san and
// --client-allow-cn (comma separated and repeatable).
func ParseClientAllowFlags(san, cn []string) (*ClientAllow, error) {
	a := &ClientAllow{}
	for _, v := range san {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				a.SAN = append(a.SAN, p)
			}
		}
	}
	for _, v := range cn {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				a.CN = append(a.CN, p)
			}
		}
	}
	if a.empty() {
		return nil, nil
	}
	if _, err := a.compile(); err != nil {
		return nil, err
	}
	return a, nil
}

type nameMatch struct {
	kind   string // "", dns, uri or email
	exact  string // lower case
	suffix string // lower case, with the leading dot; set for "*.suffix"
}

func (m nameMatch) match(v string) bool {
	v = strings.ToLower(v)
	if m.suffix != "" {
		return len(v) > len(m.suffix) && strings.HasSuffix(v, m.suffix)
	}
	return v == m.exact
}

func compileName(s, what string) (nameMatch, error) {
	var m nameMatch
	pat := strings.TrimSpace(s)
	if what == "san" {
		for _, k := range []string{"dns", "uri", "email"} {
			if len(pat) > len(k)+1 && strings.EqualFold(pat[:len(k)+1], k+":") {
				m.kind, pat = k, pat[len(k)+1:]
				break
			}
		}
	}
	if pat == "" {
		return m, fmt.Errorf("%s: empty %s entry", ClientAllowKey, what)
	}
	if strings.Contains(strings.TrimPrefix(pat, "*."), "*") || strings.HasPrefix(pat, "*") && !strings.HasPrefix(pat, "*.") {
		return m, fmt.Errorf("%s: %s entry %q: only a leading \"*.\" wildcard is supported", ClientAllowKey, what, s)
	}
	if suf, ok := strings.CutPrefix(pat, "*."); ok {
		if suf == "" {
			return m, fmt.Errorf("%s: %s entry %q: nothing after \"*.\"", ClientAllowKey, what, s)
		}
		m.suffix = "." + strings.ToLower(suf)
	} else {
		m.exact = strings.ToLower(pat)
	}
	return m, nil
}

// compiledAllow is a ClientAllow ready to match.
type compiledAllow struct {
	san, cn []nameMatch
	desc    string
}

func (a *ClientAllow) compile() (*compiledAllow, error) {
	if a.empty() {
		return nil, nil
	}
	c := &compiledAllow{desc: fmt.Sprintf("san %v cn %v", a.SAN, a.CN)}
	for _, s := range a.SAN {
		m, err := compileName(s, "san")
		if err != nil {
			return nil, err
		}
		c.san = append(c.san, m)
	}
	for _, s := range a.CN {
		m, err := compileName(s, "cn")
		if err != nil {
			return nil, err
		}
		c.cn = append(c.cn, m)
	}
	return c, nil
}

// allows reports whether the leaf matches the list.
func (c *compiledAllow) allows(leaf *x509.Certificate) bool {
	if c == nil {
		return true
	}
	each := func(kind string, vals []string) bool {
		for _, v := range vals {
			for _, m := range c.san {
				if (m.kind == "" || m.kind == kind) && m.match(v) {
					return true
				}
			}
		}
		return false
	}
	if each("dns", leaf.DNSNames) || each("email", leaf.EmailAddresses) {
		return true
	}
	for _, u := range leaf.URIs {
		if each("uri", []string{u.String()}) {
			return true
		}
	}
	if cn := leaf.Subject.CommonName; cn != "" {
		for _, m := range c.cn {
			if m.match(cn) {
				return true
			}
		}
	}
	return false
}

// resolveClientAllow picks the allow-list of a frontend validation: its own
// field, else the Gateway annotation. nil means none (the --client-allow-*
// flags then apply at run time).
func resolveClientAllow(v *FrontendValidation, gw *Gateway) (*compiledAllow, error) {
	a := v.Allow
	if a == nil {
		raw, ok := gw.Annotations[ClientAllowKey]
		if !ok {
			return nil, nil
		}
		var err error
		if a, err = ParseClientAllow([]byte(raw)); err != nil {
			return nil, fmt.Errorf("Gateway annotation %w", err)
		}
	}
	return a.compile()
}

// rejectClientCert counts and logs a client certificate the allow-list refused.
func (s *Server) rejectClientCert(listener string, leaf *x509.Certificate) {
	s.ext.bump(&s.ext.cert, listener)
	s.diag("client certificate refused on listener %s: subject %q is not on the allow-list (SAN %s)", listener, leaf.Subject.String(), sanList(leaf))
}
