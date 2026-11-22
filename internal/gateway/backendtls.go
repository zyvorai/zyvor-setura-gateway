package gateway

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// BackendTLSPolicy (gateway.networking.k8s.io/v1) makes the gateway speak TLS
// to a Service: it verifies the backend against a CA bundle, sends the policy
// hostname as SNI, optionally checks Subject Alternative Names and, when the
// Gateway declares spec.tls.backend.clientCertificateRef, presents a client
// certificate (mTLS). The same resolution backs file/snapshot mode and the
// Kubernetes source; status goes on the policy's ancestors (the Gateways whose
// routes use the targeted Service).

const backendTLSPolicyKey = "backendtlspolicies." + APIGroup

// PolicyTarget is one targetRef of a BackendTLSPolicy.
type PolicyTarget struct {
	Group       string `json:"group,omitempty"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	SectionName string `json:"sectionName,omitempty"`
}

// BackendSAN is one subjectAltNames entry.
type BackendSAN struct {
	Type     string `json:"type"`
	Hostname string `json:"hostname,omitempty"`
	URI      string `json:"uri,omitempty"`
}

// BackendTLSValidation is spec.validation.
type BackendTLSValidation struct {
	CACertificateRefs       []ObjRef     `json:"caCertificateRefs,omitempty"`
	WellKnownCACertificates string       `json:"wellKnownCACertificates,omitempty"`
	Hostname                string       `json:"hostname"`
	SubjectAltNames         []BackendSAN `json:"subjectAltNames,omitempty"`
}

// BackendTLSPolicy is the subset of the resource the data plane honours.
type BackendTLSPolicy struct {
	NS, Name   string
	Generation int64
	Created    time.Time
	Targets    []PolicyTarget
	Validation BackendTLSValidation
	Options    map[string]string
}

// Key is namespace/name.
func (p *BackendTLSPolicy) Key() string { return p.NS + "/" + p.Name }

type backendTLSSpec struct {
	creationMeta
	TargetRefs []PolicyTarget       `json:"targetRefs"`
	Validation BackendTLSValidation `json:"validation"`
	Options    map[string]string    `json:"options,omitempty"`
}

// CADef supplies a CA bundle for caCertificateRefs: PEM inline or a file
// (relative to the config file). In Kubernetes mode the ConfigMap or Secret
// key "ca.crt" fills it.
type CADef struct {
	File string `json:"file,omitempty"`
	PEM  string `json:"pem,omitempty"`
}

func (d CADef) load() ([]byte, error) {
	if d.File != "" {
		return os.ReadFile(d.File)
	}
	if d.PEM == "" {
		return nil, errors.New("no ca.crt data")
	}
	return []byte(d.PEM), nil
}

// parseBackendTLSPolicy reads a snapshot resource into the config.
func (c *Config) parseBackendTLSPolicy(ns, name string, raw []byte) error {
	var spec backendTLSSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return err
	}
	created, err := spec.created()
	if err != nil {
		return err
	}
	c.BackendTLS = append(c.BackendTLS, &BackendTLSPolicy{NS: ns, Name: name, Created: created, Targets: spec.TargetRefs, Validation: spec.Validation, Options: spec.Options})
	return nil
}

// BackendTLS is a resolved, valid policy ready to dial with.
type BackendTLS struct {
	Policy   string
	Hostname string
	MTLS     bool
	fp       string
	cfg      *tls.Config
}

func (b *BackendTLS) describe() string {
	s := fmt.Sprintf("TLS to the backend (policy %s): SNI and certificate name %s", b.Policy, b.Hostname)
	if b.MTLS {
		s += "; presents the Gateway's client certificate (mTLS)"
	}
	return s
}

// policyResult is one policy's resolution.
type policyResult struct {
	P        *BackendTLSPolicy
	Accepted fact
	Resolved fact
	TLS      *BackendTLS // nil unless every reference resolved
	// Winner reports which targets the policy applies to (not overridden by an older policy).
	lost map[string]bool
}

// ok reports whether connections may be made under the policy.
func (r *policyResult) ok() bool { return r.TLS != nil }

func (c *Config) caPool(p *BackendTLSPolicy) (*x509.CertPool, fact, fact) {
	v := p.Validation
	accepted, resolved := fact{true, "Accepted", ""}, fact{true, "ResolvedRefs", ""}
	switch {
	case len(v.CACertificateRefs) > 0 && v.WellKnownCACertificates != "":
		return nil, fact{false, "Invalid", "set either caCertificateRefs or wellKnownCACertificates, not both"}, resolved
	case len(v.CACertificateRefs) == 0 && v.WellKnownCACertificates == "":
		return nil, fact{false, "Invalid", "set caCertificateRefs or wellKnownCACertificates"}, resolved
	case v.WellKnownCACertificates != "":
		if v.WellKnownCACertificates != "System" {
			return nil, fact{false, "Invalid", fmt.Sprintf("wellKnownCACertificates %q is not supported (System is)", v.WellKnownCACertificates)}, resolved
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			return nil, fact{false, "Invalid", "system CA certificates are not available"}, resolved
		}
		return pool, accepted, resolved
	}
	pool := x509.NewCertPool()
	valid := 0
	for _, ref := range v.CACertificateRefs {
		if (ref.Group != "" && ref.Group != "core") || (ref.Kind != "ConfigMap" && ref.Kind != "Secret") {
			if resolved.OK {
				resolved = fact{false, "InvalidKind", fmt.Sprintf("caCertificateRef %s/%s is not a ConfigMap or Secret", ref.Kind, ref.Name)}
			}
			continue
		}
		def, ok := c.CACerts[p.NS+"/"+ref.Name]
		var pem []byte
		var err error
		if !ok {
			err = fmt.Errorf("%s %s/%s not found", ref.Kind, p.NS, ref.Name)
		} else if pem, err = def.load(); err == nil && !pool.AppendCertsFromPEM(pem) {
			err = fmt.Errorf("%s %s/%s ca.crt holds no PEM certificate", ref.Kind, p.NS, ref.Name)
		}
		if err != nil {
			if resolved.OK {
				resolved = fact{false, "InvalidCACertificateRef", err.Error()}
			}
			continue
		}
		valid++
	}
	if valid == 0 {
		return nil, fact{false, "NoValidCACertificate", "none of caCertificateRefs is valid: " + resolved.Message}, resolved
	}
	return pool, accepted, resolved
}

// resolve builds the client side TLS configuration of a policy.
func (c *Config) resolveBackendTLS(p *BackendTLSPolicy, clientCert *tls.Certificate) *policyResult {
	res := &policyResult{P: p, Accepted: fact{true, "Accepted", ""}, Resolved: fact{true, "ResolvedRefs", ""}, lost: map[string]bool{}}
	for _, t := range p.Targets {
		if (t.Group != "" && t.Group != "core") || t.Kind != "Service" {
			res.Accepted = fact{false, "Invalid", fmt.Sprintf("targetRef %s/%s must be a Service", t.Kind, t.Name)}
			return res
		}
	}
	if len(p.Targets) == 0 {
		res.Accepted = fact{false, "Invalid", "targetRefs is empty"}
		return res
	}
	if p.Validation.Hostname == "" {
		res.Accepted = fact{false, "Invalid", "validation.hostname is required"}
		return res
	}
	for _, s := range p.Validation.SubjectAltNames {
		if (s.Type == "Hostname" && s.Hostname == "") || (s.Type == "URI" && s.URI == "") || (s.Type != "Hostname" && s.Type != "URI") {
			res.Accepted = fact{false, "Invalid", "subjectAltNames entries need type Hostname with hostname, or type URI with uri"}
			return res
		}
	}
	pool, acc, resolved := c.caPool(p)
	res.Resolved = resolved
	if !acc.OK {
		res.Accepted = acc
		return res
	}
	if !resolved.OK {
		return res // some reference is invalid: connections must fail
	}
	host, sans := p.Validation.Hostname, p.Validation.SubjectAltNames
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		return verifyBackend(raw, pool, host, sans)
	}
	bt := &BackendTLS{Policy: p.Key(), Hostname: host, cfg: cfg}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
		bt.MTLS = true
	}
	h := sha256.New()
	fmt.Fprint(h, p.Key(), host, sans, p.Validation.WellKnownCACertificates, bt.MTLS)
	for _, ref := range p.Validation.CACertificateRefs {
		if d, ok := c.CACerts[p.NS+"/"+ref.Name]; ok {
			pem, _ := d.load()
			h.Write(pem)
		}
	}
	if clientCert != nil {
		for _, der := range clientCert.Certificate {
			h.Write(der)
		}
	}
	bt.fp = hex.EncodeToString(h.Sum(nil))[:24]
	res.TLS = bt
	return res
}

// verifyBackend validates the chain against pool and the name (or SANs).
func verifyBackend(raw [][]byte, pool *x509.CertPool, host string, sans []BackendSAN) error {
	if len(raw) == 0 {
		return errors.New("backend presented no certificate")
	}
	var leaf *x509.Certificate
	inter := x509.NewCertPool()
	for i, der := range raw {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		if i == 0 {
			leaf = c
		} else {
			inter.AddCert(c)
		}
	}
	opts := x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if len(sans) == 0 {
		opts.DNSName = host
	}
	if _, err := leaf.Verify(opts); err != nil {
		return err
	}
	if len(sans) == 0 {
		return nil
	}
	for _, s := range sans {
		switch s.Type {
		case "Hostname":
			if leaf.VerifyHostname(s.Hostname) == nil {
				return nil
			}
		case "URI":
			for _, u := range leaf.URIs {
				if u.String() == s.URI {
					return nil
				}
			}
		}
	}
	return errors.New("backend certificate has none of the subjectAltNames the policy requires")
}

func targetKey(ns, name, section string) string { return ns + "/" + name + "/" + section }

// resolvePolicies resolves every BackendTLSPolicy and settles conflicts: of
// several policies on one target (Service and section) the older wins and the
// others are Accepted=False, Conflicted.
func (t *Table) resolvePolicies() {
	t.policyFor = map[string]*policyResult{}
	ps := append([]*BackendTLSPolicy(nil), t.Cfg.BackendTLS...)
	sort.SliceStable(ps, func(i, j int) bool {
		if !ps[i].Created.Equal(ps[j].Created) {
			return ps[i].Created.Before(ps[j].Created)
		}
		return ps[i].Key() < ps[j].Key()
	})
	for _, p := range ps {
		cert := t.clientCertFor(p.NS)
		res := t.Cfg.resolveBackendTLS(p, cert)
		t.policies = append(t.policies, res)
		serviceTargets := len(p.Targets) > 0
		for _, tg := range p.Targets {
			serviceTargets = serviceTargets && tg.Kind == "Service"
		}
		if !serviceTargets {
			continue
		}
		// An invalid policy still claims its targets: traffic must fail, not go plaintext.
		for _, tg := range p.Targets {
			k := targetKey(p.NS, tg.Name, tg.SectionName)
			if prev := t.policyFor[k]; prev != nil {
				res.lost[k] = true
				res.Accepted = fact{false, "Conflicted", fmt.Sprintf("policy %s targets the same Service and section and is older", prev.P.Key())}
				res.TLS = nil
				continue
			}
			t.policyFor[k] = res
		}
	}
}

// clientCertFor returns the backend client certificate a Gateway declares
// (spec.tls.backend.clientCertificateRef), if any Gateway in the config does
// and the Secret resolves. Gateways are visited in key order, so the result is
// deterministic; one process presents one client identity per policy.
func (t *Table) clientCertFor(policyNS string) *tls.Certificate {
	if t.gwCerts == nil {
		t.gwCerts = map[string]*gwClientCert{}
	}
	var first *tls.Certificate
	gws := append([]*Gateway(nil), t.Cfg.Gateways...)
	sort.Slice(gws, func(i, j int) bool { return gws[i].Key() < gws[j].Key() })
	for _, gw := range gws {
		ref := gw.BackendClientCert
		if ref == nil {
			continue
		}
		gc := t.gwCerts[gw.Key()]
		if gc == nil {
			gc = &gwClientCert{fact: fact{true, "ResolvedRefs", ""}}
			t.gwCerts[gw.Key()] = gc
			ns := ref.Namespace
			if ns == "" {
				ns = gw.NS
			}
			switch {
			case (ref.Kind != "" && ref.Kind != "Secret") || (ref.Group != "" && ref.Group != "core"):
				gc.fact = fact{false, "InvalidClientCertificateRef", "clientCertificateRef must be a core Secret"}
			case !t.Cfg.granted("Gateway", gw.NS, "", "Secret", ns, ref.Name):
				gc.fact = fact{false, "RefNotPermitted", fmt.Sprintf("Secret %s/%s needs a ReferenceGrant", ns, ref.Name)}
			default:
				def, ok := t.Cfg.Secrets[ns+"/"+ref.Name]
				if !ok {
					gc.fact = fact{false, "InvalidClientCertificateRef", fmt.Sprintf("Secret %s/%s is not available", ns, ref.Name)}
				} else if pair, err := def.load(); err != nil {
					gc.fact = fact{false, "InvalidClientCertificateRef", fmt.Sprintf("Secret %s/%s: %v", ns, ref.Name, err)}
				} else {
					gc.cert = &pair
				}
			}
		}
		if gc.cert != nil && first == nil {
			first = gc.cert
		}
	}
	return first
}

type gwClientCert struct {
	fact fact
	cert *tls.Certificate
}

// applyBackendTLS attaches the winning policy for ns/svc:port to a new
// backend. A policy whose references do not resolve leaves TLSErr set so every
// connection fails with a 5xx instead of falling back to plaintext.
func (t *Table) applyBackendTLS(b *Backend, ns, svc string, port int, portName string) {
	var res *policyResult
	sections := []string{strconv.Itoa(port), ""}
	if portName != "" {
		sections = []string{strconv.Itoa(port), portName, ""}
	}
	for _, sec := range sections {
		if r := t.policyFor[targetKey(ns, svc, sec)]; r != nil {
			res = r
			break
		}
	}
	if res == nil {
		return
	}
	b.TLSPolicy = res.P.Key()
	if !res.ok() {
		b.TLSErr = fmt.Sprintf("BackendTLSPolicy %s is not valid: %s", res.P.Key(), firstFalse(res).Message)
		return
	}
	b.TLS = res.TLS
	for _, ep := range b.Eps {
		if ep.URL.Scheme == "http" {
			u := *ep.URL
			u.Scheme = "https"
			ep.URL = &u
		}
	}
}

func firstFalse(r *policyResult) fact {
	if !r.Resolved.OK {
		return r.Resolved
	}
	return r.Accepted
}

// errTransport fails every request: a backend whose policy is invalid.
type errTransport struct{ err error }

func (e errTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// backendTransport is the HTTP transport for b: the shared pools for plain and
// insecure upstreams, a policy specific one when a BackendTLSPolicy applies.
func (s *Server) backendTransport(b *Backend) http.RoundTripper {
	return s.derivedTransport(b, s.backendTransportBase(b), false)
}

func (s *Server) backendTransportBase(b *Backend) http.RoundTripper {
	switch {
	case b.TLSErr != "":
		return errTransport{errors.New(b.TLSErr)}
	case b.TLS == nil:
		return s.transport(b.Insecure)
	}
	if v, ok := s.btlsTr.Load("h1|" + b.TLS.fp); ok {
		return v.(*http.Transport)
	}
	tr := s.transport(false).(*http.Transport).Clone()
	tr.TLSClientConfig = b.TLS.cfg.Clone()
	v, _ := s.btlsTr.LoadOrStore("h1|"+b.TLS.fp, tr)
	return v.(*http.Transport)
}

// grpcTransport is backendTransport for gRPC (HTTP/2 only).
func (s *Server) grpcTransport(b *Backend, scheme string) http.RoundTripper {
	return s.derivedTransport(b, s.grpcTransportBase(b, scheme), true)
}

func (s *Server) grpcTransportBase(b *Backend, scheme string) http.RoundTripper {
	switch {
	case b.TLSErr != "":
		return errTransport{errors.New(b.TLSErr)}
	case b.TLS == nil:
		return s.grpcTr.get(scheme, b.Insecure)
	}
	if v, ok := s.btlsTr.Load("h2|" + b.TLS.fp); ok {
		return v.(*http.Transport)
	}
	tr := newTLSH2Transport(false)
	tr.TLSClientConfig = b.TLS.cfg.Clone()
	tr.TLSClientConfig.NextProtos = []string{"h2"}
	v, _ := s.btlsTr.LoadOrStore("h2|"+b.TLS.fp, tr)
	return v.(*http.Transport)
}

func (s *Server) closeBackendTLSTransports() {
	s.btlsTr.Range(func(_, v any) bool {
		v.(*http.Transport).CloseIdleConnections()
		return true
	})
	s.closeDerivedTransports()
}

// resolveCAPath makes a CADef file path absolute against the config directory.
func (d CADef) abs(dir string) CADef {
	if d.File != "" && !filepath.IsAbs(d.File) && dir != "" {
		d.File = filepath.Join(dir, d.File)
	}
	return d
}

// policyStatuses derives the per-ancestor status of every policy from the
// routes that use the Service it targets.
func (t *Table) policyStatuses(now time.Time, prev map[string]*PolicyStatus) map[string]*PolicyStatus {
	out := map[string]*PolicyStatus{}
	for _, res := range t.policies {
		key := res.P.Key()
		ps := &PolicyStatus{ObservedGeneration: res.P.Generation}
		seen := map[string]bool{}
		for _, rr := range t.routes {
			uses := false
			for _, b := range rr.Backends {
				for _, tg := range res.P.Targets {
					uses = uses || strings.HasPrefix(b.Key, res.P.NS+"/"+tg.Name+":")
				}
			}
			if !uses {
				continue
			}
			for _, p := range rr.Parents {
				ns := p.Ref.Namespace
				if ns == "" {
					ns = rr.Route.NS
				}
				if p.Ref.Kind != "" && p.Ref.Kind != "Gateway" {
					continue
				}
				gk := ns + "/" + p.Ref.Name
				if seen[gk] {
					continue
				}
				seen[gk] = true
				var old []Condition
				if po := prev[key]; po != nil {
					for _, a := range po.Ancestors {
						if a.AncestorRef.Name == p.Ref.Name && a.AncestorRef.Namespace == ns {
							old = a.Conditions
						}
					}
				}
				ps.Ancestors = append(ps.Ancestors, AncestorStatus{
					AncestorRef:    ParentRef{Group: APIGroup, Kind: "Gateway", Name: p.Ref.Name, Namespace: ns},
					ControllerName: ControllerName,
					Conditions: []Condition{
						mkCond(old, "Accepted", res.Accepted, res.P.Generation, now),
						mkCond(old, "ResolvedRefs", res.Resolved, res.P.Generation, now),
					},
				})
			}
		}
		out[key] = ps
	}
	return out
}

// tlsFP identifies the TLS settings of b (empty without a policy), for
// transport caches keyed by backend.
func (b *Backend) tlsFP() string {
	switch {
	case b.TLSErr != "":
		return "invalid"
	case b.TLS != nil:
		return b.TLS.fp
	}
	return ""
}

// PolicyStatus is the status of one BackendTLSPolicy: conditions per ancestor
// (each Gateway whose routes use the targeted Service).
type PolicyStatus struct {
	ObservedGeneration int64            `json:"observedGeneration"`
	Ancestors          []AncestorStatus `json:"ancestors"`
}

// AncestorStatus is a policy's status for one ancestor.
type AncestorStatus struct {
	AncestorRef    ParentRef   `json:"ancestorRef"`
	ControllerName string      `json:"controllerName"`
	Conditions     []Condition `json:"conditions"`
}
