package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client certificate validation on HTTPS listeners: Gateway API 1.5 frontend
// TLS validation (spec.tls.frontend), enforced in the handshake and again per
// request, and the verified identity forwarded in X-Setura-Client-* headers.

// Frontend validation modes.
const (
	ModeAllowValidOnly         = "AllowValidOnly"
	ModeAllowInsecureFallback  = "AllowInsecureFallback"
	reasonInvalidCACertificate = "InvalidCACertificateRef"
)

// GatewayTLS is a Gateway's spec.tls.
type GatewayTLS struct {
	Frontend *FrontendTLS `json:"frontend,omitempty"`
}

// FrontendTLS is spec.tls.frontend: client certificate validation for the
// listeners, with per-port overrides.
type FrontendTLS struct {
	Default *FrontendTLSConfig `json:"default,omitempty"`
	PerPort []struct {
		Port int               `json:"port"`
		TLS  FrontendTLSConfig `json:"tls"`
	} `json:"perPort,omitempty"`
}

// FrontendTLSConfig is one validation setting.
type FrontendTLSConfig struct {
	Validation *FrontendValidation `json:"validation,omitempty"`
}

// FrontendValidation names the CA bundle clients must chain to. The CA
// bundle is the ca.crt of a ConfigMap or Secret, which a config file supplies
// as an entry of its "secrets" section (cert or certFile; no key needed).
type FrontendValidation struct {
	CACertificateRefs []ObjRef `json:"caCertificateRefs"`
	// Mode is AllowValidOnly (default): a client without a certificate that
	// chains to the CA bundle is refused. AllowInsecureFallback accepts such
	// clients too; the request then carries no verified identity.
	Mode string `json:"mode,omitempty"`
}

// ClientValidation is the resolved form on a listener.
type ClientValidation struct {
	Mode string
	Pool *x509.CertPool
}

func (v *FrontendValidation) mode() string {
	if v.Mode == "" {
		return ModeAllowValidOnly
	}
	return v.Mode
}

// validationFor is the validation block of a Gateway for a port, or nil.
func (g *Gateway) validationFor(port int) *FrontendValidation {
	if g.TLS == nil || g.TLS.Frontend == nil {
		return nil
	}
	f := g.TLS.Frontend
	for _, pp := range f.PerPort {
		if pp.Port == port {
			return pp.TLS.Validation
		}
	}
	if f.Default != nil {
		return f.Default.Validation
	}
	return nil
}

func caPEM(def SecretDef) ([]byte, error) {
	if def.CertFile != "" {
		return os.ReadFile(def.CertFile)
	}
	if def.Cert == "" {
		return nil, fmt.Errorf("no ca.crt")
	}
	return []byte(def.Cert), nil
}

// resolveClientCA resolves the frontend validation of an HTTPS listener. A bad
// reference makes the listener not serve (fail closed): never fall back to
// serving without the validation the operator asked for.
func (c *Config) resolveClientCA(l *RTListener) {
	if c.skipCerts || l.L.Protocol != "HTTPS" {
		return
	}
	v := l.GW.validationFor(l.L.Port)
	if v == nil {
		return
	}
	fail := func(format string, a ...any) {
		l.Resolved = fact{false, reasonInvalidCACertificate, fmt.Sprintf(format, a...)}
	}
	switch v.mode() {
	case ModeAllowValidOnly, ModeAllowInsecureFallback:
	default:
		fail("frontend validation mode %q is not supported (want %s or %s)", v.Mode, ModeAllowValidOnly, ModeAllowInsecureFallback)
		return
	}
	if len(v.CACertificateRefs) == 0 {
		fail("frontend validation has no caCertificateRefs")
		return
	}
	pool := x509.NewCertPool()
	for _, ref := range v.CACertificateRefs {
		if (ref.Kind != "ConfigMap" && ref.Kind != "Secret") || (ref.Group != "" && ref.Group != "core") {
			fail("caCertificateRef %q must be a core ConfigMap or Secret", ref.Name)
			return
		}
		ns := ref.Namespace
		if ns == "" {
			ns = l.GW.NS
		}
		if !c.granted("Gateway", l.GW.NS, "", ref.Kind, ns, ref.Name) {
			l.Resolved = fact{false, "RefNotPermitted", fmt.Sprintf("%s %s/%s needs a ReferenceGrant", ref.Kind, ns, ref.Name)}
			return
		}
		def, ok := c.Secrets[ns+"/"+ref.Name]
		if !ok {
			fail("%s %s/%s is not available", ref.Kind, ns, ref.Name)
			return
		}
		pem, err := caPEM(def)
		if err != nil {
			fail("%s %s/%s: %v", ref.Kind, ns, ref.Name, err)
			return
		}
		if !pool.AppendCertsFromPEM(pem) {
			fail("%s %s/%s: ca.crt holds no PEM certificate", ref.Kind, ns, ref.Name)
			return
		}
	}
	l.Client = &ClientValidation{Mode: v.mode(), Pool: pool}
}

// listenerForTLS picks the listener a handshake with this SNI belongs to,
// the way certFor picks its certificate.
func (pg *PortGroup) listenerForTLS(sni string) *RTListener {
	sni = strings.ToLower(sni)
	var l *RTListener
	if sni != "" {
		l = pg.pickListener(sni)
	}
	if l == nil || len(l.Certs) == 0 {
		l = nil
		for _, c := range pg.Listeners {
			if len(c.Certs) > 0 && (l == nil || c.Host == "") {
				l = c
			}
		}
	}
	return l
}

// clientTLSConfig is the tls.Config GetConfigForClient hands to a handshake:
// the listener's own, with client certificates requested. It returns nil to
// keep the base configuration when the listener has no validation.
func (s *Server) clientTLSConfig(base *tls.Config, port int, h *tls.ClientHelloInfo) (*tls.Config, error) {
	t := s.table.Load()
	if t == nil || t.Ports[port] == nil {
		return nil, nil
	}
	l := t.Ports[port].listenerForTLS(h.ServerName)
	if l == nil || l.Client == nil {
		return nil, nil
	}
	c := base.Clone()
	c.GetConfigForClient = nil
	c.ClientCAs = l.Client.Pool
	if l.Client.Mode == ModeAllowValidOnly {
		c.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		c.ClientAuth = tls.RequestClientCert // verified per request, so a bad certificate does not end the connection
	}
	return c, nil
}

// ClientCert is the identity of a presented client certificate.
type ClientCert struct {
	Verified    bool
	Subject     string
	SAN         string
	Serial      string
	Fingerprint string // SHA-256 of the DER certificate, hex
}

func sanList(c *x509.Certificate) string {
	var v []string
	for _, d := range c.DNSNames {
		v = append(v, "DNS:"+d)
	}
	for _, u := range c.URIs {
		v = append(v, "URI:"+u.String())
	}
	for _, ip := range c.IPAddresses {
		v = append(v, "IP:"+ip.String())
	}
	for _, e := range c.EmailAddresses {
		v = append(v, "email:"+e)
	}
	return strings.Join(v, ",")
}

// verifyClientCert checks the peer certificate against a pool at a time.
func verifyClientCert(peers []*x509.Certificate, v *ClientValidation, now time.Time) *ClientCert {
	if len(peers) == 0 {
		return nil
	}
	leaf := peers[0]
	sum := sha256.Sum256(leaf.Raw)
	cc := &ClientCert{Fingerprint: hex.EncodeToString(sum[:])}
	inter := x509.NewCertPool()
	for _, p := range peers[1:] {
		inter.AddCert(p)
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: v.Pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err == nil {
		cc.Verified = true
		cc.Subject, cc.SAN, cc.Serial = leaf.Subject.String(), sanList(leaf), leaf.SerialNumber.Text(16)
	}
	return cc
}

// clientCertFor returns the verified client identity of a request on listener
// l (nil when the listener has no validation or the client sent no
// certificate). deny is non-empty when the listener requires a valid
// certificate and the request has none: a connection negotiated for another
// server name, and then used for this Host, does not get around the check.
func (s *Server) clientCertFor(l *RTListener, r *http.Request) (cc *ClientCert, deny string) {
	if l == nil || l.Client == nil {
		return nil, ""
	}
	var peers []*x509.Certificate
	if r.TLS != nil {
		peers = r.TLS.PeerCertificates
	}
	cc = verifyClientCert(peers, l.Client, s.authNow())
	if l.Client.Mode == ModeAllowValidOnly && (cc == nil || !cc.Verified) {
		return cc, "client certificate required and not valid for this listener"
	}
	return cc, ""
}

// setHeaders writes the identity headers. Nothing is written for a client
// without a certificate; for a certificate that did not verify (fallback
// mode) only X-Setura-Client-Verified: false, as its fields are unproven.
func (c *ClientCert) setHeaders(h http.Header) {
	if c == nil {
		return
	}
	if !c.Verified {
		h.Set(clientHeaderPrefix+"Verified", "false")
		return
	}
	h.Set(clientHeaderPrefix+"Verified", "true")
	h.Set(clientHeaderPrefix+"Subject", c.Subject)
	if c.SAN != "" {
		h.Set(clientHeaderPrefix+"SAN", c.SAN)
	}
	h.Set(clientHeaderPrefix+"Serial", c.Serial)
	h.Set(clientHeaderPrefix+"Fingerprint", c.Fingerprint)
}

// loadClientCAs fetches the CA bundles frontend validation refers to (the
// ca.crt key of a ConfigMap or Secret) into cfg.Secrets, like listener
// certificates. A bundle that cannot be read leaves the listener unresolved.
func (k *KubeSource) loadClientCAs(ctx context.Context, cfg *Config) {
	for _, gw := range cfg.Gateways {
		if gw.TLS == nil || gw.TLS.Frontend == nil {
			continue
		}
		var vals []*FrontendValidation
		if d := gw.TLS.Frontend.Default; d != nil && d.Validation != nil {
			vals = append(vals, d.Validation)
		}
		for _, pp := range gw.TLS.Frontend.PerPort {
			if pp.TLS.Validation != nil {
				vals = append(vals, pp.TLS.Validation)
			}
		}
		for _, v := range vals {
			for _, ref := range v.CACertificateRefs {
				ns := ref.Namespace
				if ns == "" {
					ns = gw.NS
				}
				key := ns + "/" + ref.Name
				if _, done := cfg.Secrets[key]; done || (ref.Kind != "ConfigMap" && ref.Kind != "Secret") {
					continue
				}
				res := "configmaps"
				if ref.Kind == "Secret" {
					res = "secrets"
				}
				b, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(ns)+"/"+res+"/"+url.PathEscape(ref.Name), nil, "")
				if err != nil {
					k.warn("%s %s: %v", ref.Kind, key, err)
					continue
				}
				var obj struct {
					Data map[string]string `json:"data"`
				}
				json.Unmarshal(b, &obj)
				pem := obj.Data["ca.crt"]
				if ref.Kind == "Secret" {
					dec, _ := base64.StdEncoding.DecodeString(pem)
					pem = string(dec)
				}
				cfg.Secrets[key] = SecretDef{Cert: pem}
			}
		}
	}
}
