package setura

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// CertInfo describes one certificate of a presented chain.
type CertInfo struct {
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	DNSNames      []string `json:"sans,omitempty"`
	IPAddresses   []string `json:"ip_sans,omitempty"`
	NotBefore     string   `json:"not_before"`
	NotAfter      string   `json:"not_after"`
	DaysToExpiry  int      `json:"days_to_expiry"`
	KeyType       string   `json:"key_type"`
	SignatureAlgo string   `json:"signature_algorithm"`
	IsCA          bool     `json:"is_ca"`
}

// CertsReport is the result of inspecting one endpoint.
type CertsReport struct {
	Address     string     `json:"address"`
	ServerName  string     `json:"server_name"`
	Version     string     `json:"tls_version,omitempty"`
	ClientCert  string     `json:"client_cert,omitempty"`
	Chain       []CertInfo `json:"chain"`
	Verified    bool       `json:"verified"`
	VerifyError string     `json:"verify_error,omitempty"`
	Expiring    bool       `json:"expiring"`
	OK          bool       `json:"ok"`
}

// CertsOptions configures Certs.
type CertsOptions struct {
	Address string // HOST:PORT
	CA      string
	SNI     string
	Timeout time.Duration
	tlsOpts
}

func keyType(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-" + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}

func certInfo(c *x509.Certificate) CertInfo {
	ci := CertInfo{Subject: c.Subject.String(), Issuer: c.Issuer.String(), DNSNames: c.DNSNames,
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		DaysToExpiry: daysUntil(c.NotAfter), KeyType: keyType(c.PublicKey), SignatureAlgo: c.SignatureAlgorithm.String(), IsCA: c.IsCA}
	for _, ip := range c.IPAddresses {
		ci.IPAddresses = append(ci.IPAddresses, ip.String())
	}
	return ci
}

// preflight validates the options without connecting.
func (o CertsOptions) preflight() error {
	if host, _, err := net.SplitHostPort(o.Address); err != nil || host == "" {
		return userError("expected HOST:PORT")
	}
	return o.tlsOpts.validate()
}

// Certs connects to HOST:PORT, records the presented chain and verifies it.
// The handshake itself skips verification so an invalid chain can still be
// reported; the chain is then verified explicitly against the chosen roots.
func Certs(o CertsOptions) (*CertsReport, error) {
	host, _, err := net.SplitHostPort(o.Address)
	if err != nil || host == "" {
		return nil, userError("expected HOST:PORT")
	}
	if err := o.tlsOpts.validate(); err != nil {
		return nil, err
	}
	name := host
	if o.SNI != "" {
		name = o.SNI
	}
	if o.ServerName != "" {
		name = o.ServerName
	}
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	var roots *x509.CertPool
	if o.CA != "" {
		pem, err := os.ReadFile(o.CA)
		if err != nil {
			return nil, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, userErrorf("no certificates found in %s", o.CA)
		}
	}
	cfg := &tls.Config{ServerName: name, InsecureSkipVerify: true} // verified manually below
	st, err := o.tlsOpts.configure(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", o.Address, o.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tc := tls.Client(conn, cfg)
	_ = tc.SetDeadline(time.Now().Add(o.Timeout))
	if err := tc.Handshake(); err != nil {
		if reason, ok := clientCertFailure(err, st); ok {
			return nil, userError(reason)
		}
		return nil, err
	}
	// TLS 1.3 reports client-certificate rejection on the next read.
	if tc.ConnectionState().Version == tls.VersionTLS13 && st.requested {
		_ = tc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := tc.Read(make([]byte, 1)); err != nil && err != io.EOF {
			if reason, ok := clientCertFailure(err, st); ok {
				return nil, userError(reason)
			}
		}
	}
	cs := tc.ConnectionState()
	rep := &CertsReport{Address: o.Address, ServerName: name, Version: tlsNames[cs.Version], ClientCert: st.clientCert(), Chain: []CertInfo{}}
	for _, c := range cs.PeerCertificates {
		rep.Chain = append(rep.Chain, certInfo(c))
	}
	if len(cs.PeerCertificates) == 0 {
		rep.VerifyError = "server presented no certificates"
		return rep, nil
	}
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: name}
	if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
		rep.VerifyError = err.Error()
	} else {
		rep.Verified = true
	}
	for _, c := range rep.Chain {
		if o.WarnExpiryDays > 0 && c.DaysToExpiry < o.WarnExpiryDays {
			rep.Expiring = true
		}
	}
	rep.OK = rep.Verified && !rep.Expiring
	return rep, nil
}

// Text renders the report for terminals.
func (r *CertsReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (server name %s) %s client_cert=%s\n", r.Address, r.ServerName, r.Version, r.ClientCert)
	for i, c := range r.Chain {
		fmt.Fprintf(&b, "[%d] subject=%s\n    issuer=%s\n    sans=%s\n    valid=%s .. %s (%d days left)\n    key=%s signature=%s ca=%t\n",
			i, c.Subject, c.Issuer, strings.Join(append(append([]string{}, c.DNSNames...), c.IPAddresses...), ","),
			c.NotBefore, c.NotAfter, c.DaysToExpiry, c.KeyType, c.SignatureAlgo, c.IsCA)
	}
	if r.Verified {
		b.WriteString("verified: yes\n")
	} else {
		fmt.Fprintf(&b, "verified: no (%s)\n", r.VerifyError)
	}
	if r.Expiring {
		b.WriteString("expiring: yes\n")
	}
	return b.String()
}
