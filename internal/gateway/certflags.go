package gateway

import (
	"flag"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

// CertOptions groups the certificate and edge-protocol settings of a Server.
type CertOptions struct {
	// ACME enables certificates from an ACME CA for HTTPS listeners that have a
	// hostname and no certificateRefs.
	ACME *ACMEOptions
	// ProxyProtocol maps a spec port to the source networks allowed to send a
	// PROXY protocol v1 or v2 header on it.
	ProxyProtocol map[int][]netip.Prefix
	// AltSvc is sent as the Alt-Svc header on HTTPS responses so that clients
	// learn about an HTTP/3-capable edge in front of the gateway.
	AltSvc string
}

// certFlags are the command line flags of CertOptions.
type certFlags struct {
	acme       ACMEOptions
	acmeDir    string
	proxyProto stringList
	altSvc     string
}

func addCertFlags(fs *flag.FlagSet, c *certFlags) {
	fs.StringVar(&c.acmeDir, "acme-dir", "", "enable ACME: store the account and certificates in DIR")
	fs.StringVar(&c.acme.DirectoryURL, "acme-directory", "", "ACME directory URL (default: Let's Encrypt staging)")
	fs.BoolVar(&c.acme.Production, "acme-production", false, "use the Let's Encrypt production directory")
	fs.StringVar(&c.acme.Email, "acme-email", "", "ACME account contact address")
	fs.StringVar(&c.acme.DNSHook, "acme-dns-hook", "", "command for DNS-01 (wildcards), run as CMD present|cleanup DOMAIN VALUE")
	fs.StringVar(&c.acme.Challenge, "acme-challenge", "", "preferred challenge: http-01 or tls-alpn-01 (default: http-01 when a plain HTTP listener exists)")
	fs.Var(&c.proxyProto, "proxy-protocol", "accept PROXY protocol v1/v2 on spec port N from CIDR[,..], as N=CIDR[,..]; repeatable")
	fs.StringVar(&c.altSvc, "alt-svc", "", "Alt-Svc header value sent on HTTPS responses (advertise an HTTP/3 edge)")
}

func (c *certFlags) apply(o *Options) error {
	if c.acmeDir != "" {
		a := c.acme
		a.Dir = c.acmeDir
		o.Cert.ACME = &a
	} else if c.acme.DirectoryURL != "" || c.acme.Production || c.acme.Email != "" || c.acme.DNSHook != "" || c.acme.Challenge != "" {
		return fmt.Errorf("--acme-* flags need --acme-dir")
	}
	if c.acme.Production && c.acme.DirectoryURL != "" {
		return fmt.Errorf("--acme-production and --acme-directory are mutually exclusive")
	}
	pp, err := parseProxyProtocolFlags(c.proxyProto)
	if err != nil {
		return err
	}
	o.Cert.ProxyProtocol = pp
	if err := validAltSvc(c.altSvc); err != nil {
		return fmt.Errorf("--alt-svc: %w", err)
	}
	o.Cert.AltSvc = c.altSvc
	return nil
}

func parseProxyProtocolFlags(groups []string) (map[int][]netip.Prefix, error) {
	var out map[int][]netip.Prefix
	for _, g := range groups {
		port, cidrs, ok := strings.Cut(strings.TrimSpace(g), "=")
		n, err := strconv.Atoi(port)
		if !ok || err != nil || n < 1 || n > 65535 || strings.TrimSpace(cidrs) == "" {
			return nil, fmt.Errorf("--proxy-protocol %q: want PORT=CIDR[,CIDR...] (the trusted sources are required)", g)
		}
		ps, err := ParseTrustedProxies(cidrs)
		if err != nil || len(ps) == 0 {
			return nil, fmt.Errorf("--proxy-protocol %q: %v", g, err)
		}
		if out == nil {
			out = map[int][]netip.Prefix{}
		}
		out[n] = append(out[n], ps...)
	}
	return out, nil
}

func validAltSvc(v string) error {
	for _, r := range v {
		if r < 0x20 || r > 0x7e {
			return fmt.Errorf("only printable ASCII is allowed")
		}
	}
	return nil
}

// initCert builds the ACME manager from the options (called by New).
func (s *Server) initCert() {
	if err := validAltSvc(s.opts.Cert.AltSvc); err != nil {
		s.acmeErr = fmt.Errorf("alt-svc: %w", err)
		return
	}
	a := s.opts.Cert.ACME
	if a == nil {
		return
	}
	o := *a
	if o.Diag == nil {
		o.Diag = s.diag
	}
	m, err := newACMEManager(o)
	if err != nil {
		s.acmeErr = err
		return
	}
	m.onInstall = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if t := s.table.Load(); t != nil {
			s.ocspSync(t)
		}
	}
	s.acme = m
}

// edgeRequest handles what happens before routing: the ACME HTTP-01 challenge
// on plain listeners and the Alt-Svc advertisement on TLS ones. It reports
// whether the request was answered.
func (s *Server) edgeRequest(w http.ResponseWriter, r *http.Request, tlsPort bool) bool {
	if tlsPort {
		if v := s.opts.Cert.AltSvc; v != "" {
			w.Header().Set("Alt-Svc", v)
		}
		return false
	}
	if s.acme != nil && strings.HasPrefix(r.URL.Path, acmeChallengePrefix) {
		s.acme.serveHTTP01(w, r)
		return true
	}
	return false
}
