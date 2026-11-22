package setura

import (
	"crypto/tls"
	"fmt"
	"math"
	"strings"
	"time"
)

// tlsOpts carries the optional client-authentication and TLS policy settings
// shared by explain, check and certs.
type tlsOpts struct {
	Cert, Key      string
	ServerName     string
	MinTLS         string // "", "1.2" or "1.3"
	WarnExpiryDays int    // 0 disables the warning
	MinCertDays    int    // 0 disables the assertion
}

// mtlsState records what happened during one handshake.
type mtlsState struct {
	requested bool // the server sent a CertificateRequest
	offered   bool // we had a certificate to give
}

var tlsVersions = map[string]uint16{"1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}

func (t tlsOpts) validate() error {
	if (t.Cert == "") != (t.Key == "") {
		return userError("--cert and --key must be given together")
	}
	if t.MinTLS != "" {
		if _, ok := tlsVersions[t.MinTLS]; !ok {
			return userError("min TLS version must be 1.2 or 1.3")
		}
	}
	if strings.ContainsAny(t.ServerName, " /\t\r\n") {
		return userError("invalid TLS server name")
	}
	if t.WarnExpiryDays < 0 || t.MinCertDays < 0 {
		return userError("expiry days must not be negative")
	}
	return nil
}

func (o ProbeOptions) tlsOpts() tlsOpts {
	return tlsOpts{o.Cert, o.Key, o.ServerName, o.MinTLS, o.WarnExpiryDays, o.MinCertDays}
}

// configure applies the options to cfg and returns a state tracker.
func (t tlsOpts) configure(cfg *tls.Config) (*mtlsState, error) {
	st := &mtlsState{}
	if t.ServerName != "" {
		cfg.ServerName = t.ServerName
	}
	if t.MinTLS != "" {
		cfg.MinVersion = tlsVersions[t.MinTLS]
	}
	var cert *tls.Certificate
	if t.Cert != "" {
		c, err := tls.LoadX509KeyPair(t.Cert, t.Key)
		if err != nil {
			return nil, fmt.Errorf("client certificate: %v", err)
		}
		cert = &c
		st.offered = true
	}
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		st.requested = true
		if cert != nil {
			return cert, nil
		}
		return &tls.Certificate{}, nil
	}
	return st, nil
}

func (s *mtlsState) clientCert() string {
	switch {
	case !s.requested:
		return "not_requested"
	case s.offered:
		return "presented"
	}
	return "withheld"
}

func daysUntil(t time.Time) int {
	return int(math.Floor(time.Until(t).Hours() / 24))
}

// tlsStep builds the tls step after a successful handshake. It returns the step
// and a failure reason when the min_cert_days assertion is violated.
func (t tlsOpts) tlsStep(cs tls.ConnectionState, st *mtlsState) (*Step, string) {
	step := &Step{{"state", "ok"}, {"version", tlsNames[cs.Version]}, {"cipher_suite", tls.CipherSuiteName(cs.CipherSuite)},
		{"client_cert", st.clientCert()}}
	reason := ""
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		days := daysUntil(leaf.NotAfter)
		step.Set("server_subject", leaf.Subject.String())
		step.Set("server_issuer", leaf.Issuer.String())
		step.Set("not_after", leaf.NotAfter.UTC().Format(time.RFC3339))
		step.Set("days_to_expiry", days)
		if t.WarnExpiryDays > 0 && days < t.WarnExpiryDays {
			step.Set("expiry_warning", fmt.Sprintf("server certificate expires in %d days (threshold %d)", days, t.WarnExpiryDays))
		}
		if t.MinCertDays > 0 && days < t.MinCertDays {
			reason = fmt.Sprintf("server certificate expires in %d days, minimum is %d", days, t.MinCertDays)
		}
	}
	return step, reason
}

// clientCertFailure rewrites a TLS alert into an actionable tls-stage reason.
// With TLS 1.3 the alert surfaces on the first read, after the handshake.
func clientCertFailure(err error, st *mtlsState) (string, bool) {
	if st == nil {
		return "", false
	}
	msg := err.Error()
	if !strings.Contains(msg, "remote error: tls:") {
		return "", false
	}
	alert := false
	for _, a := range []string{"certificate required", "bad certificate", "unknown certificate authority", "certificate unknown", "handshake failure", "unauthorized"} {
		alert = alert || strings.Contains(msg, a)
	}
	if !alert {
		return "", false
	}
	switch {
	case st.requested && !st.offered:
		return "server requires a client certificate and none was provided (use --cert and --key): " + msg, true
	case st.offered:
		return "server rejected the presented client certificate: " + msg, true
	}
	return "", false
}

// mtlsCheckKeys are the extra check-file keys.
var mtlsCheckKeys = []string{"cert", "key", "server_name", "min_tls", "min_cert_days", "warn_expiry_days"}

// applyCheckTLS reads the mTLS keys of one check case into o.
func applyCheckTLS(m obj, o *ProbeOptions) error {
	o.Cert, o.Key, o.ServerName = str(m, "cert", ""), str(m, "key", ""), str(m, "server_name", "")
	if v, ok := m["min_tls"]; ok {
		s, isStr := v.(string)
		if !isStr {
			return userError("min_tls must be the string \"1.2\" or \"1.3\"")
		}
		o.MinTLS = s
	}
	for k, dst := range map[string]*int{"min_cert_days": &o.MinCertDays, "warn_expiry_days": &o.WarnExpiryDays} {
		if v, ok := m[k]; ok {
			f, isNum := num(v)
			if !isNum || f != math.Trunc(f) || f < 0 {
				return userErrorf("%s must be a non-negative integer", k)
			}
			*dst = int(f)
		}
	}
	return nil
}

// tlsFacts emits evidence for the optional tls step fields of a saved report.
func tlsFacts(step map[string]any, add func(string)) {
	if _, ok := step["server_subject"]; ok {
		add(fmt.Sprintf("TLS %v with %v; server certificate subject %v issuer %v expires %v (%v days); client_cert=%v.",
			step["version"], step["cipher_suite"], step["server_subject"], step["server_issuer"], step["not_after"],
			pyNone(step["days_to_expiry"]), step["client_cert"]))
	}
	if w, ok := step["expiry_warning"]; ok {
		add("tls expiry warning: " + fmt.Sprint(w))
	}
}
