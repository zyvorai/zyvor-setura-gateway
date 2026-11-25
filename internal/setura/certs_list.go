package setura

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

// List mode for "setura certs": many endpoints, one verdict, soonest expiry
// first. It is meant for a nightly job or a pre-release gate that has to
// answer "which of our certificates run out next?".

const (
	maxCertTargets   = 500
	certListParallel = 8
)

// CertRow is one endpoint of a list run.
type CertRow struct {
	Target   string `json:"target"`
	Status   string `json:"status"` // ok, expiring, unverified or error
	DaysLeft *int   `json:"days_left,omitempty"`
	NotAfter string `json:"not_after,omitempty"`
	Subject  string `json:"subject,omitempty"`
	Issuer   string `json:"issuer,omitempty"`
	Verified bool   `json:"verified"`
	Detail   string `json:"detail,omitempty"`
	// Domain is set by --domain-expiry.
	Domain     *DomainRow `json:"domain,omitempty"`
	soonestDay int
}

// bad reports whether the certificate or the domain needs attention.
func (r CertRow) bad() bool {
	return r.Status != "ok" || r.Domain != nil && (r.Domain.Status == domainExpiring || r.Domain.Status == domainUnknown)
}

// CertListReport is the whole run.
type CertListReport struct {
	OK      bool      `json:"ok"`
	Targets []CertRow `json:"targets"`
}

// readCertTargets reads HOST:PORT lines (blank lines and # comments are
// skipped; "-" reads stdin).
func readCertTargets(path string, stdin io.Reader) ([]string, error) {
	var r io.Reader = stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	var out []string
	sc := bufio.NewScanner(io.LimitReader(r, 1<<20))
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// CertList inspects every target (a few at a time) and sorts the result by
// days left, soonest first, with errors on top.
func CertList(targets []string, base CertsOptions) (*CertListReport, error) {
	return certList(targets, base, nil)
}

// certList is CertList, optionally adding each target's domain expiry; the
// sort then uses whichever of certificate and domain runs out first.
func certList(targets []string, base CertsOptions, domains *DomainOptions) (*CertListReport, error) {
	if domains != nil {
		if err := domains.validate(); err != nil {
			return nil, err
		}
	}
	seen := map[string]bool{}
	var uniq []string
	for _, t := range targets {
		if !seen[t] {
			seen[t] = true
			uniq = append(uniq, t)
		}
	}
	if len(uniq) == 0 {
		return nil, userError("no certificate targets given")
	}
	if len(uniq) > maxCertTargets {
		return nil, userErrorf("at most %d targets are allowed", maxCertTargets)
	}
	for _, t := range uniq {
		o := base
		o.Address = t
		if err := o.preflight(); err != nil {
			return nil, userErrorf("target %q: %v", t, err)
		}
	}
	rows := make([]CertRow, len(uniq))
	sem := make(chan struct{}, certListParallel)
	var wg sync.WaitGroup
	for i, t := range uniq {
		wg.Add(1)
		go func(i int, t string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			o := base
			o.Address = t
			rep, err := Certs(o)
			rows[i] = certRow(t, rep, err, base.WarnExpiryDays)
		}(i, t)
	}
	wg.Wait()
	if domains != nil {
		// One at a time: registries rate limit, and answers are cached by name.
		rdap := newRDAPClient(*domains)
		for i := range rows {
			host, _, _ := net.SplitHostPort(rows[i].Target)
			if net.ParseIP(host) != nil && base.SNI != "" {
				host = base.SNI
			}
			d := rdap.Lookup(host)
			rows[i].Domain = &d
			if d.DaysLeft != nil && *d.DaysLeft < rows[i].soonestDay {
				rows[i].soonestDay = *d.DaysLeft
			}
		}
	}
	sort.SliceStable(rows, func(a, b int) bool {
		ea, eb := rows[a].Status == "error", rows[b].Status == "error"
		if ea != eb {
			return ea
		}
		return rows[a].soonestDay < rows[b].soonestDay
	})
	rep := &CertListReport{OK: true, Targets: rows}
	for _, r := range rows {
		rep.OK = rep.OK && !r.bad()
	}
	return rep, nil
}

func certRow(target string, rep *CertsReport, err error, warn int) CertRow {
	if err != nil {
		return CertRow{Target: target, Status: "error", Detail: clipStr(err.Error(), 200), soonestDay: -1 << 30}
	}
	row := CertRow{Target: target, Verified: rep.Verified}
	if len(rep.Chain) > 0 {
		min := rep.Chain[0].DaysToExpiry
		for _, c := range rep.Chain {
			if c.DaysToExpiry < min {
				min = c.DaysToExpiry
			}
		}
		row.DaysLeft, row.soonestDay = &min, min
		row.NotAfter, row.Subject, row.Issuer = rep.Chain[0].NotAfter, rep.Chain[0].Subject, rep.Chain[0].Issuer
	}
	switch {
	case !rep.Verified:
		row.Status, row.Detail = "unverified", clipStr(rep.VerifyError, 200)
	case rep.Expiring:
		row.Status = "expiring"
		row.Detail = fmt.Sprintf("a certificate in the chain expires in under %d days", warn)
	default:
		row.Status = "ok"
	}
	return row
}

// Text renders the list for terminals.
func (r *CertListReport) Text() string {
	var b strings.Builder
	w := len("TARGET")
	for _, t := range r.Targets {
		if len(t.Target) > w {
			w = len(t.Target)
		}
	}
	domains := len(r.Targets) > 0 && r.Targets[0].Domain != nil
	dw := len("DOMAIN")
	for _, t := range r.Targets {
		if t.Domain != nil && len(t.Domain.Name) > dw {
			dw = len(t.Domain.Name)
		}
	}
	extra := ""
	if domains {
		extra = fmt.Sprintf("%-*s  %-8s  %5s  ", dw, "DOMAIN", "DOMSTATE", "DAYS")
	}
	fmt.Fprintf(&b, "%-*s  %-10s  %5s  %s%s\n", w, "TARGET", "STATUS", "DAYS", extra, "DETAIL")
	for _, t := range r.Targets {
		days := "-"
		if t.DaysLeft != nil {
			days = fmt.Sprint(*t.DaysLeft)
		}
		detail := t.Detail
		if detail == "" {
			detail = t.Subject
		}
		if d := t.Domain; d != nil {
			dn, dd := d.Name, "-"
			if dn == "" {
				dn = "-"
			}
			if d.DaysLeft != nil {
				dd = fmt.Sprint(*d.DaysLeft)
			}
			extra = fmt.Sprintf("%-*s  %-8s  %5s  ", dw, dn, strings.ToUpper(d.Status), dd)
			if d.Status == domainExpiring || d.Status == domainUnknown {
				note := "domain: " + d.Detail
				if t.Detail != "" {
					note = t.Detail + "; " + note
				}
				detail = note
			}
		}
		fmt.Fprintf(&b, "%-*s  %-10s  %5s  %s%s\n", w, t.Target, strings.ToUpper(t.Status), days, extra, detail)
	}
	bad := 0
	for _, t := range r.Targets {
		if t.bad() {
			bad++
		}
	}
	if bad == 0 {
		what := "certificates ok"
		if domains {
			what = "targets ok (certificate and domain)"
		}
		fmt.Fprintf(&b, "all %d %s\n", len(r.Targets), what)
	} else {
		fmt.Fprintf(&b, "%d of %d need attention\n", bad, len(r.Targets))
	}
	return b.String()
}

func (r *CertListReport) writeJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
