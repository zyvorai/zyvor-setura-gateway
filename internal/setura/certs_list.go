package setura

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
	Target     string `json:"target"`
	Status     string `json:"status"` // ok, expiring, unverified or error
	DaysLeft   *int   `json:"days_left,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Verified   bool   `json:"verified"`
	Detail     string `json:"detail,omitempty"`
	soonestDay int
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
	sort.SliceStable(rows, func(a, b int) bool {
		ea, eb := rows[a].Status == "error", rows[b].Status == "error"
		if ea != eb {
			return ea
		}
		return rows[a].soonestDay < rows[b].soonestDay
	})
	rep := &CertListReport{OK: true, Targets: rows}
	for _, r := range rows {
		rep.OK = rep.OK && r.Status == "ok"
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
	fmt.Fprintf(&b, "%-*s  %-10s  %5s  %s\n", w, "TARGET", "STATUS", "DAYS", "DETAIL")
	for _, t := range r.Targets {
		days := "-"
		if t.DaysLeft != nil {
			days = fmt.Sprint(*t.DaysLeft)
		}
		detail := t.Detail
		if detail == "" {
			detail = t.Subject
		}
		fmt.Fprintf(&b, "%-*s  %-10s  %5s  %s\n", w, t.Target, strings.ToUpper(t.Status), days, detail)
	}
	bad := 0
	for _, t := range r.Targets {
		if t.Status != "ok" {
			bad++
		}
	}
	if bad == 0 {
		fmt.Fprintf(&b, "all %d certificates ok\n", len(r.Targets))
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
