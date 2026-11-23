package setura

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// runUsage implements "setura usage" and "setura usage invoice": it reads the
// built-in gateway's /usage endpoint (and /plans for prices) and prints it.
func runUsage(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui) (int, error) {
	admin := fs.String("admin", builtin.DefaultAdmin, "gateway admin address")
	format := fs.String("format", "table", "table, json or csv")
	since := fs.String("since", "", "first day to count: a duration (24h, 7d), a day (2026-11-01) or an RFC 3339 time; usage is kept per UTC day")
	until := fs.String("until", "", "last day to count, same forms as --since")
	by := fs.String("by", "key", "group by key, route, plan or day (comma separated to combine)")
	identity := fs.String("identity", "", "only this identity, for example apikey:acme; a trailing * matches a prefix")
	route := fs.String("route", "", "only this route (namespace/name); a trailing * matches a prefix")
	plan := fs.String("plan", "", "only this plan")
	period := fs.String("period", "", "calendar month YYYY-MM (instead of --since/--until); required by invoice")
	plans := fs.String("plans", "", "invoice: read plan prices from this plan file instead of the gateway's /plans")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	bad := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura usage: %s\n", msg)
		exampleHint(stderr, "usage")
		return 2, usageError{msg}
	}
	invoice := false
	switch {
	case len(pos) == 1 && pos[0] == "invoice":
		invoice = true
	case len(pos) != 0:
		return bad("unexpected arguments (the only subcommand is invoice)")
	}
	switch *format {
	case "table", "json", "csv":
	default:
		return bad(fmt.Sprintf("--format %q: want table, json or csv", *format))
	}
	if _, err := builtin.NormalizeBy([]string{*by}); err != nil {
		return bad(err.Error())
	}
	if *period != "" {
		if _, _, err := builtin.PeriodDays(*period); err != nil {
			return bad(err.Error())
		}
		if *since != "" || *until != "" {
			return bad("--period replaces --since and --until; give one or the other")
		}
	}
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("since", *since)
	set("until", *until)
	set("period", *period)
	set("identity", *identity)
	set("route", *route)
	set("plan", *plan)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if invoice {
		if *period == "" {
			return bad("invoice needs --period YYYY-MM, for example --period 2026-11")
		}
		q.Set("by", "key,plan")
		var rep builtin.UsageReport
		if err := adminJSON(ctx, *admin, "/usage?"+q.Encode(), &rep); err != nil {
			fmt.Fprintf(stderr, "setura usage: %v\n", err)
			return 2, nil
		}
		prices, err := invoicePlans(ctx, *admin, *plans)
		if err != nil {
			fmt.Fprintf(stderr, "setura usage: %v\n", err)
			return 2, nil
		}
		inv := builtin.BuildInvoice(*period, rep, prices, time.Now())
		return 0, writeInvoice(stdout, u, inv, *format)
	}
	q["by"] = []string{*by}
	var rep builtin.UsageReport
	if err := adminJSON(ctx, *admin, "/usage?"+q.Encode(), &rep); err != nil {
		fmt.Fprintf(stderr, "setura usage: %v\n", err)
		return 2, nil
	}
	switch *format {
	case "json":
		return 0, writeJSON(stdout, rep)
	case "csv":
		return 0, builtin.UsageCSV(stdout, rep)
	}
	writeUsageTable(stdout, u, rep)
	return 0, nil
}

func adminJSON(ctx context.Context, admin, path string, v any) error {
	base := admin
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return err
	}
	adminToken(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the gateway admin endpoint at %s: %w", admin, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s%s answered %s: %s", admin, strings.SplitN(path, "?", 2)[0], resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("reading %s: %w", strings.SplitN(path, "?", 2)[0], err)
	}
	return nil
}

func invoicePlans(ctx context.Context, admin, file string) (map[string]*builtin.Plan, error) {
	if file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		ps, err := builtin.ParsePlans(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		return ps.File.Plans, nil
	}
	var doc builtin.PlansDoc
	if err := adminJSON(ctx, admin, "/plans", &doc); err != nil {
		return nil, err
	}
	return doc.Plans, nil
}

func fmtCount(n int64) string { return strconv.FormatInt(n, 10) }

func writeUsageTable(w io.Writer, u *ui, rep builtin.UsageReport) {
	has := map[string]bool{}
	for _, b := range rep.By {
		has[b] = true
	}
	var head []string
	for _, c := range []string{"day", "identity", "route", "plan"} {
		if has[c] {
			head = append(head, strings.ToUpper(c))
		}
	}
	head = append(head, "REQUESTS", "BILLABLE", "BLOCKED", "OVER", "2XX", "4XX", "5XX", "IN", "OUT", "AVG MS")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	line := func(r builtin.UsageRow, label string) string {
		var cols []string
		if label != "" {
			cols = append(cols, label)
			for i := 1; i < len(rep.By); i++ {
				cols = append(cols, "")
			}
		} else {
			for _, c := range []string{"day", "identity", "route", "plan"} {
				if !has[c] {
					continue
				}
				v := map[string]string{"day": r.Day, "identity": r.Identity, "route": r.Route, "plan": r.Plan}[c]
				cols = append(cols, v)
			}
		}
		cols = append(cols, fmtCount(r.Requests), fmtCount(r.Billable), fmtCount(r.Blocked), fmtCount(r.OverQuota), fmtCount(r.Status2xx),
			fmtCount(r.Status4xx), fmtCount(r.Status5xx), fmtBytes(float64(r.BytesIn)), fmtBytes(float64(r.BytesOut)), fmt.Sprintf("%.1f", r.LatencyMsAvg))
		return strings.Join(cols, "\t")
	}
	for _, r := range rep.Rows {
		fmt.Fprintln(tw, line(r, ""))
	}
	if len(rep.Rows) > 1 {
		fmt.Fprintln(tw, line(rep.Totals, "TOTAL"))
	}
	tw.Flush()
	if len(rep.Rows) == 0 {
		fmt.Fprintln(w, u.gray("no usage recorded for this selection"))
	}
	if rep.Overflow > 0 {
		fmt.Fprintf(w, "%s\n", u.amber(fmt.Sprintf("%d observation(s) were folded into _overflow: the series cap (%d) was reached", rep.Overflow, rep.MaxSeries)))
	}
}

func writeInvoice(w io.Writer, u *ui, inv builtin.Invoice, format string) error {
	switch format {
	case "json":
		return writeJSON(w, inv)
	case "csv":
		cw := csv.NewWriter(w)
		cw.Write([]string{"period", "identity", "plan", "requests", "billable_requests", "included_requests", "chargeable_requests", "blocked", "over_quota", "bytes", "price_per_1k", "currency", "amount"})
		for _, l := range inv.Lines {
			cw.Write([]string{inv.Period, csvCell(l.Identity), l.Plan, fmtCount(l.Requests), fmtCount(l.Billable), fmtCount(l.Included), fmtCount(l.Chargeable),
				fmtCount(l.Blocked), fmtCount(l.OverQuota), fmtCount(l.BytesTotal), strconv.FormatFloat(l.Price1k, 'f', -1, 64), l.Currency, strconv.FormatFloat(l.Amount, 'f', 2, 64)})
		}
		cw.Flush()
		return cw.Error()
	}
	fmt.Fprintf(w, "%s  %s\n\n", u.bold("Invoice summary"), inv.Period)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IDENTITY\tPLAN\tBILLABLE\tINCLUDED\tCHARGEABLE\tPER 1K\tAMOUNT")
	for _, l := range inv.Lines {
		price, amount := "-", "-"
		if l.Currency != "" {
			price = fmt.Sprintf("%s %s", strconv.FormatFloat(l.Price1k, 'f', -1, 64), l.Currency)
			amount = fmt.Sprintf("%.2f %s", l.Amount, l.Currency)
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%s\t%s\n", l.Identity, l.Plan, l.Billable, l.Included, l.Chargeable, price, amount)
	}
	tw.Flush()
	for _, c := range sortedKeys(inv.Totals) {
		fmt.Fprintf(w, "\n%s  %.2f %s\n", u.bold("Total"), inv.Totals[c], c)
	}
	for _, n := range inv.Notes {
		fmt.Fprintln(w, u.gray(n))
	}
	return nil
}

// csvCell defuses spreadsheet formulas in values that come from credentials.
func csvCell(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
