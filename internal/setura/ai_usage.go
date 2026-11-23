package setura

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// runAIUsage is "setura gateway ai-usage": it reads /ai/usage from a running
// gateway and prints the token usage, cost estimates, cache, budgets and
// provider health of its AI routes. It exits 0, 1 when the gateway cannot be
// read and 2 on a usage error.
func runAIUsage(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gateway ai-usage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	admin := fs.String("admin", builtin.DefaultAdmin, "gateway admin address")
	token := fs.String("admin-token", os.Getenv("SETURA_ADMIN_TOKEN"), "bearer token for the admin endpoint")
	routeF := fs.String("route", "", "only this AI route (namespace/name/rule, or a part of it)")
	keyF := fs.String("key", "", "only this identity (API key name, subject, claim or header value)")
	format := fs.String("format", "auto", "auto (table on a terminal, JSON when piped), table or json")
	if _, err := parse(fs, args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "setura gateway ai-usage: %v\n", err)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "setura gateway ai-usage: unexpected arguments")
		return 2
	}
	var table bool
	switch *format {
	case "auto":
		table = isTTY(stdout)
	case "table":
		table = true
	case "json":
	default:
		fmt.Fprintf(stderr, "setura gateway ai-usage: --format must be auto, table or json, got %q\n", *format)
		return 2
	}
	target, err := adminURL(*admin, "/ai/usage")
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway ai-usage: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway ai-usage: cannot reach the gateway admin endpoint (is `setura gateway run` up, and is --admin right?): %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		fmt.Fprintf(stderr, "setura gateway ai-usage: gateway answered %s: %s\n", resp.Status, strings.TrimSpace(string(b)))
		return 1
	}
	var doc builtin.AIUsage
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&doc); err != nil {
		fmt.Fprintf(stderr, "setura gateway ai-usage: unexpected /ai/usage response: %v\n", err)
		return 1
	}
	doc = filterAIUsage(doc, *routeF, *keyF)
	if !table {
		writeJSON(stdout, doc)
		return 0
	}
	u := newUI(isTTY(stdout), termOptions{}, os.Getenv)
	fmt.Fprint(stdout, renderAIUsage(u, doc))
	return 0
}

// adminURL builds a URL on a gateway admin address.
func adminURL(admin, path string) (string, error) {
	if !strings.Contains(admin, "://") {
		admin = "http://" + admin
	}
	u, err := url.Parse(admin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", userErrorf("--admin %q: want HOST:PORT, for example %s", admin, builtin.DefaultAdmin)
	}
	u.Path = path
	return u.String(), nil
}

// filterAIUsage keeps the routes whose name contains route and, inside them,
// the identities equal to key.
func filterAIUsage(d builtin.AIUsage, route, key string) builtin.AIUsage {
	out := builtin.AIUsage{Currency: d.Currency, Routes: []builtin.AIRouteUsage{}}
	for _, r := range d.Routes {
		if route != "" && !strings.Contains(r.Route, route) {
			continue
		}
		if key != "" {
			var ks []builtin.AIKeyUsage
			for _, k := range r.Keys {
				if k.Key == key {
					ks = append(ks, k)
				}
			}
			r.Keys = ks
		}
		out.Routes = append(out.Routes, r)
	}
	return out
}

func meter(u *ui, used, max float64) string {
	const cells = 12
	frac := 0.0
	if max > 0 {
		frac = used / max
	}
	n := int(frac*cells + 0.5)
	if n > cells {
		n = cells
	}
	full, empty := u.sym("█", "#"), u.sym("░", ".")
	bar := strings.Repeat(full, n) + strings.Repeat(empty, cells-n)
	switch {
	case frac >= 1:
		bar = u.red(bar)
	case frac >= 0.8:
		bar = u.amber(bar)
	default:
		bar = u.green(bar)
	}
	return fmt.Sprintf("%s %3.0f%%", bar, frac*100)
}

func humanDur(sec int) string {
	switch {
	case sec >= 86400:
		return fmt.Sprintf("%dd%dh", sec/86400, sec%86400/3600)
	case sec >= 3600:
		return fmt.Sprintf("%dh%dm", sec/3600, sec%3600/60)
	case sec >= 60:
		return fmt.Sprintf("%dm%ds", sec/60, sec%60)
	}
	return fmt.Sprintf("%ds", sec)
}

func fmtCost(c float64, cur string) string {
	if cur == "" {
		return fmt.Sprintf("%.4f", c)
	}
	return fmt.Sprintf("%.4f %s", c, cur)
}

// renderAIUsage prints the usage document as tables.
func renderAIUsage(u *ui, d builtin.AIUsage) string {
	var b strings.Builder
	if len(d.Routes) == 0 {
		return "No AI routes (a rule needs a setura.zyvor.dev/ai block, see docs/ai-gateway.md).\n"
	}
	for i, r := range d.Routes {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "%s  %s\n", u.bold(r.Route), u.gray(fmt.Sprintf("%d requests, %d tokens in, %d out, cost estimate %s", r.Requests, r.TokensIn, r.TokensOut, fmtCost(r.CostEstimate, d.Currency))))
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  "+"PROVIDER"+"\t"+"STATE"+"\t"+"PRIORITY"+"\t"+"WEIGHT"+"\t"+"ATTEMPTS"+"\t"+"FAILED"+"\t"+"TOKENS IN"+"\t"+"TOKENS OUT"+"\t"+"COST")
		for _, p := range r.Providers {
			st := p.State
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", p.Name, st, p.Priority, p.Weight, p.Attempts, p.Failures, p.TokensIn, p.TokensOut, fmtCost(p.Cost, ""))
		}
		tw.Flush()
		if c := r.Cache; c != nil {
			rate := 0.0
			if c.Hits+c.Misses > 0 {
				rate = 100 * float64(c.Hits) / float64(c.Hits+c.Misses)
			}
			fmt.Fprintf(&b, "  cache: %d hits, %d misses (%.0f%% hit rate), %d entries, %d evicted\n", c.Hits, c.Misses, rate, c.Entries, c.Evicted)
		}
		if len(r.Denied) > 0 {
			var parts []string
			for _, k := range sortedKeys(r.Denied) {
				parts = append(parts, fmt.Sprintf("%s %d", k, r.Denied[k]))
			}
			fmt.Fprintf(&b, "  refused by budget: %s\n", strings.Join(parts, ", "))
		}
		if len(r.PII) > 0 {
			var parts []string
			for _, k := range sortedKeys(r.PII) {
				parts = append(parts, fmt.Sprintf("%s %d", k, r.PII[k]))
			}
			fmt.Fprintf(&b, "  prompt PII findings (rule/action): %s\n", strings.Join(parts, ", "))
		}
		if len(r.Keys) > 0 {
			b.WriteString("\n")
			sort.SliceStable(r.Keys, func(i, j int) bool {
				return r.Keys[i].TokensIn+r.Keys[i].TokensOut > r.Keys[j].TokensIn+r.Keys[j].TokensOut
			})
			tw = tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "  "+"IDENTITY"+"\t"+"REQUESTS"+"\t"+"TOKENS IN"+"\t"+"TOKENS OUT"+"\t"+"COST"+"\t"+"BUDGET")
			for _, k := range r.Keys {
				if len(k.Budget) == 0 {
					fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\t%s\t\n", k.Key, k.Requests, k.TokensIn, k.TokensOut, fmtCost(k.Cost, ""))
					continue
				}
				for j, w := range k.Budget {
					lead := fmt.Sprintf("  %s\t%d\t%d\t%d\t%s", k.Key, k.Requests, k.TokensIn, k.TokensOut, fmtCost(k.Cost, ""))
					if j > 0 {
						lead = "  \t\t\t\t"
					}
					fmt.Fprintf(tw, "%s\t%-17s %s %s of %s, resets in %s\n", lead, w.Limit, meter(u, w.Used, w.Max), trimNum(w.Used), trimNum(w.Max), humanDur(w.ResetsInSec))
				}
			}
			tw.Flush()
		}
	}
	return b.String()
}

func trimNum(f float64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", f), "0"), ".")
}
