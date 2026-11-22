package setura

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// runShadow implements "setura shadow": read the built-in gateway's /shadow
// document and print it. It exits 1 when the match rate is under --fail-under.
func runShadow(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui) (int, error) {
	admin := fs.String("admin", builtin.DefaultAdmin, "gateway admin address")
	follow := fs.Bool("follow", false, "keep polling and print new mismatches")
	format := fs.String("format", "table", "table or json")
	failUnder := fs.Float64("fail-under", 0, "exit 1 when the match rate is under this percent (0 = never)")
	interval := fs.Duration("interval", 2*time.Second, "poll interval with --follow")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	bad := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura shadow: %s\n", msg)
		exampleHint(stderr, "shadow")
		return 2, usageError{msg}
	}
	switch {
	case len(pos) != 0:
		return bad("unexpected arguments")
	case *format != "table" && *format != "json":
		return bad(fmt.Sprintf("--format %q: want table or json", *format))
	case *failUnder < 0 || *failUnder > 100:
		return bad("--fail-under wants a percentage from 0 to 100")
	case *interval < 100*time.Millisecond:
		return bad("--interval must be at least 100ms")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return shadowRun(ctx, *admin, *follow, *format, *failUnder, *interval, stdout, stderr, u), nil
}

func fetchShadow(ctx context.Context, admin string) (*builtin.ShadowSummary, error) {
	base := admin
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/shadow", nil)
	if err != nil {
		return nil, err
	}
	adminToken(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the gateway admin endpoint at %s: %w", admin, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s/shadow answered %s (is this a setura gateway with shadow diffing?)", admin, resp.Status)
	}
	var sum builtin.ShadowSummary
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&sum); err != nil {
		return nil, fmt.Errorf("reading /shadow: %w", err)
	}
	return &sum, nil
}

func shadowGate(sum *builtin.ShadowSummary, failUnder float64, stderr io.Writer) int {
	if failUnder <= 0 {
		return 0
	}
	if sum.Compared == 0 || sum.MatchRate == nil {
		fmt.Fprintln(stderr, "setura shadow: no compared requests yet, cannot meet --fail-under")
		return 1
	}
	if *sum.MatchRate < failUnder {
		fmt.Fprintf(stderr, "setura shadow: match rate %.2f%% is under --fail-under %.2f%%\n", *sum.MatchRate, failUnder)
		return 1
	}
	return 0
}

func shadowRun(ctx context.Context, admin string, follow bool, format string, failUnder float64, interval time.Duration, stdout, stderr io.Writer, u *ui) int {
	sum, err := fetchShadow(ctx, admin)
	if err != nil {
		fmt.Fprintf(stderr, "setura shadow: %s\n", err)
		return 2
	}
	if format == "json" {
		writeJSON(stdout, sum)
	} else {
		writeShadowTable(stdout, u, sum, 10)
	}
	code := shadowGate(sum, failUnder, stderr)
	if !follow {
		return code
	}
	seen := map[string]bool{}
	key := func(e any) string { b, _ := json.Marshal(e); return string(b) }
	for _, e := range sum.Recent {
		seen[key(e)] = true
	}
	tk := time.NewTicker(interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return code
		case <-tk.C:
		}
		next, err := fetchShadow(ctx, admin)
		if err != nil {
			if ctx.Err() != nil {
				return code
			}
			fmt.Fprintf(stderr, "setura shadow: %s\n", err)
			continue
		}
		sum = next
		code = shadowGate(sum, failUnder, io.Discard)
		fresh := false
		for i := len(sum.Recent) - 1; i >= 0; i-- {
			e := sum.Recent[i]
			if k := key(e); !seen[k] {
				seen[k] = true
				fresh = true
				if format == "json" {
					json.NewEncoder(stdout).Encode(e)
				} else {
					fmt.Fprintln(stdout, mismatchLine(u, e.Time, e.Category, e.Method, e.Path, e.Detail.Where, e.Detail.Primary, e.Detail.Shadow))
				}
			}
		}
		if fresh && format != "json" {
			fmt.Fprintln(stdout, summaryLine(u, sum))
		}
	}
}

func summaryLine(u *ui, s *builtin.ShadowSummary) string {
	if s.Compared == 0 || s.MatchRate == nil {
		return fmt.Sprintf("%s Shadow: no compared requests yet (sampled %d, dropped %d, errors %d)", u.idleSym(), s.Sampled, s.Dropped, s.Errors)
	}
	sym := u.okSym()
	if s.Mismatched > 0 {
		sym = u.warnSym()
	}
	return fmt.Sprintf("%s Shadow: %.1f%% match over %d requests", sym, *s.MatchRate, s.Compared)
}

func mismatchLine(u *ui, when, cat, method, path, where, p, s string) string {
	t := when
	if ts, err := time.Parse(time.RFC3339, when); err == nil {
		t = ts.Local().Format("15:04:05")
	}
	return fmt.Sprintf("  %s  %s  %s %s  %s: %s %s %s", u.dim(t), u.amber(pad(cat, 7)), method, path, where, p, u.arrow(), s)
}

func writeShadowTable(w io.Writer, u *ui, s *builtin.ShadowSummary, recent int) {
	fmt.Fprintln(w, summaryLine(u, s))
	fmt.Fprintf(w, "  compared %d  sampled %d  dropped %d  skipped %d  shadow errors %d\n", s.Compared, s.Sampled, s.Dropped, s.Skipped, s.Errors)
	cats := fmt.Sprintf("status %d, header %d, body %d, latency %d",
		s.ByCategory["status"], s.ByCategory["header"], s.ByCategory["body"], s.ByCategory["latency"])
	for _, c := range sortedKeys(s.ByCategory) { // gRPC adds grpc-status and grpc-message
		switch c {
		case "status", "header", "body", "latency":
		default:
			cats += fmt.Sprintf(", %s %d", c, s.ByCategory[c])
		}
	}
	fmt.Fprintf(w, "  mismatches by category: %s\n", cats)
	if s.LastError != "" {
		fmt.Fprintf(w, "  last shadow error: %s\n", s.LastError)
	}
	if len(s.Routes) > 0 {
		fmt.Fprintf(w, "\n%s %s %s %s %s\n", pad("ROUTE", 36), pad("COMPARED", 9), pad("MATCH", 8), pad("P50 DELTA", 10), "P95 DELTA")
		for _, k := range sortedKeys(s.Routes) {
			r := s.Routes[k]
			m := "n/a"
			if r.MatchRate != nil {
				m = fmt.Sprintf("%.1f%%", *r.MatchRate)
			}
			fmt.Fprintf(w, "%s %s %s %s %s\n", pad(k, 36), pad(fmt.Sprint(r.Compared), 9), pad(m, 8), pad(fmtMS(r.P50DeltaMs), 10), fmtMS(r.P95DeltaMs))
		}
	}
	if len(s.Recent) > 0 {
		fmt.Fprintln(w, "\nRecent mismatches")
		for i, e := range s.Recent {
			if i >= recent {
				fmt.Fprintf(w, "  ... %d more in the ring (use --format json)\n", len(s.Recent)-recent)
				break
			}
			fmt.Fprintln(w, mismatchLine(u, e.Time, e.Category, e.Method, e.Path, e.Detail.Where, e.Detail.Primary, e.Detail.Shadow))
		}
	}
}
