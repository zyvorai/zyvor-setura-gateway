package setura

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"flag"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// runWhy implements "setura why": explain which listener, route and rule
// the built-in gateway picks for one request, by walking its real matching code
// on a config file or snapshot, or by asking a running gateway's /why endpoint.
// Exit codes: 0 routed, 1 no route (explained), 2 usage error.
func runWhy(fs *flag.FlagSet, rest []string, stdout, stderr io.Writer, u *ui) (int, error) {
	cfgPath := fs.String("config", "", "gateway config (setura.route-specs/v1 snapshot with backends) to evaluate")
	snapPath := fs.String("snapshot", "", "snapshot file (from `setura snapshot`) to evaluate")
	admin := fs.String("admin", "", "ask the running gateway at ADDR (its admin endpoint, e.g. 127.0.0.1:19000) instead of reading a file")
	format := fs.String("format", "pretty", "pretty or json")
	grpc := fs.String("grpc", "", "explain a gRPC call to service/method (HTTP/2, application/grpc)")
	sni := fs.String("sni", "", "explain a TLS passthrough connection with this server name (TLSRoute)")
	clientIP := fs.String("client-ip", "", "client address for X-Forwarded-For and the rate-limit key (default: shown as <client-ip>)")
	rateLimit := fs.String("rate-limit", "", "model the gateway's --rate-limit (N/s, N/m, N/h); offline only")
	rateBurst := fs.Int("rate-burst", 0, "model the gateway's --rate-burst; offline only")
	rateKey := fs.String("rate-key", "ip", "model the gateway's --rate-key: ip, route or header:NAME; offline only")
	shadowDiff := fs.Int("shadow-diff", 0, "model the gateway's --shadow-diff default sample percent; offline only")
	var headers stringList
	fs.Var(&headers, "H", `request header, "Name: value"; repeatable`)
	fs.Var(&headers, "header", `request header, "Name: value"; repeatable`)
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	usage := func(msg string) (int, error) {
		fmt.Fprintf(stderr, "setura why: %s\n", msg)
		exampleHint(stderr, "why")
		return 2, usageError{msg}
	}
	var method, target string
	switch len(pos) {
	case 2:
		method, target = pos[0], pos[1]
	case 1:
		method, target = "GET", pos[0]
	default:
		return usage("expected METHOD URL")
	}
	sources := 0
	for _, s := range []string{*cfgPath, *snapPath, *admin} {
		if s != "" {
			sources++
		}
	}
	if sources != 1 {
		return usage("give exactly one of --config FILE, --snapshot FILE or --admin ADDR")
	}
	if *format != "pretty" && *format != "json" {
		return usage("--format must be pretty or json")
	}
	pretty := *format == "pretty"
	var policy builtin.ExplainServer
	if *rateLimit != "" {
		if *admin != "" {
			return usage("--rate-limit, --rate-burst, --rate-key and --shadow-diff model a gateway offline; --admin already reports the running gateway's policy")
		}
		rate, per, err := builtin.ParseRate(*rateLimit)
		if err != nil {
			return usage("--rate-limit: " + err.Error())
		}
		policy.RateLimit = builtin.RateLimitConfig{Rate: rate, Per: per, Burst: *rateBurst, Key: *rateKey}
	}
	if *shadowDiff < 0 || *shadowDiff > 100 {
		return usage("--shadow-diff must be 0-100")
	}
	policy.ShadowDiff = *shadowDiff
	req, err := builtin.ParseExplainRequest(method, target, headers, *grpc, *sni)
	if err != nil {
		return usage(err.Error())
	}

	var tr *builtin.Trace
	if *admin != "" {
		tr, err = whyRemote(*admin, method, target, headers, *grpc, *sni, *clientIP)
		if err != nil {
			return 0, err
		}
	} else {
		path := *cfgPath
		if path == "" {
			path = *snapPath
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return 0, err
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return 0, err
		}
		cfg, err := builtin.ParseConfig(raw, filepath.Dir(abs))
		if err != nil {
			return 0, userErrorf("%s: %v", path, err)
		}
		req.Remote, req.Server = *clientIP, policy
		tr = builtin.Explain(builtin.BuildTable(cfg), req)
	}
	if !pretty {
		if err := writeJSON(stdout, tr); err != nil {
			return 0, err
		}
	} else {
		fmt.Fprint(stdout, u.WhyPretty(tr, *admin != "", whyWidth()))
	}
	if tr.Verdict == builtin.VerdictRouted || tr.Verdict == builtin.VerdictRedirect {
		return 0, nil
	}
	return 1, nil
}

func whyWidth() int { return 100 }

// whyRemote asks a running gateway's admin /why endpoint.
func whyRemote(addr, method, target string, headers []string, grpc, sni, client string) (*builtin.Trace, error) {
	base := addr
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	q := url.Values{}
	q.Set("method", method)
	q.Set("url", target)
	for _, h := range headers {
		q.Add("header", h)
	}
	if grpc != "" {
		q.Set("grpc", grpc)
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if client != "" {
		q.Set("client", client)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(base, "/")+"/why?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	adminToken(req)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, userErrorf("gateway admin answered %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr builtin.Trace
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("gateway admin sent an unreadable trace: %w", err)
	}
	return &tr, nil
}

// wrap breaks text into lines of at most width cells, each after indent.
func wrap(text string, indent string, width int) []string {
	avail := width - len([]rune(indent))
	if avail < 30 {
		avail = 30
	}
	var lines []string
	cur := ""
	for _, w := range strings.Fields(text) {
		switch {
		case cur == "":
			cur = w
		case len([]rune(cur))+1+len([]rune(w)) > avail:
			lines = append(lines, indent+cur)
			cur = w
		default:
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, indent+cur)
	}
	return lines
}

// WhyPretty renders a trace for the terminal.
func (u *ui) WhyPretty(tr *builtin.Trace, remote bool, width int) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	section := func(title string) { w("\n  %s\n", u.blue(title)) }
	note := func(indent, text string) {
		for _, ln := range wrap(text, indent, width) {
			w("%s\n", u.gray(ln))
		}
	}
	q := tr.Request
	desc := q.Method + " " + q.Scheme + "://" + q.Host + q.Path
	if q.RawQuery != "" {
		desc += "?" + q.RawQuery
	}
	switch {
	case q.GRPC != "":
		desc = "gRPC " + q.GRPC + " @ " + q.Scheme + "://" + q.Host
	case q.SNI != "":
		desc = "TLS server name " + q.SNI + " on port " + fmt.Sprint(q.Port)
	}
	w("\n  %s %s\n", u.bold("setura why"), u.bold(desc))
	for _, k := range sortedKeys(headerMap(q.Header)) {
		w("    %s\n", u.gray(k+": "+strings.Join(q.Header.Values(k), ", ")))
	}

	section("Listeners")
	for _, l := range tr.Listeners {
		sym := u.idleSym()
		switch l.Verdict {
		case "chosen":
			sym = u.okSym()
		case "lost":
			sym = u.warnSym()
		}
		host := l.Hostname
		if host == "" {
			host = "*"
		}
		w("    %s %s %s\n", sym, u.bold(l.Listener), u.gray(fmt.Sprintf("%s %s :%d", l.Protocol, host, l.Port)))
		note("        ", l.Reason)
	}

	if len(tr.Routes) > 0 {
		section("Routes on the chosen listener")
		for _, r := range tr.Routes {
			sym := u.failSym()
			if r.Attached {
				sym = u.okSym()
			}
			created := ""
			if r.Created != "" {
				created = " created " + r.Created
			}
			w("    %s %s %s\n", sym, u.bold(r.Route), u.gray(r.Kind+created))
			if !r.Attached {
				note("        ", r.Reason)
			}
		}
	}

	if len(tr.Candidates) > 0 {
		section(fmt.Sprintf("Rules considered (%d)", len(tr.Candidates)))
		for _, c := range tr.Candidates {
			sym := u.failSym()
			switch c.Verdict {
			case "winner":
				sym = u.okSym()
			case "lost":
				sym = u.warnSym()
			}
			head := fmt.Sprintf("%s rule %d match %d", c.Route, c.Rule, c.Match)
			w("    %s %s  %s\n", sym, u.bold(head), u.gray(c.Summary))
			note("        ", c.Reason)
		}
	}

	if win := tr.Winner; win != nil {
		section("Winner")
		w("    %s %s %s\n", u.okSym(), u.bold(fmt.Sprintf("%s rule %d", win.Route, win.Rule)), u.gray(win.Summary))
		if len(win.Filters) > 0 {
			section("Filters applied")
			for _, f := range win.Filters {
				w("    %s %s %s\n", u.arrow(), u.bold(f.Type), u.gray("("+f.Scope+")"))
				note("        ", f.Effect)
			}
		}
		for _, m := range win.Mirrors {
			w("    %s %s\n", u.arrow(), m)
		}
		if win.Timeout != "" {
			w("    %s request timeout %s\n", u.arrow(), win.Timeout)
		}
		if win.BackendTimeout != "" {
			w("    %s backend request timeout %s\n", u.arrow(), win.BackendTimeout)
		}
		if win.RuleName != "" {
			w("    %s rule name %s\n", u.arrow(), win.RuleName)
		}
		if win.Session != "" {
			w("    %s %s\n", u.arrow(), win.Session)
		}
		if len(win.Preflight) > 0 {
			section("CORS preflight answered by the gateway")
			for _, k := range sortedKeys(win.Preflight) {
				w("    %s %s\n", u.gray(k+":"), win.Preflight[k])
			}
		}
		if len(win.ResponseHeaders) > 0 {
			section("Headers the gateway adds to the response")
			for _, k := range sortedKeys(win.ResponseHeaders) {
				w("    %s %s\n", u.gray(k+":"), win.ResponseHeaders[k])
			}
		}
		u.whyPolicy(&b, win, width)
		if win.Redirect != nil {
			section("Redirect")
			w("    %s %s %s %s\n", u.arrow(), u.bold(fmt.Sprint(win.Redirect.Status)), u.gray("Location"), win.Redirect.Location)
		}
		if len(win.Backends) > 0 {
			title := "Backends"
			if win.Passthru {
				title = "Backends (TLS is passed through untouched)"
			}
			section(title)
			for _, be := range win.Backends {
				u.backendRow(&b, be, width)
			}
			if !remote && !hasKnownHealth(win.Backends) {
				w("    %s\n", u.gray("endpoint health is unknown for a static config; run with --admin to include ejected and unhealthy endpoints"))
			}
		}
		for _, be := range win.Backends {
			if be.Request == nil {
				continue
			}
			if len(be.ResponseHeaders) > 0 && len(win.Backends) > 1 {
				w("    %s %s adds to the response: ", u.arrow(), be.Name)
				for _, k := range sortedKeys(be.ResponseHeaders) {
					w("%s: %s; ", k, be.ResponseHeaders[k])
				}
				w("\n")
			}
			if be.BackendTLS != "" {
				w("    %s %s: %s\n", u.arrow(), be.Name, be.BackendTLS)
			}
			section("Upstream request via " + be.Name)
			up := be.Request
			w("    %s %s\n", u.bold(up.Method), u.bold(up.URL))
			w("    %s %s\n", u.gray("Host:"), up.Host)
			for _, k := range sortedKeys(up.Headers) {
				w("    %s %s\n", u.gray(k+":"), up.Headers[k])
			}
		}
	}

	w("\n")
	switch tr.Verdict {
	case builtin.VerdictRouted:
		w("  %s %s\n", u.okSym(), u.bold("Routed"))
	case builtin.VerdictRedirect:
		w("  %s %s\n", u.okSym(), u.bold("Redirected"))
	default:
		w("  %s %s\n", u.failSym(), u.bold("No route: "+tr.Verdict))
	}
	note("    ", tr.Reason)
	w("\n")
	return b.String()
}

func hasKnownHealth(bs []builtin.TraceBackend) bool {
	for _, b := range bs {
		for _, e := range b.Endpoints {
			if e.State != "unknown" {
				return true
			}
		}
	}
	return len(bs) == 0
}

func headerMap(h http.Header) map[string]struct{} {
	out := map[string]struct{}{}
	for k := range h {
		out[k] = struct{}{}
	}
	return out
}

// backendRow draws one weighted backendRef with a percentage bar.
func (u *ui) backendRow(b *strings.Builder, be builtin.TraceBackend, width int) {
	const cells = 20
	filled := int(be.Percent/100*cells + 0.5)
	full, empty := u.sym("█", "#"), u.sym("░", "-")
	bar := strings.Repeat(full, filled) + strings.Repeat(empty, cells-filled)
	label := fmt.Sprintf("%5.1f%%", be.Percent)
	name := be.Name
	switch be.Status {
	case "ok":
		fmt.Fprintf(b, "    %s %s  %s  %s\n", u.green(bar), u.bold(label), u.bold(name), u.gray(fmt.Sprintf("weight %d", be.Weight)))
	case "excluded":
		fmt.Fprintf(b, "    %s %s  %s  %s\n", u.gray(strings.Repeat(empty, cells)), u.gray(label), u.gray(name), u.gray(fmt.Sprintf("weight %d, excluded", be.Weight)))
	default:
		fmt.Fprintf(b, "    %s %s  %s  %s\n", u.amber(bar), u.amber(label), u.bold(name), u.amber(be.Status))
	}
	if be.Reason != "" {
		for _, ln := range wrap(be.Reason, "        ", width) {
			fmt.Fprintln(b, u.gray(ln))
		}
	}
	for _, e := range be.Endpoints {
		sym := u.okSym()
		switch e.State {
		case "unhealthy", "ejected":
			sym = u.failSym()
		case "unknown":
			sym = u.idleSym()
		}
		fmt.Fprintf(b, "        %s %s %s\n", sym, e.URL, u.gray(e.State))
	}
}

// whyPolicy prints the rate limit, retry policy and notes of the winner.
func (u *ui) whyPolicy(b *strings.Builder, win *builtin.TraceWinner, width int) {
	if a := win.Auth; a != nil && a.Applies {
		verdict := u.green("admitted")
		switch a.Decision {
		case "deny":
			verdict = u.red(fmt.Sprintf("refused with %d", a.Status))
		case "unknown":
			verdict = u.gray("undetermined here")
		}
		fmt.Fprintf(b, "    %s auth: %s\n", u.arrow(), a.Policy)
		by := ""
		if a.Method != "" && a.Method != "none" {
			by = " by " + a.Method
			if a.Subject != "" {
				by += " as " + a.Subject
			}
		}
		fmt.Fprintf(b, "        this request would be %s%s\n", verdict, by)
		for _, ln := range wrap(a.Reason, "        ", width) {
			fmt.Fprintln(b, u.gray(ln))
		}
		for _, c := range a.Challenge {
			fmt.Fprintln(b, u.gray("        WWW-Authenticate: "+c))
		}
		if len(a.Headers) > 0 {
			fmt.Fprintln(b, u.gray("        headers set for the backend: "+strings.Join(a.Headers, ", ")))
		}
	}
	if a := win.AI; a != nil {
		u.whyAI(b, a, width)
	}
	if rl := win.RateLimit; rl != nil {
		switch {
		case !rl.Enabled:
			fmt.Fprintf(b, "    %s rate limit: none\n", u.arrow())
		default:
			fmt.Fprintf(b, "    %s rate limit %s, bucket %s\n", u.arrow(), rl.Policy, rl.Bucket)
			if rl.Live && rl.Tokens != nil {
				verdict := u.green("admitted")
				if rl.Limited != nil && *rl.Limited {
					verdict = u.red("refused with 429")
				}
				fmt.Fprintf(b, "        live bucket holds %.1f tokens: this request would be %s\n", *rl.Tokens, verdict)
			}
		}
		if rl.Note != "" {
			for _, ln := range wrap(rl.Note, "        ", width) {
				fmt.Fprintln(b, u.gray(ln))
			}
		}
	}
	if rt := win.Retry; rt != nil {
		codes := "connection errors only"
		if len(rt.Codes) > 0 {
			parts := make([]string, len(rt.Codes))
			for i, c := range rt.Codes {
				parts[i] = fmt.Sprint(c)
			}
			codes = "status " + strings.Join(parts, ", ") + " and connection errors"
		}
		fmt.Fprintf(b, "    %s retry up to %d time(s) after %s backoff on %s\n", u.arrow(), rt.Attempts, rt.Backoff, codes)
		if !rt.Idempotent {
			fmt.Fprintf(b, "        %s\n", u.gray("this method is not idempotent: only a failed connection is retried, not a status code"))
		}
		for _, ln := range wrap(rt.Budget, "        ", width) {
			fmt.Fprintln(b, u.gray(ln))
		}
	}
	for _, n := range win.Notes {
		for _, ln := range wrap(n, "    ", width) {
			fmt.Fprintln(b, u.gray(ln))
		}
	}
}

// whyAI prints the AI gateway explanation: the provider a request goes to and
// why, what happens when it fails, and the policies in force.
func (u *ui) whyAI(b *strings.Builder, a *builtin.TraceAI, width int) {
	api := a.API
	if api == "" {
		api = "AI"
	}
	fmt.Fprintf(b, "    %s AI route (%s API)\n", u.arrow(), api)
	for _, ln := range wrap(a.Why, "        ", width) {
		fmt.Fprintln(b, ln)
	}
	for _, p := range a.Providers {
		line := fmt.Sprintf("%s  %s  priority %d, weight %d", p.Name, p.Type, p.Priority, p.Weight)
		if p.Percent > 0 {
			line += fmt.Sprintf(", %.0f%% of first choices", p.Percent)
		}
		sym := u.okSym()
		switch {
		case p.Role == "excluded":
			sym, line = u.idleSym(), u.gray(line+" (excluded: "+p.Reason+")")
		case p.State != "healthy":
			sym = u.failSym()
			line += " " + u.red(p.State)
			if p.Until != "" {
				line += u.gray(" until " + p.Until)
			}
		}
		fmt.Fprintf(b, "        %s %s\n", sym, line)
		fmt.Fprintln(b, u.gray("            key: "+p.Key))
	}
	if len(a.Failover) > 0 {
		fmt.Fprintln(b, u.gray("        failover order after the first choice: "+strings.Join(a.Failover, ", ")))
	}
	if a.Credentials != "" {
		for _, ln := range wrap(a.Credentials, "        ", width) {
			fmt.Fprintln(b, u.gray(ln))
		}
	}
	if a.Identity != "" {
		fmt.Fprintln(b, u.gray("        identity: "+a.Identity))
	}
	for _, x := range a.Budget {
		for _, ln := range wrap(x, "        ", width) {
			fmt.Fprintln(b, u.gray(ln))
		}
	}
	for _, w := range a.Usage {
		fmt.Fprintf(b, "        %s %s of %s used now, resets in %s\n", w.Limit, trimNum(w.Used), trimNum(w.Max), humanDur(w.ResetsInSec))
	}
	for _, x := range []string{a.Cache, a.PII} {
		if x != "" {
			for _, ln := range wrap(x, "        ", width) {
				fmt.Fprintln(b, u.gray(ln))
			}
		}
	}
	for _, n := range a.Notes {
		for _, ln := range wrap(n, "        ", width) {
			fmt.Fprintln(b, u.gray(ln))
		}
	}
}
