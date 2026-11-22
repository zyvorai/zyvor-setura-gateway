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
	req, err := builtin.ParseExplainRequest(method, target, headers, *grpc, *sni)
	if err != nil {
		return usage(err.Error())
	}

	var tr *builtin.Trace
	if *admin != "" {
		tr, err = whyRemote(*admin, method, target, headers, *grpc, *sni)
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
func whyRemote(addr, method, target string, headers []string, grpc, sni string) (*builtin.Trace, error) {
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
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(strings.TrimRight(base, "/") + "/why?" + q.Encode())
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
