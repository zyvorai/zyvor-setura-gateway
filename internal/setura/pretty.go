package setura

import (
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// Terminal rendering layer. Everything here is stdlib-only and affects human
// output exclusively; JSON paths never touch it.

type colorDepth int

const (
	colorNone colorDepth = iota
	color256
	colorTrue
)

// Brand palette: 24-bit RGB with a 256-color fallback index.
type swatch struct {
	r, g, b uint8
	idx     int
}

var (
	palBlue  = swatch{0x29, 0x97, 0xff, 75}
	palGreen = swatch{0x30, 0xd1, 0x58, 41}
	palRed   = swatch{0xff, 0x45, 0x3a, 203}
	palAmber = swatch{0xff, 0xd6, 0x0a, 220}
	palGray  = swatch{0x86, 0x86, 0x8b, 245}
)

// termOptions are the global flags and environment that shape rendering.
type termOptions struct {
	Color string // auto, always, never
	ASCII bool
}

// ui renders styled text for one output stream.
type ui struct {
	depth colorDepth
	ascii bool
}

// isTTY reports whether w is a character device.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// newUI resolves the rendering mode. getenv is injectable for tests.
func newUI(tty bool, o termOptions, getenv func(string) string) *ui {
	term := getenv("TERM")
	u := &ui{ascii: o.ASCII || term == "dumb"}
	enabled := false
	switch o.Color {
	case "always":
		enabled = true
	case "never":
	default:
		enabled = tty && getenv("NO_COLOR") == "" && term != "dumb"
	}
	if enabled {
		u.depth = color256
		if ct := getenv("COLORTERM"); ct == "truecolor" || ct == "24bit" {
			u.depth = colorTrue
		}
	}
	return u
}

func (u *ui) paint(s swatch, text string) string {
	switch u.depth {
	case colorTrue:
		return fmt.Sprintf("\x1b[38;2;%d;%d;%dm%s\x1b[0m", s.r, s.g, s.b, text)
	case color256:
		return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", s.idx, text)
	}
	return text
}

func (u *ui) sgr(code, text string) string {
	if u.depth == colorNone {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (u *ui) blue(s string) string  { return u.paint(palBlue, s) }
func (u *ui) green(s string) string { return u.paint(palGreen, s) }
func (u *ui) red(s string) string   { return u.paint(palRed, s) }
func (u *ui) amber(s string) string { return u.paint(palAmber, s) }
func (u *ui) gray(s string) string  { return u.paint(palGray, s) }
func (u *ui) bold(s string) string  { return u.sgr("1", s) }
func (u *ui) dim(s string) string   { return u.sgr("2", s) }

func (u *ui) sym(unicode, ascii string) string {
	if u.ascii {
		return ascii
	}
	return unicode
}

func (u *ui) okSym() string   { return u.green(u.sym("✓", "+")) }
func (u *ui) failSym() string { return u.red(u.sym("✗", "x")) }
func (u *ui) warnSym() string { return u.amber(u.sym("▲", "!")) }
func (u *ui) skipSym() string { return u.gray(u.sym("–", "-")) }
func (u *ui) idleSym() string { return u.gray(u.sym("·", ".")) }
func (u *ui) arrow() string   { return u.blue(u.sym("→", "->")) }

// pad left-aligns s in width cells before styling is applied.
func pad(s string, n int) string {
	if l := len([]rune(s)); l < n {
		return s + strings.Repeat(" ", n-l)
	}
	return s
}

func fmtMS(ms float64) string {
	if ms < 10 {
		return fmt.Sprintf("%.1f ms", ms)
	}
	return fmt.Sprintf("%.0f ms", math.Round(ms))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// stepSymbol picks the symbol for a probe stage state.
func (u *ui) stepSymbol(state string) string {
	switch state {
	case "ok", "overridden":
		return u.okSym()
	case "failed":
		return u.failSym()
	case "unused":
		return u.skipSym()
	}
	return u.idleSym()
}

func stepDetail(step Step) string {
	if step.State() == "failed" {
		if r := step.Get("reason"); r != nil {
			return pyFormat(r)
		}
	}
	var parts []string
	for _, p := range step[1:] {
		parts = append(parts, fmt.Sprintf("%s=%s", p.K, pyFormat(p.V)))
	}
	return strings.Join(parts, " ")
}

// ExplainPretty renders one probe as a header, stage rows and a verdict.
func (u *ui) ExplainPretty(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s\n\n", u.bold(r.URL))
	failedStage := ""
	for _, name := range stages {
		step := r.Step(name)
		state := step.State()
		if state == "failed" && failedStage == "" {
			failedStage = name
		}
		stateText := pad(state, 10)
		switch state {
		case "failed":
			stateText = u.red(stateText)
		case "ok", "overridden":
			stateText = u.green(stateText)
		default:
			stateText = u.gray(stateText)
		}
		line := fmt.Sprintf("  %s %s %s", u.stepSymbol(state), u.bold(pad(name, 8)), stateText)
		if d := stepDetail(step); d != "" {
			line += " " + u.gray(d)
		}
		fmt.Fprintln(&b, strings.TrimRight(line, " "))
	}
	b.WriteString("\n")
	if r.OK {
		fmt.Fprintf(&b, "  %s %s %s\n", u.okSym(), u.bold("Passed"), u.gray("in "+fmtMS(r.ElapsedMS)))
	} else {
		at := ""
		if failedStage != "" {
			at = " at " + failedStage
		}
		fmt.Fprintf(&b, "  %s %s %s\n", u.failSym(), u.bold("Failed"+at), u.gray("in "+fmtMS(r.ElapsedMS)))
		if h := hints[failedStage]; h != "" {
			fmt.Fprintf(&b, "  %s %s\n", u.blue("Next:"), h)
		}
	}
	b.WriteString("\n")
	return b.String()
}

// LintPretty renders lint findings grouped by resource.
func (u *ui) LintPretty(report obj) string {
	var b strings.Builder
	var current string
	first := true
	for _, f := range asList(report["findings"]) {
		m := asMap(f)
		res := asStr(m["resource"])
		if first || res != current {
			fmt.Fprintf(&b, "\n  %s\n", u.bold(res))
			current, first = res, false
		}
		sym := u.warnSym()
		if m["severity"] == SeverityError {
			sym = u.failSym()
		}
		fmt.Fprintf(&b, "    %s %s  %s\n", sym, u.dim(asStr(m["id"])), m["message"])
	}
	e, _ := num(report["errors"])
	w, _ := num(report["warnings"])
	b.WriteString("\n")
	switch {
	case e == 0 && w == 0:
		fmt.Fprintf(&b, "  %s %s\n", u.okSym(), u.bold("No findings"))
	case e == 0:
		fmt.Fprintf(&b, "  %s %s\n", u.warnSym(), u.bold(plural(int(w), "warning", "warnings")))
	default:
		fmt.Fprintf(&b, "  %s %s, %s\n", u.failSym(), u.bold(plural(int(e), "error", "errors")), plural(int(w), "warning", "warnings"))
	}
	b.WriteString("\n")
	return b.String()
}

func failureOf(r *Report) string {
	for _, name := range stages {
		if s := r.Step(name); s.State() == "failed" {
			d := name
			if reason := s.Get("reason"); reason != nil {
				d += ": " + fmt.Sprint(reason)
			}
			return d
		}
	}
	return ""
}

// CheckPretty renders check cases as a table.
func (u *ui) CheckPretty(rows []*Report) string {
	var b strings.Builder
	w := 0
	for _, r := range rows {
		if l := len([]rune(r.URL)); l > w {
			w = l
		}
	}
	b.WriteString("\n")
	failed := 0
	for _, r := range rows {
		sym, state := u.okSym(), u.green(pad("pass", 5))
		if !r.OK {
			failed++
			sym, state = u.failSym(), u.red(pad("fail", 5))
		}
		line := fmt.Sprintf("  %s %s %s %s", sym, u.bold(pad(r.URL, w)), state, u.gray(fmt.Sprintf("%10s", fmtMS(r.ElapsedMS))))
		if f := failureOf(r); f != "" {
			line += "  " + u.gray(f)
		}
		fmt.Fprintln(&b, line)
	}
	b.WriteString("\n")
	if failed == 0 {
		fmt.Fprintf(&b, "  %s %s\n", u.okSym(), u.bold(fmt.Sprintf("%s passed", plural(len(rows), "case", "cases"))))
	} else {
		fmt.Fprintf(&b, "  %s %s %s\n", u.failSym(), u.bold(fmt.Sprintf("%d of %s failed", failed, plural(len(rows), "case", "cases"))),
			u.gray(fmt.Sprintf("(%d passed)", len(rows)-failed)))
	}
	b.WriteString("\n")
	return b.String()
}

// ComparePretty renders one row per target.
func (u *ui) ComparePretty(url string, targets []string, res obj) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s\n\n", u.bold(url))
	results := asMap(res["targets"])
	w := 0
	for _, t := range targets {
		if len(t) > w {
			w = len(t)
		}
	}
	seen := map[string]bool{}
	for _, t := range targets {
		r, ok := results[t].(*Report)
		if !ok || seen[t] {
			continue
		}
		seen[t] = true
		sym, verdict := u.okSym(), u.green(pad("ok", 5))
		if !r.OK {
			sym, verdict = u.failSym(), u.red(pad("fail", 5))
		}
		line := fmt.Sprintf("  %s %s %s %s", sym, u.bold(pad(t, w)), verdict, u.gray(fmt.Sprintf("%10s", fmtMS(r.ElapsedMS))))
		if f := failureOf(r); f != "" {
			line += "  " + u.gray(f)
		}
		fmt.Fprintln(&b, line)
	}
	b.WriteString("\n")
	if res["ok"] == true {
		fmt.Fprintf(&b, "  %s %s\n", u.okSym(), u.bold("All targets agree"))
	} else {
		fmt.Fprintf(&b, "  %s %s\n", u.failSym(), u.bold("At least one target failed"))
	}
	b.WriteString("\n")
	return b.String()
}

// GatePretty renders the attempt history and the verdict.
func (u *ui) GatePretty(route string, streak int, res obj) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n  %s\n\n", u.bold("Gate "+route))
	for _, a := range asList(res["attempts"]) {
		m := asMap(a)
		parent := asMap(m["parent"])
		n, _ := num(m["attempt"])
		s, _ := num(m["streak"])
		parentSym := u.failSym()
		if parent["ok"] == true {
			parentSym = u.okSym()
		}
		probeSym, ms := u.skipSym(), ""
		if r, ok := m["probe"].(*Report); ok {
			probeSym = u.failSym()
			if r.OK {
				probeSym = u.okSym()
			}
			ms = fmtMS(r.ElapsedMS)
		}
		line := fmt.Sprintf("  %s %s  parent %s  probe %s  streak %d/%d", u.gray(u.sym("•", "*")), pad(fmt.Sprintf("attempt %d", int(n)), 10), parentSym, probeSym, int(s), streak)
		if ms != "" {
			line += "  " + u.gray(ms)
		}
		if parent["ok"] != true {
			if reason := asStr(parent["reason"]); reason != "" {
				line += "  " + u.gray(reason)
			}
		}
		fmt.Fprintln(&b, line)
	}
	b.WriteString("\n")
	if res["ok"] == true {
		fmt.Fprintf(&b, "  %s %s\n", u.okSym(), u.bold("Gate passed"))
	} else {
		fmt.Fprintf(&b, "  %s %s\n", u.failSym(), u.bold("Gate failed"))
		fmt.Fprintf(&b, "  %s %s\n", u.blue("Next:"), "Inspect the route with: setura inspect "+route)
	}
	b.WriteString("\n")
	return b.String()
}

// DoctorPretty renders permission checks as a checklist.
func (u *ui) DoctorPretty(res obj) string {
	var b strings.Builder
	b.WriteString("\n")
	denied := 0
	for _, c := range asList(res["checks"]) {
		m := asMap(c)
		state := asStr(m["state"])
		sym := u.okSym()
		switch state {
		case "denied":
			sym = u.failSym()
			denied++
		case "unknown":
			sym = u.warnSym()
			denied++
		}
		what := asStr(m["verb"]) + " " + asStr(m["resource"])
		if sub := asStr(m["subresource"]); sub != "" {
			what += "/" + sub
		}
		line := fmt.Sprintf("  %s %s %s", sym, pad(what, 38), u.gray(pad(asStr(m["namespace"]), 24)))
		if state != "allowed" {
			line += " " + state
		}
		fmt.Fprintln(&b, strings.TrimRight(line, " "))
	}
	b.WriteString("\n")
	if denied == 0 {
		fmt.Fprintf(&b, "  %s %s\n", u.okSym(), u.bold("Everything setura needs is allowed"))
	} else {
		fmt.Fprintf(&b, "  %s %s\n", u.failSym(), u.bold(plural(denied, "permission", "permissions")+" missing or unknown"))
		fmt.Fprintf(&b, "  %s %s\n", u.blue("Next:"), "Ask a cluster admin to grant the denied verbs, then rerun setura doctor.")
	}
	b.WriteString("\n")
	return b.String()
}

// extractTermFlags removes --color and --ascii from args wherever they appear
// (they are global) and returns the resulting options.
func extractTermFlags(args []string) ([]string, termOptions, error) {
	o := termOptions{Color: "auto"}
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return append(rest, args[i:]...), o, validColor(o)
		case a == "--ascii" || a == "-ascii":
			o.ASCII = true
		case a == "--color" || a == "-color":
			if i+1 >= len(args) {
				return nil, o, userError("--color needs a value: auto, always or never")
			}
			i++
			o.Color = args[i]
		case strings.HasPrefix(a, "--color="):
			o.Color = strings.TrimPrefix(a, "--color=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, o, validColor(o)
}

func validColor(o termOptions) error {
	switch o.Color {
	case "auto", "always", "never":
		return nil
	}
	return userErrorf("--color must be auto, always or never, got %q", o.Color)
}

// wantPretty resolves a --format auto|pretty|json flag for a command whose
// default is JSON when piped and pretty on a terminal.
func wantPretty(format string, tty bool) (bool, error) {
	switch format {
	case "auto":
		return tty, nil
	case "pretty":
		return true, nil
	case "json":
		return false, nil
	}
	return false, userErrorf("--format must be auto, pretty or json, got %q", format)
}
