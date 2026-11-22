package setura

import (
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
)

type helpEntry struct{ name, args, summary string }

type helpGroup struct {
	title   string
	entries []helpEntry
}

// helpGroups drives the top-level help screen. Add new commands here.
var helpGroups = []helpGroup{
	{"Verify", []helpEntry{
		{"explain", "URL", "probe a URL from this host, stage by stage"},
		{"check", "FILE [--context a,b]", "run a JSON file of route assertions"},
		{"gate", "ROUTE URL [--context a,b]", "require current parent status and a probe streak"},
		{"compare", "URL --target dns|IP", "probe the same URL via DNS and/or IPs"},
		{"watch", "URL... [--file FILE]", "re-probe on an interval; metrics, --history, --alert-webhook/--alert-slack"},
		{"history", "FILE [--since 24h]", "summarize watch history: uptime, p50/p95, last failure, regressions"},
		{"bench", "URL", "repeat probes and report latency percentiles and budgets"},
		{"grpc-health", "HOST:PORT", "call grpc.health.v1.Health/Check over TLS (HTTP/2)"},
	}},
	{"Inspect", []helpEntry{
		{"inspect", "ROUTE", "show route conditions and backend inventory"},
		{"listeners", "GATEWAY", "show listener attachment and conditions"},
		{"certs", "HOST:PORT", "show and verify the presented TLS certificate chain"},
		{"snapshot", "", "capture Gateway and HTTPRoute specs"},
		{"map", "", "render the declared route topology"},
		{"impact", "TARGET", "query what a resource change would affect"},
	}},
	{"Analyze", []helpEntry{
		{"lint", "", "statically analyze specs (offline)"},
		{"diff", "BEFORE AFTER", "compare two snapshots"},
		{"migrate", "check [--ingress F] [--routes F] [--services F] [--ingress-class C]", "compare Ingress rules with their converted HTTPRoute, GRPCRoute and TLSRoute rules"},
		{"ai", "REPORT [--model NAME]", "explain saved evidence, optionally with local Ollama"},
	}},
	{"Publish", []helpEntry{
		{"gateway", "run|up|install", "built-in Gateway API data plane, no Envoy needed"},
		{"publish", "GATEWAY --listener NAME", "forward an Envoy Gateway listener to IPv4 loopback"},
	}},
	{"Utilities", []helpEntry{
		{"doctor", "", "check permissions needed by setura"},
		{"capabilities", "", "list GatewayClasses and controller features"},
		{"exposure", "", "show Service exposure"},
		{"completion", "bash|zsh|fish", "print a shell completion script"},
		{"echo", "--name NAME", "run a tiny identity backend that answers with X-Setura-Backend"},
		{"man", "", "print the manual page (roff)"},
		{"version", "[--verbose]", "print the version and build info"},
	}},
}

// cmdExamples are shown in per-command help and after usage errors.
var cmdExamples = map[string][]string{
	"publish":   {"setura publish dev --listener http --port 8080"},
	"explain":   {"setura explain https://orders.example.test/checkout --address 127.0.0.1 --backend orders-v1"},
	"check":     {"setura check examples/checks.json --junit results.xml", "setura check examples/checks.json --context prod-eu,prod-us"},
	"inspect":   {"setura inspect orders -n demo"},
	"listeners": {"setura listeners dev -n demo"},
	"gate":      {"setura gate orders http://127.0.0.1:8080/ --gateway dev --backend orders-v2 -n demo"},
	"compare":   {"setura compare https://orders.example.test/ --target dns --target 10.0.0.5"},
	"snapshot":  {"setura snapshot -n demo > before.json", "setura --context prod-eu,prod-us snapshot -n demo"},
	"diff":      {"setura diff before.json after.json"},
	"map":       {"setura map -n demo > map.html"},
	"impact":    {"setura impact Service/demo/orders --snapshot before.json"},
	"lint":      {"setura lint --snapshot before.json --strict", "setura lint --all-contexts -n demo --format json"},
	"history":   {"setura history probes.jsonl --since 24h --route orders", "setura watch https://orders.example.test/ --history probes.jsonl --alert-slack \"$SLACK_URL\""},
	"watch":     {"setura watch https://orders.example.test/ --history probes.jsonl --alert-slack \"$SLACK_URL\" --alert-cooldown 5m"},
	"doctor":    {"setura doctor -n demo"},
	"migrate": {"setura migrate check --ingress ingress.yaml --routes routes.yaml --services services.yaml",
		"setura migrate check -n shop --ingress-class nginx",
		"setura migrate check -n shop --ingress-url http://10.0.0.1 --gateway-url http://10.0.0.2 --format github",
		"setura migrate check --ingress-url http://10.0.0.1 --gateway-url http://10.0.0.2 --probe-extra"},
	"ai": {"setura ai report.json --model llama3"},
}

func writeHelp(w io.Writer, u *ui) {
	fmt.Fprintf(w, "\n  %s  serve, publish and verify Gateway API routes\n\n", u.bold("setura"))
	fmt.Fprintf(w, "  %s  setura [--context NAME[,NAME...] | --all-contexts] [--color auto|always|never] [--ascii] COMMAND [flags]\n", u.gray("Usage"))
	for _, g := range helpGroups {
		fmt.Fprintf(w, "\n  %s\n", u.blue(g.title))
		for _, e := range g.entries {
			name := e.name
			if e.args != "" {
				name += " " + e.args
			}
			fmt.Fprintf(w, "    %s  %s\n", pad(name, 34), u.gray(e.summary))
		}
	}
	fmt.Fprintf(w, "\n  %s\n", u.blue("Examples"))
	for _, c := range []string{"explain", "check", "lint"} {
		fmt.Fprintf(w, "    %s\n", cmdExamples[c][0])
	}
	fmt.Fprintf(w, "\n  Run %s for a command's flags.\n\n", u.bold("setura COMMAND -h"))
}

// commandSummary finds a command's one-line description.
func commandSummary(cmd string) (helpEntry, bool) {
	for _, g := range helpGroups {
		for _, e := range g.entries {
			if e.name == cmd {
				return e, true
			}
		}
	}
	return helpEntry{}, false
}

// setCommandUsage installs per-command help on a FlagSet.
func setCommandUsage(fs *flag.FlagSet, cmd string, u *ui) {
	fs.Usage = func() {
		w := fs.Output()
		e, _ := commandSummary(cmd)
		fmt.Fprintf(w, "\n  %s %s\n", u.bold("setura "+cmd), u.gray(e.args))
		if e.summary != "" {
			fmt.Fprintf(w, "  %s\n", u.gray(e.summary))
		}
		fmt.Fprintf(w, "\n  %s\n", u.blue("Flags"))
		fs.PrintDefaults()
		if ex := cmdExamples[cmd]; len(ex) > 0 {
			fmt.Fprintf(w, "\n  %s\n", u.blue("Examples"))
			for _, x := range ex {
				fmt.Fprintf(w, "    %s\n", x)
			}
		}
		fmt.Fprintln(w)
	}
}

// exampleHint prints an example for cmd, if known.
func exampleHint(w io.Writer, cmd string) {
	if ex := cmdExamples[cmd]; len(ex) > 0 {
		fmt.Fprintf(w, "  Example: %s\n", ex[0])
	}
}

// nearest suggests the closest known command by edit distance.
func nearest(cmd string, names []string) string {
	best, bestD := "", 1<<30
	for _, n := range names {
		if d := levenshtein(cmd, n); d < bestD {
			best, bestD = n, d
		}
	}
	if bestD <= 2 || bestD <= len(cmd)/3 {
		return best
	}
	return ""
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

// unknownCommand writes the unknown-command error with a suggestion.
func unknownCommand(w io.Writer, cmd string) {
	fmt.Fprintf(w, "setura: unknown command %q\n", cmd)
	if s := nearest(cmd, commandNames); s != "" {
		fmt.Fprintf(w, "  Did you mean %q?\n", s)
	}
	fmt.Fprintln(w, `  Run "setura --help" for the list of commands.`)
}

// versionVerbose prints build information from runtime/debug.
func versionVerbose(w io.Writer, u *ui) {
	rows := [][2]string{{"version", Version}, {"go", runtime.Version()}, {"platform", runtime.GOOS + "/" + runtime.GOARCH}}
	if bi, ok := debug.ReadBuildInfo(); ok {
		rows = append(rows, [2]string{"module", bi.Main.Path})
		settings := map[string]string{}
		for _, s := range bi.Settings {
			settings[s.Key] = s.Value
		}
		keys := []string{"vcs.revision", "vcs.time", "vcs.modified", "CGO_ENABLED"}
		for _, k := range keys {
			if v, ok := settings[k]; ok {
				rows = append(rows, [2]string{strings.TrimPrefix(k, "vcs."), v})
			}
		}
	}
	fmt.Fprintf(w, "setura %s\n", Version)
	for _, r := range rows[1:] {
		fmt.Fprintf(w, "  %s %s\n", u.gray(pad(r[0], 12)), r[1])
	}
}
