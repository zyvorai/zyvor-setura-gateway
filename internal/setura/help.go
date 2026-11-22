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
		{"why", "METHOD URL [--config F|--admin ADDR]", "explain why the built-in gateway routes a request the way it does"},
		{"bench", "URL", "repeat probes and report latency percentiles and budgets"},
		{"load", "URL", "keep-alive load generator: requests/s, p50/p90/p99/p99.9, errors, gateway goroutines and memory"},
		{"grpc-health", "HOST:PORT", "call grpc.health.v1.Health/Check over TLS (HTTP/2)"},
	}},
	{"Inspect", []helpEntry{
		{"inspect", "ROUTE", "show route conditions and backend inventory"},
		{"listeners", "GATEWAY", "show listener attachment and conditions"},
		{"certs", "HOST:PORT", "show and verify the presented TLS certificate chain"},
		{"snapshot", "", "capture Gateway and HTTPRoute specs"},
		{"map", "", "render the declared route topology"},
		{"ui", "[--listen ADDR]", "live read-only web dashboard: route map, lint, traffic, feed"},
		{"connections", "[--admin ADDR] [--follow]", "who connected to which listener, over what protocol, and where the gateway sent it"},
		{"impact", "TARGET", "query what a resource change would affect"},
	}},
	{"Analyze", []helpEntry{
		{"lint", "", "statically analyze specs (offline)"},
		{"diff", "BEFORE AFTER", "compare two snapshots"},
		{"migrate", "check [--ingress F] [--routes F] [--services F] [--objects F] [--ingress-class C]", "compare Ingress rules with their converted HTTPRoute, GRPCRoute and TLSRoute rules"},
		{"replay", "--log F --before OLD --after NEW", "replay an access log through two gateway configs and report the routing impact"},
		{"ai", "REPORT [--model NAME]", "explain saved evidence, optionally with local Ollama"},
	}},
	{"Publish", []helpEntry{
		{"gateway", "run|up|install|rollout|history|rollback", "built-in Gateway API data plane, no Envoy needed; guarded config rollout"},
		{"shadow", "[--admin ADDR] [--follow] [--fail-under PCT]", "compare mirrored HTTP and gRPC responses with the primary (built-in gateway /shadow); exit 1 under the threshold"},
		{"publish", "GATEWAY --listener NAME", "forward an Envoy Gateway listener to IPv4 loopback"},
	}},
	{"Utilities", []helpEntry{
		{"doctor", "", "check permissions needed by setura"},
		{"capabilities", "", "list GatewayClasses and controller features"},
		{"exposure", "", "show Service exposure"},
		{"completion", "bash|zsh|fish", "print a shell completion script"},
		{"echo", "--name NAME", "run a tiny identity backend that answers with X-Setura-Backend"},
		{"licence", "verify [KEY|--file F] | show", "verify a signed ZYV1 licence key offline (exit 0 valid, 1 invalid)"},
		{"man", "", "print the manual page (roff)"},
		{"version", "[--verbose]", "print the version and build info"},
	}},
}

// cmdExamples are shown in per-command help and after usage errors.
var cmdExamples = map[string][]string{
	"publish": {"setura publish dev --listener http --port 8080"},
	"explain": {"setura explain https://orders.example.test/checkout --address 127.0.0.1 --backend orders-v1"},
	"why": {"setura why GET https://orders.example.test/api/v1 -H 'x-canary: 1' --config gateway.json",
		"setura why POST http://x.test:8080/ --admin 127.0.0.1:19000 --format json",
		"setura why GET http://x.test:8080 --grpc helloworld.Greeter/SayHello --config gateway.json",
		"setura why GET tls://db.secure.test:8443 --sni db.secure.test --config gateway.json",
		"setura why GET http://x.test:8080/ --config gateway.json --rate-limit 100/s --rate-key route --client-ip 10.1.2.3"},
	"check":     {"setura check examples/checks.json --junit results.xml", "setura check examples/checks.json --context prod-eu,prod-us"},
	"inspect":   {"setura inspect orders -n demo"},
	"listeners": {"setura listeners dev -n demo"},
	"gateway":   {"setura gateway rollout --config live.json --new candidate.json --checks checks.json [--steps 10,50,100|--no-steps] [--max-error-rate 0.01 --max-p95 300ms]", "setura gateway run --config routes.json --shadow-diff 10 --shadow-state shadow.json", "setura gateway history --config live.json", "setura gateway rollback --config live.json"},
	"gate":      {"setura gate orders http://127.0.0.1:8080/ --gateway dev --backend orders-v2 -n demo"},
	"compare":   {"setura compare https://orders.example.test/ --target dns --target 10.0.0.5"},
	"snapshot":  {"setura snapshot -n demo > before.json", "setura --context prod-eu,prod-us snapshot -n demo"},
	"diff":      {"setura diff before.json after.json"},
	"map":       {"setura map -n demo > map.html"},
	"impact":    {"setura impact Service/demo/orders --snapshot before.json"},
	"lint":      {"setura lint --snapshot before.json --strict", "setura lint --all-contexts -n demo --format json"},
	"shadow":    {"setura shadow --admin 127.0.0.1:19000 --fail-under 99.5", "setura gateway run --config routes.json --shadow-diff 10"},
	"history":   {"setura history probes.jsonl --since 24h --route orders", "setura watch https://orders.example.test/ --history probes.jsonl --alert-slack \"$SLACK_URL\""},
	"watch":     {"setura watch https://orders.example.test/ --history probes.jsonl --alert-slack \"$SLACK_URL\" --alert-cooldown 5m"},
	"doctor":    {"setura doctor -n demo"},
	"replay": {"setura replay --log access.jsonl --before old.json --after new.json",
		"zcat access.jsonl.gz | setura replay --log - --before old.json --after new.json --fail-on any --format github",
		"setura replay --log /var/log/nginx/access.log --default-host shop.example.test --before old.json --after new.json --fail-on route,policy"},
	"migrate": {"setura migrate check --ingress ingress.yaml --routes routes.yaml --services services.yaml --objects objects.yaml",
		"setura migrate check -n shop --ingress-class nginx",
		"setura migrate check -n shop --ingress-url http://10.0.0.1 --gateway-url http://10.0.0.2 --format github",
		"setura migrate check --ingress-url http://10.0.0.1 --gateway-url http://10.0.0.2 --probe-extra"},
	"ai":          {"setura ai report.json --model llama3"},
	"connections": {"setura connections", "setura connections --follow --filter status=5xx --filter route=orders", "setura connections --admin 127.0.0.1:19000 --format json | jq '.history[0]'"},
	"ui":          {"setura ui --snapshot before.json", "setura ui --kube -n demo --listen 127.0.0.1:9090"},
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
