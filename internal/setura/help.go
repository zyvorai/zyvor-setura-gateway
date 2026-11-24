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
		{"history", "FILE [--since 24h] [--slo]", "summarize watch history: uptime, p50/p95, last failure, regressions; --slo for burn rates"},
		{"slo", "[--history FILE|--admin ADDR] [--config F]", "availability and latency SLO burn rates (multi-window) from probes or the gateway's metrics"},
		{"why", "METHOD URL [--config F|--admin ADDR]", "explain why the built-in gateway routes a request the way it does"},
		{"bench", "URL", "repeat probes and report latency percentiles and budgets"},
		{"split", "URL --expect NAME=WEIGHT...", "send requests and check the observed backend split against the expected weights (canary verification)"},
		{"cors", "URL --origin O [--request-method M]", "send a CORS preflight and judge the answer against the Fetch rules"},
		{"load", "URL", "keep-alive load generator: requests/s, p50/p90/p99/p99.9, errors, gateway goroutines and memory"},
		{"grpc-health", "HOST:PORT", "call grpc.health.v1.Health/Check over TLS (HTTP/2)"},
	}},
	{"Inspect", []helpEntry{
		{"inspect", "ROUTE", "show route conditions and backend inventory"},
		{"listeners", "GATEWAY", "show listener attachment and conditions"},
		{"certs", "HOST:PORT... [--file F]", "show and verify the presented TLS certificate chain; several targets give an expiry-sorted table"},
		{"snapshot", "", "capture Gateway and HTTPRoute specs"},
		{"map", "", "render the declared route topology"},
		{"ui", "[--listen ADDR]", "live read-only web dashboard: route map, lint, traffic, feed"},
		{"connections", "[--admin ADDR] [--follow]", "who connected to which listener, over what protocol, and where the gateway sent it"},
		{"top", "[--admin ADDR] [--once]", "live terminal view of requests/s, errors, p50/p95, ejected endpoints and connections"},
		{"impact", "TARGET", "query what a resource change would affect"},
	}},
	{"Analyze", []helpEntry{
		{"lint", "", "statically analyze specs (offline)"},
		{"diff", "BEFORE AFTER", "compare two snapshots"},
		{"migrate", "check [--ingress F] [--routes F] ... | convert [--from SRC] [PATH...] [--out DIR]", "compare Ingress rules with their converted routes (check); turn Ingress, Envoy Gateway, Traefik or nginx.conf into Gateway API YAML (convert)"},
		{"replay", "--log F --before OLD --after NEW", "replay an access log through two gateway configs and report the routing impact"},
		{"pr-check", "--base OLD --head NEW --traffic LOG", "what share of recorded traffic a config change re-routes, per route, with 404/403/429 and redirect changes; table, JSON or PR-comment Markdown; --fail-if-changed-over PCT for CI"},
		{"ai", "REPORT [--model NAME]", "explain saved evidence, optionally with local Ollama"},
	}},
	{"Publish", []helpEntry{
		{"gateway", "run|up|install|status|rollout|history|rollback|ai-usage", "built-in Gateway API data plane, no Envoy needed; guarded config rollout; AI gateway routes (providers, token budgets, cache, PII) and `gateway ai-usage`"},
		{"shadow", "[--admin ADDR] [--follow] [--fail-under PCT]", "compare mirrored HTTP and gRPC responses with the primary (built-in gateway /shadow); exit 1 under the threshold"},
		{"chaos", "run --plan F | stop | status [--admin ADDR]", "game-day fault injection (latency, abort, reset, truncate, throttle) with a safety guard on the gateway's own SLO signals; every fault expires, `chaos stop` kills them all"},
		{"usage", "[invoice --period YYYY-MM] [--by key|route|plan] [--since 7d]", "API usage per key, route or plan from the gateway's metering (table, JSON or CSV); invoice prices a month from the plan prices"},
		{"contract", "learn|show|export|diff [--learned F|--admin ADDR] [--spec openapi.json]", "learn which endpoints the gateway serves; export an OpenAPI 3.1 document; find shadow, zombie and drifting APIs and auth gaps against a real spec (--fail-on for CI)"},
		{"init", "[--route host=upstream | --openapi FILE]", "scaffold a gateway config and checks.json from host=upstream pairs or an OpenAPI JSON file"},
		{"publish", "GATEWAY --listener NAME", "forward an Envoy Gateway listener to IPv4 loopback"},
	}},
	{"Utilities", []helpEntry{
		{"doctor", "[gateway]", "check permissions needed by setura; `doctor gateway` checks a gateway config, ports, certificates and backends (--kube adds CRDs and Gateway status)"},
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
	"gateway":   {"setura gateway rollout --config live.json --new candidate.json --checks checks.json [--steps 10,50,100|--no-steps] [--max-error-rate 0.01 --max-p95 300ms]", "setura gateway run --config routes.json --shadow-diff 10 --shadow-state shadow.json", "setura gateway history --config live.json", "setura gateway rollback --config live.json", "setura gateway install --service-type NodePort --node-port HTTP=30080,HTTPS=30443 --listener-port 7443 | kubectl apply -f -", "setura gateway install --check", "setura gateway install --envoy-compat | kubectl apply -f -", "setura gateway status -A", "setura gateway ai-usage --admin 127.0.0.1:19000 --route shop/llm"},
	"gate":      {"setura gate orders http://127.0.0.1:8080/ --gateway dev --backend orders-v2 -n demo"},
	"split":     {"setura split http://orders.test:8080/ --address 127.0.0.1 --expect orders-v1=90 --expect orders-v2=10 --requests 400", "setura split https://shop.test/ --request-header 'X-Canary: always' --expect v2=1"},
	"cors":      {"setura cors https://api.example.test/v1/items --origin https://app.example.test --request-method PUT --request-headers content-type,x-token --credentials"},
	"compare":   {"setura compare https://orders.example.test/ --target dns --target 10.0.0.5"},
	"snapshot":  {"setura snapshot -n demo > before.json", "setura --context prod-eu,prod-us snapshot -n demo"},
	"diff":      {"setura diff before.json after.json"},
	"map":       {"setura map -n demo > map.html"},
	"impact":    {"setura impact Service/demo/orders --snapshot before.json"},
	"lint":      {"setura lint --snapshot before.json --strict", "setura lint --all-contexts -n demo --format json"},
	"usage": {"setura usage --admin 127.0.0.1:19000 --by key --since 7d",
		"setura usage --by route --identity 'apikey:acme*' --format csv",
		"setura usage invoice --period 2026-11 --format csv"},
	"shadow":  {"setura shadow --admin 127.0.0.1:19000 --fail-under 99.5", "setura gateway run --config routes.json --shadow-diff 10"},
	"history": {"setura history probes.jsonl --since 24h --route orders", "setura watch https://orders.example.test/ --history probes.jsonl --alert-slack \"$SLACK_URL\""},
	"slo":     {"setura slo --history probes.jsonl --objective 99.9", "setura slo --admin 127.0.0.1:19000 --config slo.json --state slo.jsonl"},
	"watch":   {"setura watch https://orders.example.test/ --history probes.jsonl --alert-slack \"$SLACK_URL\" --alert-cooldown 5m"},
	"doctor":  {"setura doctor -n demo", "setura doctor gateway --config setura.json --admin 127.0.0.1:19000", "setura doctor gateway --kube"},
	"contract": {"setura contract diff --spec openapi.json --learned inventory.json --fail-on shadow,drift",
		"setura gateway run --config routes.json --learn inventory.json",
		"setura contract export --learned inventory.json --title Orders --out observed.openapi.json",
		"setura contract learn --log access.jsonl --out inventory.json",
		"setura contract diff --spec openapi.json --admin 127.0.0.1:19000 --format markdown > comment.md"},
	"init": {"setura init --route orders.example.test=127.0.0.1:9001 --out gw", "setura init --openapi api.json --out gw"},
	"replay": {"setura replay --log access.jsonl --before old.json --after new.json",
		"zcat access.jsonl.gz | setura replay --log - --before old.json --after new.json --fail-on any --format github",
		"setura replay --log /var/log/nginx/access.log --default-host shop.example.test --before old.json --after new.json --fail-on route,policy"},
	"pr-check": {"setura pr-check --base main/gateway.json --head pr/gateway.json --traffic access.jsonl",
		"setura pr-check --base base/ --head head/ --traffic access.jsonl.gz --format markdown --fail-if-changed-over 5",
		"zcat access.jsonl.gz | setura pr-check --base old.json --head new.json --traffic - --format json"},
	"chaos": {"setura chaos run --plan plan.json --report chaos-report.json", "setura chaos run --plan plan.json --dry-run", "setura chaos status --admin 127.0.0.1:19000", "setura chaos stop"},
	"migrate": {"setura migrate check --ingress ingress.yaml --routes routes.yaml --services services.yaml --objects objects.yaml",
		"setura migrate check -n shop --ingress-class nginx",
		"setura migrate check -n shop --ingress-url http://10.0.0.1 --gateway-url http://10.0.0.2 --format github",
		"setura migrate check --ingress-url http://10.0.0.1 --gateway-url http://10.0.0.2 --probe-extra",
		"setura migrate convert ingress.yaml services.yaml --out gateway/",
		"setura migrate convert --from traefik routes/ --format json --report convert.json",
		"setura migrate convert --from envoy-gateway --compat-report",
		"setura migrate convert -n shop --ingress-class nginx > gateway.yaml"},
	"ai":          {"setura ai report.json --model llama3"},
	"connections": {"setura connections", "setura connections --follow --filter status=5xx --filter route=orders", "setura connections --admin 127.0.0.1:19000 --format json | jq '.history[0]'"},
	"top":         {"setura top", "setura top --admin 127.0.0.1:19000 --once", "setura top --format json | jq '.routes[0]'"},
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
	fmt.Fprintln(w, `  Next: setura --help lists every command.`)
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
