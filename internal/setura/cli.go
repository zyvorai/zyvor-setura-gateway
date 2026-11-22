package setura

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

// Version is the release version, overridden at build time with -ldflags.
var Version = "0.4.0"

const usage = `setura - publish and diagnose a local Envoy gateway

Usage: setura [--context NAME] COMMAND [flags]

Commands:
  publish GATEWAY --listener NAME   forward an Envoy listener to IPv4 loopback
  explain URL                       probe a URL from this host
  check FILE [--junit FILE]         run a JSON file of route assertions
  inspect ROUTE                     show route conditions and backend inventory
  listeners GATEWAY                 show listener attachment and conditions
  gate ROUTE URL                    require current parent status and a probe streak
  compare URL --target dns|IP       probe the same URL via DNS and/or IPs
  snapshot / diff BEFORE AFTER      capture and compare Gateway and HTTPRoute specs
  map / impact TARGET               render or query the declared route topology
  lint                              statically analyze Gateway and HTTPRoute specs (offline)
  completion bash|zsh|fish          print a shell completion script
  ai REPORT [--model NAME]          explain saved evidence, optionally with local Ollama
  doctor / capabilities / exposure  check permissions, controllers and Service exposure
  watch URL... [--file FILE]        re-probe on an interval, print state changes, serve metrics
  version                           print the version

Run "setura COMMAND -h" for a command's flags.
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// parse runs a FlagSet while allowing flags and positionals to interleave.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// Main runs the CLI and returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int { return runWith(nil, args, stdout, stderr) }

func runWith(cluster *Cluster, args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			if ke, ok := r.(keyError); ok {
				fmt.Fprintf(stderr, "setura: %s\n", ke)
				code = 2
				return
			}
			panic(r)
		}
	}()
	code, err := run(cluster, args, stdout, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		var ue usageError
		if !errors.As(err, &ue) {
			fmt.Fprintf(stderr, "setura: %s\n", err)
		}
		return 2
	}
	return code
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func run(injected *Cluster, args []string, stdout, stderr io.Writer) (int, error) {
	var context string
	for len(args) > 0 {
		switch a := args[0]; {
		case a == "--context" || a == "-context":
			if len(args) < 2 {
				fmt.Fprintln(stderr, "setura: --context needs a value")
				return 2, usageError{"context"}
			}
			context, args = args[1], args[2:]
			continue
		case strings.HasPrefix(a, "--context="):
			context, args = strings.TrimPrefix(a, "--context="), args[1:]
			continue
		}
		break
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		if len(args) == 0 {
			return 2, usageError{"missing command"}
		}
		return 0, nil
	}
	cmd, rest := args[0], args[1:]
	cluster := injected
	if cluster == nil {
		cluster = NewCluster(context)
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var ns string
	nsFlag := func() {
		fs.StringVar(&ns, "n", "default", "namespace")
		fs.StringVar(&ns, "namespace", "default", "namespace")
	}
	need := func(pos []string, n int, what string) error {
		if len(pos) != n {
			fmt.Fprintf(stderr, "setura %s: expected %s\n", cmd, what)
			return usageError{what}
		}
		return nil
	}
	out := func(v any) error { return writeJSON(stdout, v) }

	switch cmd {
	case "version":
		fmt.Fprintln(stdout, "setura", Version)
		return 0, nil

	case "publish":
		listener := fs.String("listener", "", "listener name (required)")
		proxyNS := fs.String("proxy-namespace", "envoy-gateway-system", "namespace of the Envoy proxy Services")
		port := fs.Int("port", 8080, "local port")
		service := fs.String("service", "", "explicit proxy Service for Traefik or another controller")
		servicePort := fs.Int("service-port", -1, "explicit Service port when it differs from the listener")
		dry := fs.Bool("dry-run", false, "discover the Service and print the command")
		nsFlag()
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "GATEWAY"); err != nil {
			return 2, err
		}
		if *listener == "" {
			fmt.Fprintln(stderr, "setura publish: --listener is required")
			return 2, usageError{"listener"}
		}
		command, err := cluster.Publication(ns, pos[0], *listener, *proxyNS, *port, *service, *servicePort)
		if err != nil {
			return 0, err
		}
		if *dry {
			quoted := make([]string, len(command))
			for i, c := range command {
				quoted[i] = shellQuote(c)
			}
			fmt.Fprintln(stdout, strings.Join(quoted, " "))
			return 0, nil
		}
		return 0, publish(command)

	case "inspect":
		nsFlag()
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "ROUTE"); err != nil {
			return 2, err
		}
		res, err := cluster.Inspect(ns, pos[0])
		if err != nil {
			return 0, err
		}
		return 0, out(res)

	case "explain":
		address := fs.String("address", "", "connect to this numeric IP, preserving Host and TLS identity")
		backend := fs.String("backend", "", "expected X-Setura-Backend response header")
		ca := fs.String("ca", "", "trusted PEM CA bundle for this request")
		status := fs.Int("status", 200, "expected HTTP status")
		timeout := fs.Float64("timeout", 4, "per-operation timeout in seconds")
		asJSON := fs.Bool("json", false, "print JSON")
		var headers stringList
		fs.Var(&headers, "header", `require a response header, "Name: value" or "Name: *" for presence; repeatable`)
		body := fs.String("body-contains", "", "require this text in the first 1 MiB of the response body")
		maxMS := fs.Float64("max-ms", 0, "fail when the whole probe takes longer than this many milliseconds")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "URL"); err != nil {
			return 2, err
		}
		o := ProbeOptions{URL: pos[0], Address: *address, CA: *ca, Backend: *backend, Status: *status, Timeout: *timeout,
			BodyContains: *body, MaxMS: *maxMS}
		for _, h := range headers {
			name, value, ok := strings.Cut(h, ":")
			if !ok || strings.TrimSpace(name) == "" {
				return 0, userErrorf("--header expects \"Name: value\", got %q", h)
			}
			if o.Headers == nil {
				o.Headers = map[string]string{}
			}
			o.Headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
		}
		r, err := Probe(o)
		if err != nil {
			return 0, err
		}
		if *asJSON {
			if err := out(r); err != nil {
				return 0, err
			}
		} else {
			for _, name := range stages {
				step := r.Step(name)
				line := fmt.Sprintf("%-8s %-12s", name, step.State())
				for _, p := range step[1:] {
					line += fmt.Sprintf(" %s=%s", p.K, pyFormat(p.V))
				}
				fmt.Fprintln(stdout, line)
			}
		}
		return boolExit(!r.OK), nil

	case "check":
		junit := fs.String("junit", "", "also write JUnit XML to FILE")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "FILE"); err != nil {
			return 2, err
		}
		rows, err := Check(pos[0])
		if err != nil {
			return 0, err
		}
		if *junit != "" {
			if err := WriteJUnit(rows, *junit); err != nil {
				return 0, err
			}
		}
		if err := out(rows); err != nil {
			return 0, err
		}
		failed := false
		for _, r := range rows {
			failed = failed || !r.OK
		}
		return boolExit(failed), nil

	case "doctor":
		proxyNS := fs.String("proxy-namespace", "envoy-gateway-system", "namespace of the Envoy proxy Services")
		nsFlag()
		if _, err := parse(fs, rest); err != nil {
			return 2, err
		}
		res, err := Doctor(cluster, ns, *proxyNS)
		if err != nil {
			return 0, err
		}
		return boolExit(res["ok"] != true), out(res)

	case "capabilities", "exposure", "snapshot":
		nsFlag()
		if _, err := parse(fs, rest); err != nil {
			return 2, err
		}
		var res any
		var err error
		switch cmd {
		case "capabilities":
			res, err = Capabilities(cluster, ns)
		case "exposure":
			res, err = Exposure(cluster, ns)
		default:
			res, err = Snapshot(cluster, ns)
		}
		if err != nil {
			return 0, err
		}
		return 0, out(res)

	case "listeners":
		nsFlag()
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "GATEWAY"); err != nil {
			return 2, err
		}
		res, err := Listeners(cluster, ns, pos[0])
		if err != nil {
			return 0, err
		}
		return 0, out(res)

	case "gate":
		g := GateOptions{}
		fs.StringVar(&g.Backend, "backend", "", "expected backend identity (required)")
		fs.StringVar(&g.Gateway, "gateway", "", "parent Gateway name (required)")
		fs.StringVar(&g.GatewayNamespace, "gateway-namespace", "", "parent Gateway namespace")
		fs.StringVar(&g.Controller, "controller", "", "required controllerName")
		fs.StringVar(&g.Listener, "listener", "", "required listener sectionName")
		fs.StringVar(&g.Address, "address", "", "connect to this numeric IP")
		fs.StringVar(&g.CA, "ca", "", "trusted PEM CA bundle")
		fs.IntVar(&g.Attempts, "attempts", 5, "maximum attempts")
		fs.IntVar(&g.Streak, "streak", 2, "consecutive passes required")
		fs.Float64Var(&g.Interval, "interval", 1, "seconds between attempts")
		nsFlag()
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 2, "ROUTE URL"); err != nil {
			return 2, err
		}
		if g.Backend == "" || g.Gateway == "" {
			fmt.Fprintln(stderr, "setura gate: --backend and --gateway are required")
			return 2, usageError{"required"}
		}
		g.Route, g.URL, g.Namespace = pos[0], pos[1], ns
		res, err := Gate(cluster, g)
		if err != nil {
			return 0, err
		}
		return boolExit(res["ok"] != true), out(res)

	case "compare":
		var targets stringList
		fs.Var(&targets, "target", "dns or a numeric IP; repeatable (required)")
		backend := fs.String("backend", "", "expected backend identity")
		ca := fs.String("ca", "", "trusted PEM CA bundle")
		status := fs.Int("status", 200, "expected HTTP status")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "URL"); err != nil {
			return 2, err
		}
		if len(targets) == 0 {
			fmt.Fprintln(stderr, "setura compare: at least one --target is required")
			return 2, usageError{"target"}
		}
		res, err := Compare(pos[0], targets, *backend, *ca, *status)
		if err != nil {
			return 0, err
		}
		return boolExit(res["ok"] != true), out(res)

	case "diff":
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 2, "BEFORE AFTER"); err != nil {
			return 2, err
		}
		res, err := Diff(pos[0], pos[1])
		if err != nil {
			return 0, err
		}
		return boolExit(res["equal"] != true), out(res)

	case "map", "impact":
		format := fs.String("format", "html", "html or json")
		snap := fs.String("snapshot", "", "read a Setura snapshot instead of querying Kubernetes")
		nsFlag()
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if cmd == "impact" {
			if err := need(pos, 1, "TARGET (for example Service/demo/orders)"); err != nil {
				return 2, err
			}
		} else if err := need(pos, 0, "no arguments"); err != nil {
			return 2, err
		}
		if *format != "html" && *format != "json" {
			fmt.Fprintln(stderr, "setura map: --format must be html or json")
			return 2, usageError{"format"}
		}
		var snapshot obj
		if *snap != "" {
			raw, err := os.ReadFile(*snap)
			if err != nil {
				return 0, err
			}
			var v any
			if err := json.Unmarshal(raw, &v); err != nil {
				return 0, userErrorf("invalid snapshot JSON: %v", err)
			}
			snapshot = asMap(v)
		} else if snapshot, err = Snapshot(cluster, ns); err != nil {
			return 0, err
		}
		graph, err := BuildTopology(snapshot)
		if err != nil {
			return 0, err
		}
		switch {
		case cmd == "impact":
			res, err := Impact(graph, pos[0])
			if err != nil {
				return 0, err
			}
			return 0, out(res)
		case *format == "html":
			page, err := Page(graph)
			if err != nil {
				return 0, err
			}
			fmt.Fprint(stdout, page)
			return 0, nil
		}
		return 0, out(graph)

	case "lint":
		format := fs.String("format", "text", "text or json")
		snap := fs.String("snapshot", "", "read a Setura snapshot instead of querying Kubernetes")
		strict := fs.Bool("strict", false, "exit 1 on warnings as well as errors")
		rules := fs.Bool("rules", false, "list the lint rules and exit")
		nsFlag()
		if _, err := parse(fs, rest); err != nil {
			return 2, err
		}
		if *rules {
			for _, r := range Rules {
				fmt.Fprintf(stdout, "%s  %-7s %s\n", r.ID, r.Severity, r.Summary)
			}
			return 0, nil
		}
		if *format != "text" && *format != "json" {
			fmt.Fprintln(stderr, "setura lint: --format must be text or json")
			return 2, usageError{"format"}
		}
		var snapshot obj
		if *snap != "" {
			var err error
			if snapshot, err = readSnapshot(*snap); err != nil {
				return 0, err
			}
		} else {
			var err error
			if snapshot, err = Snapshot(cluster, ns); err != nil {
				return 0, err
			}
		}
		report, err := Lint(snapshot)
		if err != nil {
			return 0, err
		}
		if *format == "json" {
			if err := out(report); err != nil {
				return 0, err
			}
		} else {
			fmt.Fprint(stdout, LintText(report))
		}
		failed := report["ok"] != true
		if w, _ := num(report["warnings"]); *strict && w > 0 {
			failed = true
		}
		return boolExit(failed), nil

	case "watch":
		return watchCommand(rest, stdout, stderr)

	case "completion":
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "bash, zsh or fish"); err != nil {
			return 2, err
		}
		return 0, Completion(pos[0], stdout)

	case "ai":
		model := fs.String("model", "", "installed Ollama model name; enables local inference")
		port := fs.Int("port", 11434, "Ollama port on 127.0.0.1")
		ask := fs.String("ask", "", "question for the model")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "REPORT"); err != nil {
			return 2, err
		}
		if *ask != "" && *model == "" {
			return 0, userError("--ask requires --model")
		}
		raw, err := os.ReadFile(pos[0])
		if err != nil {
			return 0, err
		}
		var report any
		if err := json.Unmarshal(raw, &report); err != nil {
			return 0, userErrorf("invalid report JSON: %v", err)
		}
		facts, err := Evidence(report)
		if err != nil {
			return 0, err
		}
		diagnosis := obj{"mode": "evidence", "evidence": facts}
		if *model != "" {
			question := *ask
			if question == "" {
				question = "What does this evidence show, and what should I check next?"
			}
			findings, err := Interpret(facts, question, *model, *port)
			if err != nil {
				return 0, err
			}
			diagnosis["mode"], diagnosis["model"], diagnosis["findings"] = "local-model", *model, findings
		}
		return 0, out(diagnosis)
	}
	fmt.Fprintf(stderr, "setura: unknown command %q\n\n%s", cmd, usage)
	return 2, usageError{"unknown command"}
}

func boolExit(failed bool) int {
	if failed {
		return 1
	}
	return 0
}

// Check runs each case in a JSON assertion file.
func Check(path string) ([]*Report, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, userErrorf("invalid check file JSON: %v", err)
	}
	cases := asList(v)
	if len(cases) == 0 {
		return nil, userError("check file must be a nonempty JSON array")
	}
	allowed := map[string]bool{"url": true, "address": true, "status": true, "backend": true, "ca": true, "timeout": true,
		"headers": true, "body_contains": true, "max_ms": true}
	rows := []*Report{}
	for _, c := range cases {
		m := asMap(c)
		valid := m != nil && asStr(m["url"]) != ""
		for k := range m {
			valid = valid && allowed[k]
		}
		if !valid {
			return nil, userError("invalid check case; see examples/checks.json")
		}
		o := NewProbe(asStr(m["url"]))
		o.Address, o.Backend, o.CA = str(m, "address", ""), str(m, "backend", ""), str(m, "ca", "")
		if s, ok := m["status"]; ok {
			f, isNum := num(s)
			if !isNum || f != float64(int(f)) {
				return nil, userError("invalid port or expected HTTP status")
			}
			o.Status = int(f)
		}
		if t, ok := m["timeout"]; ok {
			f, isNum := num(t)
			if !isNum {
				return nil, userError("timeout must be positive and at most 60 seconds")
			}
			o.Timeout = f
		}
		o.BodyContains = str(m, "body_contains", "")
		if h, ok := m["headers"]; ok {
			hm := asMap(h)
			if hm == nil {
				return nil, userError("headers must be an object of header names to values")
			}
			o.Headers = map[string]string{}
			for k, v := range hm {
				sv, ok := v.(string)
				if !ok {
					return nil, userErrorf("header %s must be a string", k)
				}
				o.Headers[k] = sv
			}
		}
		if t, ok := m["max_ms"]; ok {
			f, isNum := num(t)
			if !isNum {
				return nil, userError("max_ms must be a number")
			}
			o.MaxMS = f
		}
		r, err := Probe(o)
		if err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func pyFormat(v any) string {
	if l, ok := v.([]string); ok {
		q := make([]string, len(l))
		for i, s := range l {
			q[i] = pyRepr(s)
		}
		return "[" + strings.Join(q, ", ") + "]"
	}
	return fmt.Sprint(v)
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
