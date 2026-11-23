package setura

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Version is the release version, overridden at build time with -ldflags.
var Version = "0.9.0"

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// parse runs a FlagSet while allowing flags and positionals to interleave.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := parseOnce(fs, args); err != nil {
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
			var ue userError
			if errors.As(err, &ue) {
				if cmd := firstCommand(args); cmd != "" {
					fmt.Fprintf(stderr, "  Next: setura %s -h shows the flags and an example.\n", cmd)
				}
			}
		}
		return 2
	}
	return code
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func run(injected *Cluster, args []string, stdout, stderr io.Writer) (int, error) {
	var context string
	var allCtx bool
	args, topts, terr := extractTermFlags(args)
	if terr != nil {
		fmt.Fprintf(stderr, "setura: %s\n", terr)
		return 2, usageError{"color"}
	}
	u := newUI(isTTY(stdout), topts, os.Getenv)
	stdoutTTY := isTTY(stdout)
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
		case a == "--all-contexts" || a == "-all-contexts":
			allCtx, args = true, args[1:]
			continue
		}
		break
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if len(args) == 2 && args[0] == "help" {
			if _, ok := commandSummary(args[1]); ok {
				return run(injected, []string{args[1], "-h"}, stdout, stderr)
			}
		}
		writeHelp(stdout, u)
		if len(args) == 0 {
			return 2, usageError{"missing command"}
		}
		return 0, nil
	}
	cmd, rest := args[0], args[1:]
	if done, code, err := multiContext(injected, cmd, &rest, &context, allCtx, stdout, stderr, stdoutTTY); done {
		return code, err
	}
	cluster := injected
	if cluster == nil {
		cluster = NewCluster(context)
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	setCommandUsage(fs, cmd, newUI(isTTY(stderr), topts, os.Getenv))
	var ns string
	nsFlag := func() {
		fs.StringVar(&ns, "n", "default", "namespace")
		fs.StringVar(&ns, "namespace", "default", "namespace")
	}
	need := func(pos []string, n int, what string) error {
		if len(pos) != n {
			fmt.Fprintf(stderr, "setura %s: expected %s\n", cmd, what)
			exampleHint(stderr, cmd)
			return usageError{what}
		}
		return nil
	}
	out := func(v any) error { return writeJSON(stdout, v) }

	switch cmd {
	case "version":
		verbose := fs.Bool("verbose", false, "print build information")
		if _, err := parse(fs, rest); err != nil {
			return 2, err
		}
		if *verbose {
			versionVerbose(stdout, u)
			fmt.Fprintf(stdout, "  %s %s\n", u.gray(pad("licence", 12)), licenceLine(os.Getenv, time.Now()))
			return 0, nil
		}
		fmt.Fprintln(stdout, "setura", Version)
		return 0, nil

	case "gateway":
		if len(rest) > 0 && (rest[0] == "status" || (rest[0] == "install" && wantsCheck(rest[1:]))) {
			if rest[0] == "status" {
				return runGatewayStatus(cluster, rest[1:], stdout, stderr, u, stdoutTTY), nil
			}
			return runInstallCheck(cluster, rest[1:], stdout, stderr, u, stdoutTTY), nil
		}
		return runGateway(rest, stdout, stderr), nil

	case "connections":
		return runConnections(fs, rest, stdout, stderr, u, stdoutTTY)

	case "top":
		return runTop(fs, rest, stdout, stderr, u, stdoutTTY)

	case "ui":
		return uiCommand(cluster, rest, stdout, stderr)

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
			exampleHint(stderr, "publish")
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
		cert := fs.String("cert", "", "PEM client certificate for mTLS (requires --key)")
		key := fs.String("key", "", "PEM client private key for mTLS (requires --cert)")
		sni := fs.String("tls-server-name", "", "TLS SNI and verification name (default: URL host)")
		minTLS := fs.String("min-tls", "", "minimum TLS version, 1.2 or 1.3")
		warnDays := fs.Int("warn-expiry-days", 0, "add expiry_warning when the server certificate expires sooner than N days")
		http2 := fs.Bool("http2", false, "negotiate ALPN h2 over TLS and speak HTTP/2")
		method := fs.String("method", "", "request method: GET (default), HEAD, OPTIONS; POST, PUT, PATCH, DELETE need --allow-unsafe-method")
		unsafeMethod := fs.Bool("allow-unsafe-method", false, "allow POST, PUT, PATCH and DELETE (sent with no body)")
		var reqHeaders stringList
		fs.Var(&reqHeaders, "request-header", `send a request header, "Name: value"; repeatable (Host and framing headers are refused)`)
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "URL"); err != nil {
			return 2, err
		}
		rh, err := parseRequestHeaderFlags(reqHeaders)
		if err != nil {
			return 0, err
		}
		o := ProbeOptions{Method: *method, AllowUnsafeMethod: *unsafeMethod, RequestHeaders: rh, URL: pos[0], Address: *address, CA: *ca, Backend: *backend, Status: *status, Timeout: *timeout,
			BodyContains: *body, MaxMS: *maxMS, HTTP2: *http2,
			Cert: *cert, Key: *key, ServerName: *sni, MinTLS: *minTLS, WarnExpiryDays: *warnDays}
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
			fmt.Fprint(stdout, u.ExplainPretty(r))
		}
		return boolExit(!r.OK), nil

	case "certs":
		ca := fs.String("ca", "", "trusted PEM CA bundle (default: system roots)")
		sni := fs.String("sni", "", "TLS SNI and verification name (default: host)")
		cert := fs.String("cert", "", "PEM client certificate (requires --key)")
		key := fs.String("key", "", "PEM client private key (requires --cert)")
		warn := fs.Int("warn-expiry-days", 0, "exit 1 when any chain certificate expires sooner than N days")
		timeout := fs.Float64("timeout", 5, "timeout in seconds")
		asJSON := fs.Bool("json", false, "print JSON")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "HOST:PORT"); err != nil {
			return 2, err
		}
		rep, err := Certs(CertsOptions{Address: pos[0], CA: *ca, SNI: *sni, Timeout: time.Duration(*timeout * float64(time.Second)),
			tlsOpts: tlsOpts{Cert: *cert, Key: *key, WarnExpiryDays: *warn}})
		if err != nil {
			return 0, err
		}
		if *asJSON {
			if err := out(rep); err != nil {
				return 0, err
			}
		} else {
			fmt.Fprint(stdout, rep.Text())
		}
		return boolExit(!rep.OK), nil

	case "check":
		junit := fs.String("junit", "", "also write JUnit XML to FILE")
		sarifOut := fs.String("sarif", "", "also write SARIF 2.1.0 to FILE")
		format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty, json or github (workflow annotations)")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "FILE"); err != nil {
			return 2, err
		}
		pretty := false
		if *format != "github" {
			var ferr error
			if pretty, ferr = wantPretty(*format, stdoutTTY); ferr != nil {
				return 2, ferr
			}
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
		if *sarifOut != "" {
			b, err := CheckSARIF(rows, pos[0])
			if err == nil {
				err = writeFile(*sarifOut, b)
			}
			if err != nil {
				return 0, err
			}
		}
		if *format == "github" {
			fmt.Fprint(stdout, CheckAnnotations(rows, pos[0]))
		} else if pretty {
			fmt.Fprint(stdout, u.CheckPretty(rows))
		} else if err := out(rows); err != nil {
			return 0, err
		}
		failed := false
		for _, r := range rows {
			failed = failed || !r.OK
		}
		return boolExit(failed), nil

	case "init":
		code, err := runInit(fs, rest, os.Stdin, isTTY(os.Stdin), stdout, stderr, u, stdoutTTY)
		return code, err

	case "doctor":
		if len(rest) > 0 && rest[0] == "gateway" {
			return runDoctorGatewayWith(cluster, rest[1:], stdout, stderr, u, stdoutTTY)
		}
		proxyNS := fs.String("proxy-namespace", "envoy-gateway-system", "namespace of the Envoy proxy Services")
		format := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
		nsFlag()
		if _, err := parse(fs, rest); err != nil {
			return 2, err
		}
		pretty, ferr := wantPretty(*format, stdoutTTY)
		if ferr != nil {
			return 2, ferr
		}
		res, err := Doctor(cluster, ns, *proxyNS)
		if err != nil {
			return 0, err
		}
		if pretty {
			fmt.Fprint(stdout, u.DoctorPretty(res))
			return boolExit(res["ok"] != true), nil
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
		gformat := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
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
			exampleHint(stderr, "gate")
			return 2, usageError{"required"}
		}
		pretty, ferr := wantPretty(*gformat, stdoutTTY)
		if ferr != nil {
			return 2, ferr
		}
		g.Route, g.URL, g.Namespace = pos[0], pos[1], ns
		res, err := Gate(cluster, g)
		if err != nil {
			return 0, err
		}
		if pretty {
			fmt.Fprint(stdout, u.GatePretty(g.Route, g.Streak, res))
			return boolExit(res["ok"] != true), nil
		}
		return boolExit(res["ok"] != true), out(res)

	case "compare":
		var targets stringList
		fs.Var(&targets, "target", "dns or a numeric IP; repeatable (required)")
		backend := fs.String("backend", "", "expected backend identity")
		ca := fs.String("ca", "", "trusted PEM CA bundle")
		status := fs.Int("status", 200, "expected HTTP status")
		cformat := fs.String("format", "auto", "auto (pretty on a terminal, JSON when piped), pretty or json")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "URL"); err != nil {
			return 2, err
		}
		pretty, ferr := wantPretty(*cformat, stdoutTTY)
		if ferr != nil {
			return 2, ferr
		}
		if len(targets) == 0 {
			fmt.Fprintln(stderr, "setura compare: at least one --target is required")
			exampleHint(stderr, "compare")
			return 2, usageError{"target"}
		}
		res, err := Compare(pos[0], targets, *backend, *ca, *status)
		if err != nil {
			return 0, err
		}
		if pretty {
			fmt.Fprint(stdout, u.ComparePretty(pos[0], targets, res))
			return boolExit(res["ok"] != true), nil
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
		format := fs.String("format", "text", "text, json, sarif or github")
		manifestDir := fs.String("manifest-dir", "", "directory of YAML/JSON manifests used to add file:line to sarif/github findings")
		baselineFile := fs.String("baseline", "", "ignore findings recorded in this baseline FILE")
		writeBaseline := fs.String("write-baseline", "", "record current findings to FILE and ignore them")
		var disable, overrides stringList
		fs.Var(&disable, "disable", "comma-separated rule IDs to disable, e.g. SET004,SET009; repeatable")
		fs.Var(&overrides, "severity-override", "RULE=error|warning; repeatable")
		snap := fs.String("snapshot", "", "read a Setura snapshot instead of querying Kubernetes")
		strict := fs.Bool("strict", false, "exit 1 on warnings as well as errors")
		rules := fs.Bool("rules", false, "list the lint rules and exit")
		plansFile := fs.String("plans", "", "also check this gateway API plan file against the snapshot's routes (SET020-SET022)")
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
		if *format != "text" && *format != "json" && *format != "sarif" && *format != "github" {
			fmt.Fprintln(stderr, "setura lint: --format must be text, json, sarif or github")
			return 2, usageError{"format"}
		}
		var lopts LintOptions
		var locs ManifestIndex
		{
			var err error
			if lopts.Disable, err = ParseDisable(disable); err != nil {
				return 2, err
			}
			if lopts.Override, err = ParseOverrides(overrides); err != nil {
				return 2, err
			}
			if *baselineFile != "" {
				if lopts.Baseline, err = ReadBaseline(*baselineFile); err != nil {
					return 2, err
				}
			}
			if *manifestDir != "" {
				if locs, err = ScanManifests(*manifestDir); err != nil {
					return 2, err
				}
			}
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
		if *plansFile != "" {
			raw, err := os.ReadFile(*plansFile)
			if err != nil {
				return 0, err
			}
			report = LintPlans(report, raw, "PlanFile/"+filepath.Base(*plansFile), snapshot)
		}
		if *writeBaseline != "" {
			all := ApplyLintOptions(report, LintOptions{Disable: lopts.Disable, Override: lopts.Override})
			if err := WriteBaseline(all, *writeBaseline); err != nil {
				return 0, err
			}
			lopts.Baseline = fingerprintSet(all)
		}
		report = ApplyLintOptions(report, lopts)
		switch *format {
		case "json":
			if err := out(report); err != nil {
				return 0, err
			}
		case "sarif":
			b, err := LintSARIF(report, locs)
			if err != nil {
				return 0, err
			}
			stdout.Write(b)
		case "github":
			fmt.Fprint(stdout, LintAnnotations(report, locs))
		default:
			fmt.Fprint(stdout, u.LintPretty(report))
			fmt.Fprint(stdout, lintSummary(report))
		}
		failed := report["ok"] != true
		if w, _ := num(report["warnings"]); *strict && w > 0 {
			failed = true
		}
		return boolExit(failed), nil

	case "watch":
		return watchCommand(rest, stdout, stderr)

	case "history":
		return runHistory(fs, rest, stdout, stderr, u)

	case "slo":
		return runSLO(fs, rest, stdout, stderr, u)

	case "man":
		return 0, Man(stdout)

	case "licence", "license":
		return runLicence(rest, os.Stdin, stdout, stderr, os.Getenv, time.Now()), nil

	case "shadow":
		return runShadow(fs, rest, stdout, stderr, u)

	case "usage":
		return runUsage(fs, rest, stdout, stderr, u)
	case "contract":
		return runContract(fs, rest, stdout, stderr, u)

	case "replay":
		return runReplay(fs, rest, u, stdoutTTY, os.Stdin, stdout, stderr)

	case "pr-check":
		return runPRCheck(fs, rest, u, stdoutTTY, os.Stdin, stdout, stderr)

	case "chaos":
		return runChaos(fs, rest, stdout, stderr, u, stdoutTTY)

	case "echo":
		return runEcho(fs, rest, stdout, stderr)

	case "grpc-health":
		return runGRPCHealth(fs, rest, stdout, stderr)

	case "why":
		return runWhy(fs, rest, stdout, stderr, u)

	case "bench":
		return runBench(fs, rest, stdout, stderr)

	case "split":
		return runSplit(fs, rest, stdout, stderr)

	case "cors":
		return runCORS(fs, rest, stdout, stderr)

	case "load":
		return runLoad(fs, rest, stdout, stderr)

	case "migrate":
		return runMigrate(cluster, fs, rest, stdout, stderr, u, stdoutTTY)

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
		provider := fs.String("provider", "ollama", "ollama or openai-compatible")
		endpoint := fs.String("endpoint", "", "model server base URL (loopback or RFC1918 unless --allow-remote); key from SETURA_AI_KEY")
		allowRemote := fs.Bool("allow-remote", false, "allow a non-local --endpoint")
		redact := fs.Bool("redact", false, "mask IPs, hostnames, namespaces and header values before sending evidence")
		suggest := fs.Bool("suggest", false, "ask for read-only next-step commands and print only allowlisted ones")
		maxEvidence := fs.Int("max-evidence", 0, "send at most N evidence facts (failures first, deterministic); 0 = all")
		pos, err := parse(fs, rest)
		if err != nil {
			return 2, err
		}
		if err := need(pos, 1, "REPORT"); err != nil {
			return 2, err
		}
		if *model == "" && (*ask != "" || *endpoint != "" || *redact || *suggest || *provider != "ollama") {
			return 0, userError("--ask, --provider, --endpoint, --redact and --suggest require --model")
		}
		if *maxEvidence < 0 {
			return 0, userError("--max-evidence must not be negative")
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
		facts, omitted := LimitEvidence(facts, *maxEvidence)
		diagnosis := obj{"mode": "evidence", "evidence": facts}
		if omitted > 0 {
			diagnosis["evidence_omitted"] = omitted
		}
		if *model != "" {
			question := *ask
			if question == "" {
				question = "What does this evidence show, and what should I check next?"
			}
			res, err := InterpretWith(facts, question, AIConfig{Provider: *provider, Endpoint: *endpoint, Model: *model, Port: *port,
				AllowRemote: *allowRemote, Suggest: *suggest, Redact: *redact, Namespaces: ReportNamespaces(report)})
			if err != nil {
				return 0, err
			}
			diagnosis["mode"], diagnosis["model"], diagnosis["findings"] = "local-model", *model, res.Findings
			if *redact {
				diagnosis["redacted"] = true
			}
			if *suggest {
				diagnosis["suggested_commands"], diagnosis["rejected_suggestions"] = nonNil(res.Suggestions), nonNil(res.Rejected)
			}
		}
		return 0, out(diagnosis)
	}
	unknownCommand(stderr, cmd)
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
		"headers": true, "body_contains": true, "max_ms": true, "http2": true}
	for _, k := range append(append([]string{}, mtlsCheckKeys...), requestCheckKeys...) {
		allowed[k] = true
	}
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
		if err := applyCheckTLS(m, &o); err != nil {
			return nil, err
		}
		if err := applyCheckRequest(m, &o); err != nil {
			return nil, err
		}
		if h, ok := m["http2"]; ok {
			b, isBool := h.(bool)
			if !isBool {
				return nil, userError("http2 must be true or false")
			}
			o.HTTP2 = b
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

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
