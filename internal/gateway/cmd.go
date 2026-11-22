package gateway

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const usage = `setura gateway - the built-in Gateway API data plane (no Envoy required)

Usage:
  setura gateway run --config FILE [flags]     serve a snapshot file, reloading it when it changes
  setura gateway run --kubernetes [flags]      run as an in-cluster controller and data plane
  setura gateway up FILE [flags]               local demo: start demo backends and serve FILE
  setura gateway install [flags]               print Kubernetes YAML for the controller (never applies)
  setura gateway rollout --config LIVE --new CANDIDATE --checks CHECKS   guarded rollout with automatic rollback
  setura gateway history --config LIVE         list config backups
  setura gateway rollback --config LIVE [--to ID]   restore a backup

Flags for run and up:
  --bind ADDR           listener bind address (default 127.0.0.1)
  --port-map A=B[,..]   serve spec port A on port B (0 = any free port); repeatable
  --port-offset N       add N to spec ports below 1024 (unprivileged remapping)
  --admin ADDR|off      admin endpoint (default 127.0.0.1:19000)
  --interval DUR        poll interval for config changes (default 1s; with --kubernetes only used by --poll, default 5s)
  --poll                with --kubernetes: poll instead of using watches
  --resync DUR          with --kubernetes: safety relist while watching (default 1m)
  --leader-elect        with --kubernetes: only the holder of a coordination.k8s.io Lease writes status
  --lease-name N, --lease-namespace NS, --lease-duration D (15s), --lease-renew-deadline D (10s),
  --lease-retry-period D (2s), --lease-identity ID   Lease settings for --leader-elect
  --service-name N, --service-namespace NS   Service whose address becomes Gateway status.addresses
  --expose-gateway-ports   with --kubernetes: add a Service port for every Gateway listener port
  --force               apply configurations that have lint errors
  --udp-idle-timeout DUR   close a UDP session after DUR without client datagrams (default 30s)
  --access-log FILE|-|off   access log (default "-", stdout)
  --access-log-format json|text   access log format (default json)
  --access-log-max-size SIZE    rotate the access log file past SIZE (100, 64k, 10MB, 1g; default off)
  --access-log-keep N           rotated files to keep (default: all)
  --access-log-gzip             gzip rotated files
                        (a file access log also rotates on SIGHUP; a file moved away by logrotate is reopened)
  --otlp-endpoint HOST:PORT|URL   export spans via OTLP/HTTP JSON (default off)
  --rate-limit N/s|N/m|N/h  local token-bucket rate limit (default off)
  --rate-burst N        bucket size (default: the per-second rate)
  --rate-key ip|route|header:NAME   what a bucket is keyed on (default ip)
  --rate-limit-share N  divide the rate by N, the declared replica count (an approximation of a
                        shared limit; no state is shared between replicas)
  --trusted-proxies CIDR[,..]   believe X-Forwarded-For only from these peers (client IP for rate
                        limits and access logs; appended to, not replaced, when forwarded)
  --otlp-retries N, --otlp-backoff DUR, --otlp-queue N   OTLP export retry count (default 4, -1 = none),
                        first backoff (250ms, doubling) and bounded span queue (2048)
  --retry-budget PCT    retries may not exceed PCT percent of recent requests (default 20)
  --retry-header        add X-Setura-Retries to responses (default off)
  --retry-cross-backend retries may move to another weighted backendRef (rule retry.crossBackend overrides)
  --retry-jitter F      randomise retry backoff by +/- F, 0-1 (default 0; rule retry.jitter overrides)
  --cb-max-requests N, --cb-max-pending N, --cb-max-connections N   circuit-breaker limits per backend
                        (a backend's circuitBreaker block overrides; default off)
  --cb-failures N, --cb-open-for DUR, --cb-probes N   open the circuit after N consecutive failures
                        for DUR (30s), then let N probes through (1)
  (a "resilience" block in the config file sets the same options; flags win over it)
  --outlier-failures N  consecutive 5xx/connect failures that eject an endpoint (default 5, 0 = off)
  --outlier-base-ejection DUR  first ejection time, doubling each time (default 30s)
  --outlier-max-ejection DUR   ejection time cap (default 5m)
  --health-path PATH    active-check every backend without its own healthCheck (default off)
  --health-interval DUR, --health-timeout DUR   defaults for those checks (5s, 2s)
                        (a backend healthCheck with protocol "grpc" probes grpc.health.v1)
  --log-query           keep query strings in logged and dashboard paths (default: stripped)
  --conn-history N      recent requests kept for /connections and the dashboard (default 500, 0 = off)
  --shadow-diff PCT     compare RequestMirror responses with the primary for PCT percent of requests;
                        a setura.zyvor.dev/shadow-diff block on the filter overrides it (default 0, see /shadow)
  --shadow-state FILE   snapshot shadow results (counters, recent mismatches) to FILE every 10s and
                        reload them at start (default off)
  --ui ADDR             serve the read-only live dashboard, for example 127.0.0.1:9090 or :9090
                        (loopback only unless --ui-token is set)
  --ui-token TOKEN      bearer token for the dashboard (or SETURA_UI_TOKEN); required off loopback
`

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type runFlags struct {
	opts       Options
	portMap    stringList
	accessLog  string
	interval   time.Duration
	bindFlagFS *flag.FlagSet
	obs        obsFlags
	outlier    int
	rotate     RotateOptions
	rotateSize string
	connHist   int
	uiAddr     string
	uiToken    string
}

func addRunFlags(fs *flag.FlagSet, f *runFlags) {
	fs.StringVar(&f.opts.Bind, "bind", "127.0.0.1", "listener bind address")
	fs.Var(&f.portMap, "port-map", "serve spec port A on port B, as A=B")
	fs.IntVar(&f.opts.PortOffset, "port-offset", 0, "add N to spec ports below 1024")
	fs.StringVar(&f.opts.Admin, "admin", DefaultAdmin, "admin address or off")
	fs.DurationVar(&f.interval, "interval", 0, "config poll interval")
	fs.BoolVar(&f.opts.Force, "force", false, "apply configurations that have lint errors")
	fs.StringVar(&f.accessLog, "access-log", "-", "access log file, - for stdout, off to disable")
	addObsFlags(fs, &f.obs)
	r := &f.opts.Resilience
	// Unset flags stay zero so the config file's resilience block (then the
	// built-in defaults) can fill them in; the real defaults are in the text.
	fs.IntVar(&r.RetryBudgetPercent, "retry-budget", 0, "retries as a percentage of recent requests (default 20)")
	fs.BoolVar(&r.RetryHeader, "retry-header", false, "add X-Setura-Retries to responses")
	fs.BoolVar(&r.RetryCrossBackend, "retry-cross-backend", false, "retries may move to another weighted backendRef")
	fs.Float64Var(&r.RetryJitter, "retry-jitter", 0, "randomise retry backoff by +/- this fraction (0-1)")
	fs.IntVar(&f.outlier, "outlier-failures", -1, "consecutive failures that eject an endpoint, 0 disables (default 5)")
	fs.DurationVar(&r.OutlierBaseEject, "outlier-base-ejection", 0, "first ejection duration (default 30s)")
	fs.DurationVar(&r.OutlierMaxEject, "outlier-max-ejection", 0, "maximum ejection duration (default 5m)")
	fs.StringVar(&r.HealthPath, "health-path", "", "default active health check path")
	fs.DurationVar(&r.HealthInterval, "health-interval", 0, "default active check interval (default 5s)")
	fs.DurationVar(&r.HealthTimeout, "health-timeout", 0, "default active check timeout (default 2s)")
	fs.IntVar(&r.Circuit.MaxRequests, "cb-max-requests", 0, "circuit breaker: concurrent requests per backend")
	fs.IntVar(&r.Circuit.MaxPending, "cb-max-pending", 0, "circuit breaker: requests allowed to wait for a slot")
	fs.IntVar(&r.Circuit.MaxConnections, "cb-max-connections", 0, "circuit breaker: upstream connections per backend")
	fs.IntVar(&r.Circuit.FailureThreshold, "cb-failures", 0, "circuit breaker: consecutive failures that open it")
	fs.DurationVar(&r.Circuit.OpenFor, "cb-open-for", 0, "circuit breaker: time open before probing (default 30s)")
	fs.IntVar(&r.Circuit.HalfOpenProbes, "cb-probes", 0, "circuit breaker: probe requests while half-open (default 1)")
	fs.StringVar(&f.rotateSize, "access-log-max-size", "", "rotate the access log file past this size (100, 64k, 10MB, 1g)")
	fs.IntVar(&f.rotate.Keep, "access-log-keep", 0, "rotated access log files to keep (default all)")
	fs.BoolVar(&f.rotate.Gzip, "access-log-gzip", false, "gzip rotated access log files")
	fs.DurationVar(&f.opts.UDPIdle, "udp-idle-timeout", 0, "idle timeout of UDP sessions on UDP listeners (default 30s)")
	fs.IntVar(&f.connHist, "conn-history", DefaultConnHistory, "recent requests kept for /connections, 0 disables")
	fs.IntVar(&f.opts.ShadowDiff, "shadow-diff", 0, "compare mirrored responses for PCT percent of requests (0 = only annotated mirrors)")
	fs.StringVar(&f.opts.ShadowState, "shadow-state", "", "persist shadow results to FILE (atomic snapshots, reloaded at start)")
	fs.StringVar(&f.uiAddr, "ui", "", "serve the read-only dashboard on ADDR")
	fs.StringVar(&f.uiToken, "ui-token", os.Getenv("SETURA_UI_TOKEN"), "bearer token for the dashboard")
}

func (f *runFlags) finish(stdout, stderr io.Writer, lint func([]byte) (bool, string)) (func(), error) {
	f.opts.PortMap = map[int]int{}
	for _, group := range f.portMap {
		for _, kv := range strings.Split(group, ",") {
			a, b, ok := strings.Cut(strings.TrimSpace(kv), "=")
			from, e1 := strconv.Atoi(a)
			to, e2 := strconv.Atoi(b)
			if !ok || e1 != nil || e2 != nil || from < 1 || to < 0 || to > 65535 {
				return nil, fmt.Errorf("--port-map %q: want SPEC=ACTUAL, for example 80=8080", kv)
			}
			f.opts.PortMap[from] = to
		}
	}
	if f.opts.ShadowDiff < 0 || f.opts.ShadowDiff > 100 {
		return nil, fmt.Errorf("--shadow-diff %d: want 0-100", f.opts.ShadowDiff)
	}
	switch {
	case f.outlier < 0: // unset
		f.opts.Resilience.OutlierFailures = 0
	case f.outlier == 0:
		f.opts.Resilience.OutlierFailures = -1
	default:
		f.opts.Resilience.OutlierFailures = f.outlier
	}
	if b := f.opts.Resilience.RetryBudgetPercent; b != 0 && (b < 1 || b > 100) {
		return nil, fmt.Errorf("--retry-budget %d: want 1-100", b)
	}
	if j := f.opts.Resilience.RetryJitter; j < 0 || j > 1 {
		return nil, fmt.Errorf("--retry-jitter %v: want 0-1", j)
	}
	if f.rotateSize != "" {
		n, err := ParseSize(f.rotateSize)
		if err != nil {
			return nil, fmt.Errorf("--access-log-max-size: %w", err)
		}
		f.rotate.MaxSize = n
	}
	if f.rotate.Keep < 0 {
		return nil, fmt.Errorf("--access-log-keep %d: want 0 or more", f.rotate.Keep)
	}
	if f.connHist < 0 {
		return nil, fmt.Errorf("--conn-history %d: want 0 (off) or a positive count", f.connHist)
	}
	f.opts.ConnHistory = f.connHist
	if f.connHist == 0 {
		f.opts.ConnHistory = -1
	}
	f.opts.Diag = stderr
	f.opts.Lint = lint
	if err := f.obs.apply(&f.opts); err != nil {
		return nil, err
	}
	closeFn := func() {}
	switch f.accessLog {
	case "off", "":
	case "-":
		f.opts.AccessLog = stdout
	default:
		rf, err := newRotatingFile(f.accessLog, f.rotate)
		if err != nil {
			return nil, err
		}
		f.opts.AccessLog = rf
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		stopHup := make(chan struct{})
		go func() {
			for {
				select {
				case <-hup:
					if err := rf.Reopen(); err != nil {
						fmt.Fprintf(stderr, "access log: reopen on SIGHUP: %v\n", err)
					}
				case <-stopHup:
					return
				}
			}
		}()
		closeFn = func() { signal.Stop(hup); close(stopHup); rf.Close() }
	}
	return closeFn, nil
}

// Main runs "setura gateway ...". lint is the snapshot linter (nil disables
// the lint gate). It returns the process exit code: 0 ok, 2 usage or setup.
func Main(args []string, stdout, stderr io.Writer, lint func([]byte) (bool, string)) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("gateway "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fail := func(err error) int {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "setura gateway %s: %v\n", sub, err)
		return 2
	}
	var rf runFlags
	switch sub {
	case "run":
		cfgPath := fs.String("config", "", "snapshot file to serve")
		kube := fs.Bool("kubernetes", false, "run as an in-cluster controller")
		kopts := addKubeFlags(fs)
		addRunFlags(fs, &rf)
		if err := fs.Parse(rest); err != nil {
			return fail(err)
		}
		if fs.NArg() != 0 || (*cfgPath == "") == !*kube {
			return fail(errors.New("give exactly one of --config FILE or --kubernetes"))
		}
		closeLog, err := rf.finish(stdout, stderr, lint)
		if err != nil {
			return fail(err)
		}
		defer closeLog()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var src Source
		interval := rf.interval
		if *kube {
			if interval == 0 {
				interval = 5 * time.Second
			}
			kopts.ctl.portOffsetFn = func() (int, map[int]int) { return rf.opts.PortOffset, rf.opts.PortMap }
			ks, err := kopts.source(stderr)
			if err != nil {
				return fail(err)
			}
			src = ks
		} else {
			src = FileSource{*cfgPath}
		}
		s := New(rf.opts)
		if err := s.startUIFlag(ctx, &rf, stderr); err != nil {
			return fail(err)
		}
		if err := s.Run(ctx, src, interval); err != nil {
			return fail(err)
		}
		return 0
	case "up":
		addRunFlags(fs, &rf)
		pos, err := parseInterleaved(fs, rest)
		if err != nil {
			return fail(err)
		}
		if len(pos) != 1 {
			return fail(errors.New("expected FILE"))
		}
		closeLog, err := rf.finish(stdout, stderr, lint)
		if err != nil {
			return fail(err)
		}
		defer closeLog()
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := up(ctx, pos[0], rf.opts, rf.interval, stdout, stderr, &rf); err != nil {
			return fail(err)
		}
		return 0
	case "install":
		var io InstallOptions
		fs.StringVar(&io.Namespace, "namespace", "setura-system", "namespace for the controller")
		fs.StringVar(&io.Image, "image", "", "container image (default ghcr.io/zyvorai/zyvor-setura-gateway:VERSION)")
		fs.StringVar(&io.ClassName, "class", "setura", "GatewayClass name")
		fs.IntVar(&io.Replicas, "replicas", 1, "controller replicas")
		fs.BoolVar(&io.ExposePorts, "expose-gateway-ports", false, "run the controller with --expose-gateway-ports and grant it patch on its own Service")
		if _, err := parseInterleaved(fs, rest); err != nil {
			return fail(err)
		}
		fmt.Fprint(stdout, Install(io))
		return 0
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// parseInterleaved lets flags and positionals mix, like the rest of Setura.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
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

// Up serves a snapshot after starting an in-process demo upstream for every
// loopback backend endpoint that nothing is already listening on.
func Up(ctx context.Context, path string, opts Options, interval time.Duration, stdout, stderr io.Writer) error {
	return up(ctx, path, opts, interval, stdout, stderr, nil)
}

// startUIFlag starts the dashboard when --ui was given.
func (s *Server) startUIFlag(ctx context.Context, rf *runFlags, stderr io.Writer) error {
	if rf == nil || rf.uiAddr == "" {
		return nil
	}
	return s.StartUI(ctx, rf.uiAddr, rf.uiToken, stderr)
}

func up(ctx context.Context, path string, opts Options, interval time.Duration, stdout, stderr io.Writer, rf *runFlags) error {
	src := FileSource{path}
	ld, err := src.Load(ctx)
	if err != nil {
		return err
	}
	var demos []*http.Server
	defer func() {
		for _, d := range demos {
			d.Close()
		}
	}()
	for _, key := range sortedKeys(ld.Config.Backends) {
		name := key[strings.Index(key, "/")+1:]
		if i := strings.LastIndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		for _, e := range ld.Config.Backends[key].Endpoints {
			u, err := parseEndpoint(e)
			if err != nil {
				return err
			}
			host, _, _ := net.SplitHostPort(u.Host)
			if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
				continue
			}
			ln, err := net.Listen("tcp", u.Host)
			if err != nil {
				continue // something real is already there
			}
			srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: demoHandler(name)}
			demos = append(demos, srv)
			go srv.Serve(ln)
			fmt.Fprintf(stderr, "demo backend %-14s http://%s\n", name, u.Host)
		}
	}
	s := New(opts)
	if err := s.startUIFlag(ctx, rf, stderr); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, src, interval) }()
	for deadline := time.Now().Add(10 * time.Second); !s.Ready(); time.Sleep(10 * time.Millisecond) {
		select {
		case err := <-done:
			return err
		default:
		}
		if time.Now().After(deadline) {
			return errors.New("gateway did not become ready")
		}
	}
	if cmd := demoHint(s); cmd != "" {
		fmt.Fprintf(stdout, "\ntry:\n  %s\n\nCtrl-C to stop.\n", cmd)
	}
	return <-done
}

func demoHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "%s served %s %s (Host: %s)\n", name, r.Method, r.URL.RequestURI(), r.Host)
	})
}

// demoHint builds a ready-to-run explain command for the first route.
func demoHint(s *Server) string {
	t := s.Table()
	if t == nil || len(t.Cfg.Routes) == 0 {
		return ""
	}
	r := t.Cfg.Routes[0]
	host := "demo.test"
	if len(r.Hostnames) > 0 {
		host = strings.Replace(r.Hostnames[0], "*", "demo", 1)
	}
	path, backend := "/", ""
	if len(r.Rules) > 0 {
		if len(r.Rules[0].Matches) > 0 && r.Rules[0].Matches[0].Path != nil && r.Rules[0].Matches[0].Path.Value != "" {
			path = r.Rules[0].Matches[0].Path.Value
		}
		// Only suggest asserting a backend when exactly one can answer, so the
		// suggested command always passes (a canary split would fail ~10%).
		var live []string
		for _, b := range r.Rules[0].BackendRefs {
			if b.Weight == nil || *b.Weight > 0 {
				live = append(live, b.Name)
			}
		}
		if len(live) == 1 {
			backend = live[0]
		}
	}
	for _, l := range t.Listeners {
		if !l.Serving {
			continue
		}
		_, port, _ := net.SplitHostPort(s.Addr(l.L.Port))
		scheme := "http"
		if l.L.Protocol == "HTTPS" {
			scheme = "https"
		}
		cmd := fmt.Sprintf("setura explain %s://%s:%s%s --address 127.0.0.1", scheme, host, port, path)
		if backend != "" {
			cmd += " --backend " + backend
		}
		return cmd
	}
	return ""
}
