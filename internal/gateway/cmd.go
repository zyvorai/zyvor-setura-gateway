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

Flags for run and up:
  --bind ADDR           listener bind address (default 127.0.0.1)
  --port-map A=B[,..]   serve spec port A on port B (0 = any free port); repeatable
  --port-offset N       add N to spec ports below 1024 (unprivileged remapping)
  --admin ADDR|off      admin endpoint (default 127.0.0.1:19000)
  --interval DUR        poll interval for config changes (default 1s; 5s with --kubernetes)
  --force               apply configurations that have lint errors
  --access-log FILE|-|off   JSON access log (default "-", stdout)
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
}

func addRunFlags(fs *flag.FlagSet, f *runFlags) {
	fs.StringVar(&f.opts.Bind, "bind", "127.0.0.1", "listener bind address")
	fs.Var(&f.portMap, "port-map", "serve spec port A on port B, as A=B")
	fs.IntVar(&f.opts.PortOffset, "port-offset", 0, "add N to spec ports below 1024")
	fs.StringVar(&f.opts.Admin, "admin", DefaultAdmin, "admin address or off")
	fs.DurationVar(&f.interval, "interval", 0, "config poll interval")
	fs.BoolVar(&f.opts.Force, "force", false, "apply configurations that have lint errors")
	fs.StringVar(&f.accessLog, "access-log", "-", "access log file, - for stdout, off to disable")
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
	f.opts.Diag = stderr
	f.opts.Lint = lint
	closeFn := func() {}
	switch f.accessLog {
	case "off", "":
	case "-":
		f.opts.AccessLog = stdout
	default:
		fh, err := os.OpenFile(f.accessLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, err
		}
		f.opts.AccessLog = fh
		closeFn = func() { fh.Close() }
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
			ks, err := kopts.source(stderr)
			if err != nil {
				return fail(err)
			}
			src = ks
		} else {
			src = FileSource{*cfgPath}
		}
		if err := New(rf.opts).Run(ctx, src, interval); err != nil {
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
		if err := Up(ctx, pos[0], rf.opts, rf.interval, stdout, stderr); err != nil {
			return fail(err)
		}
		return 0
	case "install":
		var io InstallOptions
		fs.StringVar(&io.Namespace, "namespace", "setura-system", "namespace for the controller")
		fs.StringVar(&io.Image, "image", "", "container image (default ghcr.io/zyvorai/zyvor-setura-gateway:VERSION)")
		fs.StringVar(&io.ClassName, "class", "setura", "GatewayClass name")
		fs.IntVar(&io.Replicas, "replicas", 1, "controller replicas")
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
		if len(r.Rules[0].BackendRefs) > 0 {
			backend = r.Rules[0].BackendRefs[0].Name
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
