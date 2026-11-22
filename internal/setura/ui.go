package setura

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/zyvorai/zyvor-setura-gateway/internal/webui"
)

// uiProvider keeps the latest dashboard state and announces changes on a hub.
type uiProvider struct {
	load  func() (obj, error)
	build func(obj) (obj, error)
	hub   *webui.Hub

	mu    sync.Mutex
	state obj
	prev  map[string]string // route id -> status
}

func (p *uiProvider) refresh() error {
	snap, err := p.load()
	if err == nil {
		var st obj
		if st, err = p.build(snap); err == nil {
			p.publishChanges(st)
			p.mu.Lock()
			p.state = st
			p.mu.Unlock()
			return nil
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	failed := obj{"message": err.Error(), "hint": "Check the snapshot file or cluster access, then it will recover on its own."}
	if p.state == nil {
		st, _ := BuildUIState(nil, UIInput{Mode: "snapshot"})
		st["summary"] = obj{"status": "unknown", "headline": "Cannot load the routes", "detail": "", "gateways": 0, "listeners": 0, "routes": 0, "backends": 0}
		p.state = st
	}
	cp := obj{}
	for k, v := range p.state {
		cp[k] = v
	}
	cp["error"] = failed
	p.state = cp
	if p.hub != nil {
		p.hub.Publish(webui.Event{Kind: "info", Level: "warn", Text: "could not refresh: " + err.Error()})
	}
	return err
}

func (p *uiProvider) publishChanges(st obj) {
	cur := map[string]string{}
	for _, r := range asList(st["routes"]) {
		m := asMap(r)
		cur[asStr(m["id"])] = asStr(m["status"])
	}
	if p.hub != nil {
		p.mu.Lock()
		old := p.prev
		p.mu.Unlock()
		for id, s := range cur {
			switch o, seen := old[id]; {
			case old == nil:
			case !seen:
				p.hub.Publish(webui.Event{Kind: "reload", Level: "info", Target: id, Text: "route added"})
			case o != s && s == "attention":
				p.hub.Publish(webui.Event{Kind: "change", Level: "warn", Target: id, Text: "now needs attention"})
			case o != s:
				p.hub.Publish(webui.Event{Kind: "change", Level: "ok", Target: id, Text: "healthy again"})
			}
		}
		for id := range old {
			if _, ok := cur[id]; !ok {
				p.hub.Publish(webui.Event{Kind: "reload", Level: "info", Target: id, Text: "route removed"})
			}
		}
		if old == nil {
			p.hub.Publish(webui.Event{Kind: "info", Level: "info", Text: fmt.Sprintf("loaded %d routes", len(cur))})
		}
	}
	p.mu.Lock()
	p.prev = cur
	p.mu.Unlock()
}

func (p *uiProvider) State() any {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == nil {
		return nil
	}
	return p.state
}

// uiCommand implements "setura ui".
func uiCommand(cluster *Cluster, rest []string, stdout, stderr io.Writer) (int, error) {
	fs := newFlagSet("ui", stderr)
	setCommandUsage(fs, "ui", newUI(isTTY(stderr), termOptions{}, os.Getenv))
	listen := fs.String("listen", "127.0.0.1:9090", "address to serve the dashboard on")
	snap := fs.String("snapshot", "", "read a Setura snapshot file (re-read when it changes)")
	kube := fs.Bool("kube", false, "read the cluster (default when no --snapshot is given)")
	token := fs.String("token", os.Getenv("SETURA_UI_TOKEN"), "bearer token, required for non-loopback --listen (or SETURA_UI_TOKEN)")
	redact := fs.Bool("redact", false, "mask hostnames, IPs and namespaces in the dashboard")
	interval := fs.Duration("interval", 5*time.Second, "how often to re-read the source")
	var ns string
	fs.StringVar(&ns, "n", "default", "namespace")
	fs.StringVar(&ns, "namespace", "default", "namespace")
	pos, err := parse(fs, rest)
	if err != nil {
		return 2, err
	}
	if len(pos) != 0 || (*snap != "" && *kube) {
		fmt.Fprintln(stderr, "setura ui: use either --snapshot FILE or --kube, with no other arguments")
		exampleHint(stderr, "ui")
		return 2, usageError{"arguments"}
	}
	if *interval < time.Second {
		return 0, userError("--interval must be at least 1s")
	}
	if _, err := webui.NormalizeListen(*listen, *token); err != nil {
		return 0, userError(err.Error())
	}
	mode, source := "cluster", "cluster namespace "+ns
	load := func() (obj, error) { return Snapshot(cluster, ns) }
	if *snap != "" {
		mode, source = "snapshot", *snap
		load = func() (obj, error) { return readSnapshot(*snap) }
	}
	p := &uiProvider{load: load, hub: webui.NewHub(200)}
	p.build = func(s obj) (obj, error) {
		return BuildUIState(s, UIInput{Mode: mode, Source: source, Redact: *redact})
	}
	if err := p.refresh(); err != nil && *snap != "" {
		return 0, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handler := webui.New(webui.Options{State: p.State, Hub: p.hub, Token: *token})
	addr, closeUI, err := webui.Serve(ctx, *listen, *token, handler)
	if err != nil {
		return 0, err
	}
	defer closeUI()
	fmt.Fprintf(stderr, "setura ui: http://%s  (read-only; Ctrl-C to stop)\n", addr)
	tk := time.NewTicker(*interval)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, nil
		case <-tk.C:
			_ = p.refresh()
		}
	}
}

// healthBoard keeps the latest probe result per target for the dashboard.
type healthBoard struct {
	mu    sync.Mutex
	order []string
	rows  map[string]obj
}

func newHealthBoard() *healthBoard { return &healthBoard{rows: map[string]obj{}} }

func (b *healthBoard) Record(r *Report, now time.Time) {
	stage, reason := failure(r)
	b.mu.Lock()
	defer b.mu.Unlock()
	old, seen := b.rows[r.URL]
	since := now.UTC().Format(time.RFC3339)
	if seen && old["ok"] == r.OK {
		since = asStr(old["since"])
	}
	if !seen {
		b.order = append(b.order, r.URL)
	}
	b.rows[r.URL] = obj{"url": r.URL, "ok": r.OK, "stage": stage, "reason": reason, "backend": backendOf(r),
		"ms": r.ElapsedMS, "since": since}
}

func (b *healthBoard) Snapshot() obj {
	b.mu.Lock()
	defer b.mu.Unlock()
	targets := make([]any, 0, len(b.order))
	for _, u := range b.order {
		targets = append(targets, b.rows[u])
	}
	return obj{"targets": targets}
}

// watchUIState builds the dashboard state for "setura watch --ui".
func watchUIState(b *healthBoard, redact bool) func() any {
	return func() any {
		st, err := BuildUIState(nil, UIInput{Mode: "watch", Source: "probes", Health: b.Snapshot(), Redact: redact})
		if err != nil {
			return nil
		}
		return st
	}
}
