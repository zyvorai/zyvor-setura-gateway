package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/zyvorai/zyvor-setura-gateway/internal/webui"
)

// UIInput is what the dashboard builder receives from a running Server.
type UIInput struct {
	Snapshot []byte // route specs in setura.route-specs/v1 form, secrets excluded
	Stats    any    // Stats.Snapshot()
	Reload   any    // generation and last reload result
	// Connections says whether the connections table is available:
	// {"enabled":true,"capacity":N}. The rows themselves are served live at
	// /api/connections and over the event stream, not in the state document.
	Connections any
}

// UIStateBuilder turns a UIInput into the dashboard state document. The
// setura package installs it (this package cannot import setura).
var UIStateBuilder func(UIInput) (any, error)

// UIChangesBuilder, installed by the setura package, serves the dashboard's
// Changes page from the live config file and its .setura-history backups.
var UIChangesBuilder func(configPath string) (changes func() any, detail func(id string) (any, bool))

func (s *Server) uiChanges() (func() any, func(string) (any, bool)) {
	if UIChangesBuilder == nil || s.opts.ConfigPath == "" {
		return nil, nil
	}
	return UIChangesBuilder(s.opts.ConfigPath)
}

// specSnapshot renders the live configuration as a route-specs snapshot so
// the dashboard can lint and draw it like any other source.
func specSnapshot(c *Config) []byte {
	res := map[string]any{}
	// Objects outside the default namespace keep it in the key, as the file
	// format does, so cross-namespace lint rules see the same picture.
	key := func(kind, ns, name string) string {
		if ns != "" && ns != c.Namespace {
			return kind + "." + APIGroup + "/" + ns + "/" + name
		}
		return kind + "." + APIGroup + "/" + name
	}
	for _, g := range c.Gateways {
		res[key("gateways", g.NS, g.Name)] = gatewaySpec{GatewayClassName: g.ClassName, Listeners: g.Listeners}
	}
	for _, r := range c.Routes {
		res[key("httproutes", r.NS, r.Name)] = routeSpec{ParentRefs: r.Parents, Hostnames: r.Hostnames, Rules: r.Rules}
	}
	for _, r := range c.GRPCRoutes {
		res[key("grpcroutes", r.NS, r.Name)] = grpcRouteSpec{ParentRefs: r.Parents, Hostnames: r.Hostnames, Rules: r.Rules}
	}
	for _, r := range c.TLSRoutes {
		res[key("tlsroutes", r.NS, r.Name)] = tlsRouteSpec{ParentRefs: r.Parents, Hostnames: r.Hostnames, Rules: r.Rules}
	}
	doc := map[string]any{"schema": "setura.route-specs/v1", "namespace": c.Namespace, "resources": res}
	// ReferenceGrants, in the same top-level form a config file uses, so the
	// dashboard's lint grades a missing grant exactly as linting the file does.
	// Present (even empty) only when the source supplied grants.
	if c.GrantsCaptured || len(c.Grants) > 0 {
		grants := []any{}
		for _, g := range c.Grants {
			from, to := []any{}, []any{}
			for _, f := range g.From {
				from = append(from, map[string]any{"group": f.Group, "kind": f.Kind, "namespace": f.Namespace})
			}
			for _, t := range g.To {
				e := map[string]any{"group": t.Group, "kind": t.Kind}
				if t.Name != "" {
					e["name"] = t.Name
				}
				to = append(to, e)
			}
			grants = append(grants, map[string]any{"metadata": map[string]any{"namespace": g.Namespace}, "spec": map[string]any{"from": from, "to": to}})
		}
		doc["referenceGrants"] = grants
	}
	b, _ := json.Marshal(doc)
	return b
}

// UIState returns the current dashboard state, or nil before the first
// configuration is applied.
func (s *Server) UIState() any {
	t := s.Table()
	if t == nil || UIStateBuilder == nil {
		return nil
	}
	in := UIInput{Snapshot: specSnapshot(t.Cfg), Stats: s.stats.Snapshot()}
	if s.conns != nil {
		in.Connections = map[string]any{"enabled": true, "capacity": s.conns.cap}
	}
	if d := s.Status(); d != nil {
		in.Reload = map[string]any{"generation": d.Generation, "ok": d.LastReload.OK, "time": d.LastReload.Time, "error": d.LastReload.Error}
	}
	st, err := UIStateBuilder(in)
	if err != nil {
		return nil
	}
	if m, ok := st.(map[string]any); ok {
		if s.opts.ShadowDiff > 0 || s.shadow.active() {
			m["shadow"] = s.shadow.Summary()
		}
		if c := s.chaosForStatus(); c != nil {
			m["chaos"] = c
		}
		s.hist.start(s.opts.HistoryInterval)
		if hs := s.hist.series(); len(hs) > 0 {
			m["history"] = map[string]any{"series": hs}
		}
	}
	return st
}

// uiFeed publishes reload and traffic events derived from the server's own
// counters, so the proxy hot path stays untouched.
func (s *Server) uiFeed(ctx context.Context, hub *webui.Hub) {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	prev := map[string]Counter{}
	var gen, lastConn int64
	var hadOpen bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		if d := s.Status(); d != nil && d.Generation != gen {
			if gen != 0 {
				hub.Publish(webui.Event{Kind: "reload", Level: "info", Text: fmt.Sprintf("configuration applied (generation %d)", d.Generation)})
			}
			gen = d.Generation
		}
		if s.conns != nil {
			snap := s.PublicConnections(maxConnBatch, lastConn)
			if len(snap.History) > 0 || len(snap.Open) > 0 || hadOpen {
				hub.Broadcast(webui.Event{Kind: "conns", Data: connBatch(snap, lastConn)})
			}
			hadOpen, lastConn = len(snap.Open) > 0, snap.Latest
		}
		cur, _ := s.stats.Snapshot()["routes"].(map[string]Counter)
		for key, c := range cur {
			p := prev[key]
			if n := c.Requests - p.Requests; n > 0 {
				bad := c.Status["5xx"] - p.Status["5xx"]
				ev := webui.Event{Kind: "traffic", Level: "ok", Target: key, Text: fmt.Sprintf("%d %s", n, plural(n, "request", "requests"))}
				if bad > 0 {
					ev.Level, ev.Text = "warn", ev.Text+fmt.Sprintf(", %d server %s", bad, plural(bad, "error", "errors"))
				}
				hub.Publish(ev)
			}
		}
		prev = cur
	}
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// StartUI serves the read-only dashboard for s on addr until ctx ends.
func (s *Server) StartUI(ctx context.Context, addr, token string, diag io.Writer) error {
	hub := webui.NewHub(200)
	ch, cd := s.uiChanges()
	h := webui.New(webui.Options{State: s.UIState, Hub: hub, Token: token, Connections: s.uiConnections(), Changes: ch, ChangeDetail: cd})
	bound, stop, err := webui.Serve(ctx, addr, token, h)
	if err != nil {
		return err
	}
	go func() { s.uiFeed(ctx, hub); stop() }()
	if diag != nil {
		fmt.Fprintf(diag, "dashboard http://%s/ (read-only)\n", bound)
	}
	return nil
}

// UIHandler returns the dashboard as an http.Handler for embedding.
func (s *Server) UIHandler(token string) http.Handler {
	ch, cd := s.uiChanges()
	return webui.New(webui.Options{State: s.UIState, Token: token, Connections: s.uiConnections(), Changes: ch, ChangeDetail: cd})
}

const maxConnBatch = 200

// connBatch is the payload of a "conns" event: the records finished since
// the previous one (oldest first) and the full list of open connections.
// Truncated tells the page to refetch /api/connections instead.
func connBatch(snap *ConnSnapshot, prev int64) map[string]any {
	recs := make([]*logLine, len(snap.History))
	for i, l := range snap.History {
		recs[len(recs)-1-i] = l
	}
	return map[string]any{"records": recs, "open": snap.Open, "latest": snap.Latest,
		"truncated": len(recs) == maxConnBatch && snap.Latest-prev > int64(len(recs))}
}

// uiConnections serves the dashboard's connections table, or nil when the
// history is disabled.
func (s *Server) uiConnections() func(int, int64) any {
	if s.conns == nil {
		return nil
	}
	return func(limit int, since int64) any { return s.PublicConnections(limit, since) }
}
