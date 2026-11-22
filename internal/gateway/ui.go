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
}

// UIStateBuilder turns a UIInput into the dashboard state document. The
// setura package installs it (this package cannot import setura).
var UIStateBuilder func(UIInput) (any, error)

// specSnapshot renders the live configuration as a route-specs snapshot so
// the dashboard can lint and draw it like any other source.
func specSnapshot(c *Config) []byte {
	res := map[string]any{}
	for _, g := range c.Gateways {
		res["gateways.gateway.networking.k8s.io/"+g.Name] = gatewaySpec{GatewayClassName: g.ClassName, Listeners: g.Listeners}
	}
	for _, r := range c.Routes {
		res["httproutes.gateway.networking.k8s.io/"+r.Name] = routeSpec{ParentRefs: r.Parents, Hostnames: r.Hostnames, Rules: r.Rules}
	}
	b, _ := json.Marshal(map[string]any{"schema": "setura.route-specs/v1", "namespace": c.Namespace, "resources": res})
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
	if d := s.Status(); d != nil {
		in.Reload = map[string]any{"generation": d.Generation, "ok": d.LastReload.OK, "time": d.LastReload.Time, "error": d.LastReload.Error}
	}
	st, err := UIStateBuilder(in)
	if err != nil {
		return nil
	}
	if m, ok := st.(map[string]any); ok && (s.opts.ShadowDiff > 0 || s.shadow.active()) {
		m["shadow"] = s.shadow.Summary()
	}
	return st
}

// uiFeed publishes reload and traffic events derived from the server's own
// counters, so the proxy hot path stays untouched.
func (s *Server) uiFeed(ctx context.Context, hub *webui.Hub) {
	tk := time.NewTicker(time.Second)
	defer tk.Stop()
	prev := map[string]Counter{}
	var gen int64
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
	h := webui.New(webui.Options{State: s.UIState, Hub: hub, Token: token})
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
	return webui.New(webui.Options{State: s.UIState, Token: token})
}
