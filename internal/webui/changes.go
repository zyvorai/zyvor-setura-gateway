package webui

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/http"
	"sort"
	"strings"
)

// bootMarker is where the server-rendered initial state goes. The page keeps
// working without it: the script falls back to skeletons and fetches.
const bootMarker = `<script type="application/json" id="boot">null</script>`

// docPages are the documentation entries offered by the command palette.
var docPages = []struct{ Title, Path, Hint string }{
	{"Dashboard guide", "docs/ui.md", "this page, its shortcuts and endpoints"},
	{"Connections", "docs/connections.md", "who connected, over what, and where it went"},
	{"Terminal output", "docs/terminal.md", "colour, ASCII and NO_COLOR"},
	{"Rollout and rollback", "docs/rollout.md", "guarded config changes and history"},
	{"Replay", "docs/replay.md", "what an access log would do under a new config"},
	{"Why", "docs/why.md", "explain a routing decision"},
	{"Lint rules", "docs/lint-rules.md", "every check and how to fix it"},
	{"Built-in gateway", "docs/builtin-gateway.md", "the data plane"},
	{"Top, init and doctor", "docs/top-init-doctor.md", "live view, scaffolding, health checks"},
}

const docBase = "https://github.com/zyvorai/zyvor-setura-gateway/blob/main/"

// PaletteItem is one jump target of the command palette.
type PaletteItem struct {
	Type     string `json:"type"` // page, route, backend, doc
	Title    string `json:"title"`
	Subtitle string `json:"subtitle,omitempty"`
	Hash     string `json:"hash,omitempty"` // in-page target, for page, route, backend
	URL      string `json:"url,omitempty"`  // external target, for doc
}

func asMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func asList(v any) []any         { l, _ := v.([]any); return l }
func asStr(v any) string         { s, _ := v.(string); return s }

// buildPalette derives the palette from a state document. It tolerates any
// shape: missing sections simply contribute nothing.
func buildPalette(st any, hasChanges, hasConns bool) []PaletteItem {
	items := []PaletteItem{
		{Type: "page", Title: "Overview", Subtitle: "Status, routes and health", Hash: "#/"},
		{Type: "page", Title: "Changes", Subtitle: "What changed and what a rollback would do", Hash: "#/changes"},
	}
	if hasConns {
		items = append(items, PaletteItem{Type: "page", Title: "Connections", Subtitle: "Recent and open connections", Hash: "#/connections"})
	}
	// Normalise through JSON so typed state documents work as well as maps.
	var doc map[string]any
	if b, err := json.Marshal(st); err == nil {
		_ = json.Unmarshal(b, &doc)
	}
	seen := map[string]bool{}
	var backs []PaletteItem
	for _, r := range asList(doc["routes"]) {
		m := asMap(r)
		id, name := asStr(m["id"]), asStr(m["name"])
		if id == "" {
			continue
		}
		var hosts []string
		for _, h := range asList(m["hostnames"]) {
			hosts = append(hosts, asStr(h))
		}
		sub := strings.Join(hosts, ", ")
		if sub == "" {
			sub = "any host"
		}
		if asStr(m["status"]) == "attention" {
			sub += " · needs attention"
		}
		items = append(items, PaletteItem{Type: "route", Title: name, Subtitle: sub, Hash: "#route=" + escapeFrag(id)})
		for _, u := range asList(m["rules"]) {
			for _, b := range asList(asMap(u)["backends"]) {
				bm := asMap(b)
				bn := asStr(bm["name"])
				if bn != "" && !seen[bn] {
					seen[bn] = true
					backs = append(backs, PaletteItem{Type: "backend", Title: bn, Subtitle: "Backend · show the routes that use it", Hash: "#q=" + escapeFrag(bn)})
				}
			}
		}
	}
	sort.SliceStable(backs, func(i, j int) bool { return backs[i].Title < backs[j].Title })
	items = append(items, backs...)
	for _, d := range docPages {
		items = append(items, PaletteItem{Type: "doc", Title: d.Title, Subtitle: d.Hint, URL: docBase + d.Path})
	}
	return items
}

// escapeFrag percent-encodes a fragment value the way encodeURIComponent does
// for the characters that matter here.
func escapeFrag(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte("-_.!~*'()", c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

func (s *srv) palette(w http.ResponseWriter, r *http.Request) {
	var st any
	if s.o.State != nil {
		st = s.o.State()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"items": buildPalette(st, true, s.o.Connections != nil)})
}

func (s *srv) changes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.o.Changes == nil {
		json.NewEncoder(w).Encode(map[string]any{
			"available": false,
			"headline":  "Change history is not connected",
			"detail":    "Point the dashboard at the live configuration file and it shows every rollout here. The gateway does this with --config; setura ui takes --config FILE.",
			"next":      "setura ui --config live.json",
		})
		return
	}
	json.NewEncoder(w).Encode(s.o.Changes())
}

func (s *srv) changeDetail(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/changes/")
	if s.o.ChangeDetail == nil || id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	doc, ok := s.o.ChangeDetail(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

// renderIndex returns the page with the current state inlined so the first
// paint shows real content. When the state is not ready the page is served
// unchanged and falls back to skeletons.
func (s *srv) renderIndex() []byte {
	b, ok := s.snapshot()
	if !ok {
		return page
	}
	out := bytes.Replace(page, []byte(bootMarker), []byte(`<script type="application/json" id="boot">`+string(b)+`</script>`), 1)
	var doc struct {
		Summary struct {
			Status   string `json:"status"`
			Headline string `json:"headline"`
			Detail   string `json:"detail"`
		} `json:"summary"`
	}
	if json.Unmarshal(b, &doc) == nil && doc.Summary.Headline != "" {
		out = bytes.Replace(out, []byte(`<div class="status" id="status" data-st="unknown">`), []byte(`<div class="status" id="status" data-st="`+html.EscapeString(doc.Summary.Status)+`">`), 1)
		out = bytes.Replace(out, []byte(`<h1 id="headline">Loading routes</h1>`), []byte(`<h1 id="headline">`+html.EscapeString(doc.Summary.Headline)+`</h1>`), 1)
		if doc.Summary.Detail != "" {
			out = bytes.Replace(out, []byte(`<p class="detail" id="detail">Reading the current configuration.</p>`), []byte(`<p class="detail" id="detail">`+html.EscapeString(doc.Summary.Detail)+`</p>`), 1)
		}
	}
	return out
}

// writePage sends the page gzip-compressed when the client accepts it. The
// page embeds live state, so it is never stored by caches (no-store), but the
// ETag lets a client that holds it revalidate cheaply on reload.
func writePage(w http.ResponseWriter, r *http.Request, body []byte) {
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Add("Vary", "Accept-Encoding")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		zw, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
		zw.Write(body)
		zw.Close()
		return
	}
	w.Write(body)
}
