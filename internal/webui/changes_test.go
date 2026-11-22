package webui

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func routesState() any {
	return map[string]any{
		"summary": map[string]any{"status": "attention", "headline": "1 route <needs> attention", "detail": "Look at orders."},
		"routes": []any{
			map[string]any{"id": "HTTPRoute/shop/orders", "name": "orders", "status": "attention", "hostnames": []any{"orders.test"},
				"rules": []any{map[string]any{"backends": []any{map[string]any{"name": "orders-v1"}, map[string]any{"name": "orders-v2"}}}}},
			map[string]any{"id": "HTTPRoute/shop/cat", "name": "catalog", "rules": []any{map[string]any{"backends": []any{map[string]any{"name": "orders-v1"}}}}},
		},
	}
}

func TestIndexInlinesInitialState(t *testing.T) {
	h := New(Options{State: routesState})
	w := get(t, h, "/", nil)
	body := w.Body.String()
	if strings.Contains(body, bootMarker) {
		t.Fatal("boot placeholder was not replaced")
	}
	i := strings.Index(body, `id="boot">`)
	if i < 0 {
		t.Fatal("no boot block")
	}
	raw := body[i+len(`id="boot">`) : i+strings.Index(body[i:], "</script>")]
	var st map[string]any
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		t.Fatalf("boot JSON: %v", err)
	}
	if st["routes"] == nil {
		t.Error("boot JSON lacks routes")
	}
	// The headline is rendered into the HTML itself, escaped, with its status.
	if !strings.Contains(body, `<h1 id="headline">1 route &lt;needs&gt; attention</h1>`) || !strings.Contains(body, `id="status" data-st="attention"`) {
		t.Error("headline and status are not server-rendered")
	}
	// A hostile value in the state cannot close the script element.
	h2 := New(Options{State: func() any { return map[string]any{"x": "</script><script>alert(1)</script>"} }})
	if strings.Count(get(t, h2, "/", nil).Body.String(), "</script>") != strings.Count(string(page), "</script>") {
		t.Error("state escaped out of the boot block")
	}
	// The inline script is unchanged, so the CSP hash still matches.
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'sha256-") {
		t.Error("CSP lost its script hash")
	}
}

func TestIndexFallsBackWhenNotReady(t *testing.T) {
	h := New(Options{State: func() any { return nil }})
	w := get(t, h, "/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), bootMarker) || !strings.Contains(w.Body.String(), "Loading routes") {
		t.Fatalf("expected the skeleton page, got %d", w.Code)
	}
}

func TestIndexGzipAndETag(t *testing.T) {
	h := New(Options{State: routesState})
	w := get(t, h, "/", func(r *http.Request) { r.Header.Set("Accept-Encoding", "gzip") })
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("not compressed")
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if !strings.Contains(string(b), "Setura") || len(w.Body.Bytes()) >= len(b) {
		t.Error("gzip body is not smaller than the page")
	}
	etag := w.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	w = get(t, h, "/", func(r *http.Request) { r.Header.Set("If-None-Match", etag) })
	if w.Code != http.StatusNotModified {
		t.Errorf("revalidation: %d", w.Code)
	}
}

func TestPaletteEndpoint(t *testing.T) {
	h := New(Options{State: routesState, Connections: func(int, int64) any { return nil }})
	w := get(t, h, "/api/palette", nil)
	var doc struct{ Items []PaletteItem }
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	has := func(typ, title, frag string) bool {
		for _, it := range doc.Items {
			if it.Type == typ && it.Title == title && (strings.Contains(it.Hash, frag) || strings.Contains(it.URL, frag)) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct{ typ, title, frag string }{
		{"page", "Changes", "#/changes"}, {"page", "Connections", "#/connections"},
		{"route", "orders", "#route=HTTPRoute%2Fshop%2Forders"}, {"backend", "orders-v2", "#q=orders-v2"},
		{"doc", "Dashboard guide", "docs/ui.md"},
	} {
		if !has(c.typ, c.title, c.frag) {
			t.Errorf("palette lacks %s %q (%s)", c.typ, c.title, c.frag)
		}
	}
	n := 0
	for _, it := range doc.Items {
		if it.Type == "backend" && it.Title == "orders-v1" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("backend listed %d times", n)
	}
	// Without connections the page is not offered; without state it still works.
	w = get(t, New(Options{}), "/api/palette", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "Connections") && !strings.Contains(w.Body.String(), "docs/connections.md") {
		t.Errorf("empty palette: %d %s", w.Code, w.Body)
	}
	if get(t, New(Options{Token: "t"}), "/api/palette", func(r *http.Request) { r.Host = "x.test" }).Code != 401 {
		t.Error("palette must honour the token")
	}
}

func TestChangesEndpoints(t *testing.T) {
	w := get(t, New(Options{}), "/api/changes", nil)
	var d map[string]any
	json.Unmarshal(w.Body.Bytes(), &d)
	if d["available"] != false || d["next"] == "" {
		t.Errorf("unconnected: %v", d)
	}
	h := New(Options{
		Changes: func() any { return map[string]any{"available": true, "headline": "x"} },
		ChangeDetail: func(id string) (any, bool) {
			return map[string]any{"id": id}, id == "known"
		},
	})
	if w := get(t, h, "/api/changes", nil); !strings.Contains(w.Body.String(), `"headline":"x"`) {
		t.Errorf("changes: %s", w.Body)
	}
	if w := get(t, h, "/api/changes/known", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"id":"known"`) {
		t.Errorf("detail: %d %s", w.Code, w.Body)
	}
	for _, p := range []string{"/api/changes/nope", "/api/changes/", "/api/changes/a/b"} {
		if get(t, h, p, nil).Code != 404 {
			t.Errorf("%s should 404", p)
		}
	}
	if get(t, New(Options{}), "/api/changes/x", nil).Code != 404 {
		t.Error("detail without a source should 404")
	}
}

// The page wires the palette shortcut, the Changes route and the search deep link.
func TestPageHasPaletteChangesAndDeepLinks(t *testing.T) {
	s := string(page)
	for _, want := range []string{
		`id="boot"`, `role="combobox"`, `role="listbox"`, `aria-keyshortcuts="Control+K Meta+K"`,
		`e.key.toLowerCase()==='k'`, `#/changes`, `'#q='+encodeURIComponent`, `api/palette`, `api/changes/`,
		`prefers-reduced-motion:reduce`, `id="tab-changes"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}
