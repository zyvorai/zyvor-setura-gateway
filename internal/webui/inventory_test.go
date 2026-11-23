package webui

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInventoryEndpoint(t *testing.T) {
	var off map[string]any
	w := get(t, New(Options{State: routesState}), "/api/inventory", nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &off) != nil || off["available"] != false || !strings.Contains(off["next"].(string), "--learn") {
		t.Fatalf("unconnected: %d %s", w.Code, w.Body)
	}
	h := New(Options{State: routesState, Inventory: func() any { return map[string]any{"inventory": map[string]any{"endpoints": []any{}}} }})
	var on map[string]any
	w = get(t, h, "/api/inventory", nil)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &on) != nil || on["available"] != true || on["data"] == nil {
		t.Fatalf("connected: %d %s", w.Code, w.Body)
	}
	// a token-protected dashboard guards it like every other API
	if w := get(t, New(Options{State: routesState, Token: "tkn", Inventory: func() any { return 1 }}), "/api/inventory", nil); w.Code != 401 {
		t.Errorf("unauthenticated: %d", w.Code)
	}
}

func TestInventoryPageAndPalette(t *testing.T) {
	body := string(page)
	for _, want := range []string{`id="v-inventory"`, `href="#/inventory"`, "function renderInventory", "api/inventory"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	found := false
	for _, it := range buildPalette(routesState(), false, false) {
		found = found || (it.Type == "page" && it.Hash == "#/inventory")
	}
	if !found {
		t.Error("palette has no API inventory page")
	}
}
