package webui

import (
	"encoding/json"
	"net/http"
)

// inventory serves /api/inventory: the learned API inventory with the
// contract status, or a short explanation of how to turn learning on.
func (s *srv) inventory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.o.Inventory == nil {
		json.NewEncoder(w).Encode(map[string]any{
			"available": false,
			"headline":  "No endpoint inventory is connected",
			"detail":    "The built-in gateway learns which endpoints it serves when started with --learn FILE. Names, methods, status codes and timings are kept; request bodies, header values and query values never are.",
			"next":      "setura gateway run --config routes.json --learn inventory.json --ui 127.0.0.1:9090",
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"available": true, "data": s.o.Inventory()})
}
