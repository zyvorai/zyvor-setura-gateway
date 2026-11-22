// Package grafana embeds the Setura Gateway dashboard so `setura gateway
// install --with-monitoring` can print it as a ConfigMap.
package grafana

import _ "embed"

// Dashboard is grafana/setura-gateway.json.
//
//go:embed setura-gateway.json
var Dashboard []byte
