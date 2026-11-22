package setura

import (
	"encoding/json"
	"io"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// gatewayLint gates built-in gateway reloads on Setura's own lint rules.
func gatewayLint(raw []byte) (bool, string) {
	var snapshot obj
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return false, err.Error()
	}
	report, err := Lint(snapshot)
	if err != nil {
		return false, err.Error()
	}
	return report["ok"] == true, LintText(report)
}

func runGateway(args []string, stdout, stderr io.Writer) int {
	builtin.DefaultImage = "ghcr.io/zyvorai/zyvor-setura-gateway:" + Version
	return builtin.Main(args, stdout, stderr, gatewayLint)
}

func init() {
	builtin.UIStateBuilder = func(in builtin.UIInput) (any, error) {
		var snap obj
		if err := json.Unmarshal(in.Snapshot, &snap); err != nil {
			return nil, err
		}
		return BuildUIState(snap, UIInput{Mode: "gateway", Source: "built-in gateway", Stats: in.Stats, Reload: in.Reload})
	}
}
