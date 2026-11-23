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
	if len(args) > 0 {
		switch args[0] {
		case "rollout", "history", "rollback":
			return runRolloutCommand(args[0], args[1:], stdout, stderr)
		case "ai-usage":
			return runAIUsage(args[1:], stdout, stderr)
		}
	}
	builtin.DefaultImage = "ghcr.io/zyvorai/zyvor-setura-gateway:" + Version
	return builtin.Main(args, stdout, stderr, gatewayLint)
}

func init() {
	builtin.UIChangesBuilder = func(path string) (func() any, func(string) (any, bool)) {
		return newChangesSource(path).attach()
	}
	builtin.UIStateBuilder = func(in builtin.UIInput) (any, error) {
		var snap obj
		if err := json.Unmarshal(in.Snapshot, &snap); err != nil {
			return nil, err
		}
		return BuildUIState(snap, UIInput{Mode: "gateway", Source: "built-in gateway", Stats: in.Stats, Reload: in.Reload, Connections: in.Connections})
	}
}

// wantsCheck reports whether install's arguments ask for --check.
func wantsCheck(args []string) bool {
	for _, a := range args {
		if a == "--check" || a == "-check" || a == "--check=true" || a == "-check=true" {
			return true
		}
	}
	return false
}
