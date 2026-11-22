package setura

import (
	"fmt"
	"io"
	"strings"
)

var commandNames = []string{
	"publish",
	"explain",
	"check",
	"inspect",
	"listeners",
	"gate",
	"compare",
	"snapshot",
	"diff",
	"migrate",
	"replay",
	"map",
	"ui",
	"connections",
	"impact",
	"lint",
	"ai",
	"certs",
	"grpc-health",
	"bench",
	"load",
	"why",
	"doctor",
	"capabilities",
	"exposure",
	"gateway",
	"shadow",
	"completion",
	"watch",
	"history",
	"echo",
	"licence",
	"man",
	"version",
}

// migrateFlags are offered after "setura migrate".
var migrateFlags = []string{"--ingress", "--routes", "--services", "--objects", "--ingress-class", "--namespace", "-A", "--ingress-url", "--gateway-url",
	"--probe-extra", "--address", "--ingress-address", "--gateway-address", "--ca", "--timeout", "--header", "--format"}

// replayFlags are offered after "setura replay".
var replayFlags = []string{"--log", "--before", "--after", "--format", "--limit", "--ignore-weights", "--fail-on", "--default-host", "--before-rate-limit", "--after-rate-limit"}

// gatewayFlags are offered after "setura gateway".
var gatewayFlags = []string{"--config", "--new", "--checks", "--admin", "--observe", "--steps", "--rollback-on-fail", "--max-error-rate",
	"--max-p95", "--keep", "--to", "--force", "--format", "--probe-interval", "--apply-timeout", "--no-steps", "--lock-timeout",
	"--shadow-diff", "--shadow-state", "--admin-token", "--admin-open-ready", "--ocsp-staple", "--kind", "--iterations", "--udp-idle-timeout",
	"--acme-dir", "--acme-directory", "--acme-production", "--acme-email", "--acme-dns-hook", "--acme-challenge", "--proxy-protocol", "--alt-svc"}

// connectionsFlags are offered after "setura connections".
var connectionsFlags = []string{"--admin", "--follow", "--format", "--filter", "--limit", "--interval"}

// licenceFlags are offered after "setura licence".
var licenceFlags = []string{"verify", "show", "--file", "--format"}

var shadowFlags = []string{"--admin", "--follow", "--format", "--fail-under", "--interval"}

// whyFlags are offered after "setura why".
var whyFlags = []string{"--config", "--snapshot", "--admin", "--format", "--grpc", "--sni", "-H", "--header", "--client-ip", "--rate-limit", "--rate-burst", "--rate-key", "--shadow-diff"}

// flagSets maps a command to the flags completed after it. Adding a command's
// flags is one entry here; the three shell scripts are generated from it.
var flagSets = []struct {
	cmd   string
	flags []string
}{
	{"migrate", migrateFlags},
	{"replay", replayFlags},
	{"gateway", gatewayFlags},
	{"shadow", shadowFlags},
	{"why", whyFlags},
	{"connections", connectionsFlags},
	{"licence", licenceFlags},
}

// Completion writes a shell completion script for command names and for the
// flags of the commands in flagSets.
func Completion(shell string, w io.Writer) error {
	names := strings.Join(commandNames, " ")
	switch shell {
	case "bash":
		fmt.Fprintf(w, "_setura() {\n  local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n  if [ \"$COMP_CWORD\" -eq 1 ]; then\n    COMPREPLY=($(compgen -W \"%s\" -- \"$cur\"))\n", names)
		for _, fs := range flagSets {
			fmt.Fprintf(w, "  elif [ \"${COMP_WORDS[1]}\" = %s ] && [[ \"$cur\" == -* ]]; then\n    COMPREPLY=($(compgen -W \"%s\" -- \"$cur\"))\n", fs.cmd, strings.Join(fs.flags, " "))
		}
		fmt.Fprint(w, "  else\n    COMPREPLY=($(compgen -f -- \"$cur\"))\n  fi\n}\ncomplete -F _setura setura\n")
	case "zsh":
		fmt.Fprintf(w, "#compdef setura\n_setura() {\n  if (( CURRENT == 2 )); then\n    compadd %s\n", names)
		for _, fs := range flagSets {
			fmt.Fprintf(w, "  elif [[ ${words[2]} == %s && ${words[CURRENT]} == -* ]]; then\n    compadd -- %s\n", fs.cmd, strings.Join(fs.flags, " "))
		}
		fmt.Fprint(w, "  else\n    _files\n  fi\n}\ncompdef _setura setura\n")
	case "fish":
		fmt.Fprintf(w, "complete -c setura -f -n '__fish_use_subcommand' -a '%s'\n", names)
		for _, fs := range flagSets {
			for _, f := range fs.flags {
				if strings.HasPrefix(f, "--") {
					fmt.Fprintf(w, "complete -c setura -n '__fish_seen_subcommand_from %s' -l %s\n", fs.cmd, f[2:])
				}
			}
		}
	default:
		return userError("completion supports bash, zsh and fish")
	}
	return nil
}
