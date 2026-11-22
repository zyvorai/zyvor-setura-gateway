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
	"map",
	"impact",
	"lint",
	"ai",
	"certs",
	"grpc-health",
	"bench",
	"doctor",
	"capabilities",
	"exposure",
	"gateway",
	"completion",
	"watch",
	"history",
	"echo",
	"man",
	"version",
}

// migrateFlags are offered after "setura migrate".
var migrateFlags = []string{"--ingress", "--routes", "--services", "--objects", "--ingress-class", "--namespace", "-A", "--ingress-url", "--gateway-url",
	"--probe-extra", "--address", "--ingress-address", "--gateway-address", "--ca", "--timeout", "--header", "--format"}

// Completion writes a shell completion script for command names, and for the
// flags of "migrate".
func Completion(shell string, w io.Writer) error {
	names := strings.Join(commandNames, " ")
	flags := strings.Join(migrateFlags, " ")
	switch shell {
	case "bash":
		fmt.Fprintf(w, "_setura() {\n  local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n  if [ \"$COMP_CWORD\" -eq 1 ]; then\n    COMPREPLY=($(compgen -W \"%s\" -- \"$cur\"))\n  elif [ \"${COMP_WORDS[1]}\" = migrate ] && [[ \"$cur\" == -* ]]; then\n    COMPREPLY=($(compgen -W \"%s\" -- \"$cur\"))\n  else\n    COMPREPLY=($(compgen -f -- \"$cur\"))\n  fi\n}\ncomplete -F _setura setura\n", names, flags)
	case "zsh":
		fmt.Fprintf(w, "#compdef setura\n_setura() {\n  if (( CURRENT == 2 )); then\n    compadd %s\n  elif [[ ${words[2]} == migrate && ${words[CURRENT]} == -* ]]; then\n    compadd -- %s\n  else\n    _files\n  fi\n}\ncompdef _setura setura\n", names, flags)
	case "fish":
		fmt.Fprintf(w, "complete -c setura -f -n '__fish_use_subcommand' -a '%s'\n", names)
		for _, f := range migrateFlags {
			if strings.HasPrefix(f, "--") {
				fmt.Fprintf(w, "complete -c setura -n '__fish_seen_subcommand_from migrate' -l %s\n", f[2:])
			}
		}
	default:
		return userError("completion supports bash, zsh and fish")
	}
	return nil
}
