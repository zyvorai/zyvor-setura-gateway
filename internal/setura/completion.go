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
	"echo",
	"man",
	"version",
}

// Completion writes a shell completion script for command names.
func Completion(shell string, w io.Writer) error {
	names := strings.Join(commandNames, " ")
	switch shell {
	case "bash":
		fmt.Fprintf(w, "_setura() {\n  local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n  if [ \"$COMP_CWORD\" -eq 1 ]; then\n    COMPREPLY=($(compgen -W \"%s\" -- \"$cur\"))\n  else\n    COMPREPLY=($(compgen -f -- \"$cur\"))\n  fi\n}\ncomplete -F _setura setura\n", names)
	case "zsh":
		fmt.Fprintf(w, "#compdef setura\n_setura() {\n  if (( CURRENT == 2 )); then\n    compadd %s\n  else\n    _files\n  fi\n}\ncompdef _setura setura\n", names)
	case "fish":
		fmt.Fprintf(w, "complete -c setura -f -n '__fish_use_subcommand' -a '%s'\n", names)
	default:
		return userError("completion supports bash, zsh and fish")
	}
	return nil
}
