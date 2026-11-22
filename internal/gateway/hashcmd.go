package gateway

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"strings"
)

// hashCmd implements "setura gateway hash": it reads a secret from stdin (never
// from an argument, which shell history and process lists would keep) and prints
// the value to store in an API key or basic auth policy.
func hashCmd(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gateway hash", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("kind", "", "apikey or password")
	iter := fs.Int("iterations", 0, "PBKDF2 iterations for passwords (default 600000)")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	line, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		fmt.Fprintf(stderr, "setura gateway hash: %v\n", err)
		return 2
	}
	secret := strings.TrimRight(line, "\r\n")
	if secret == "" {
		fmt.Fprintln(stderr, "setura gateway hash: give the secret on stdin (one line); it is never taken from an argument")
		return 2
	}
	var out string
	switch *kind {
	case "apikey":
		out, err = HashAPIKey(secret)
	case "password":
		out, err = HashPassword(secret, *iter)
	default:
		fmt.Fprintln(stderr, "setura gateway hash: --kind must be apikey or password")
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "setura gateway hash: %v\n", err)
		return 2
	}
	fmt.Fprintln(stdout, out)
	return 0
}
