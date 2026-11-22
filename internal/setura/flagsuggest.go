package setura

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// firstCommand returns the first argument that names a command, or "".
func firstCommand(args []string) string {
	for _, a := range args {
		for _, n := range commandNames {
			if a == n {
				return a
			}
		}
	}
	return ""
}

var undefinedFlagRe = regexp.MustCompile(`flag provided but not defined: -{1,2}([^\s]+)`)

// parseOnce runs fs.Parse. When the stdlib reports an unknown flag it replaces
// the raw message and the full usage dump with one calm line, a suggestion
// drawn from the command's own flags, and a Next: hint. Every other outcome
// (help, bad values) is passed through unchanged.
func parseOnce(fs *flag.FlagSet, args []string) error {
	out := fs.Output()
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	err := fs.Parse(args)
	fs.SetOutput(out)
	if err == nil {
		return nil
	}
	if m := undefinedFlagRe.FindStringSubmatch(err.Error()); m != nil {
		name, _, _ := strings.Cut(m[1], "=")
		writeUnknownFlag(out, fs, name)
		return usageError{"unknown flag"}
	}
	io.Copy(out, &buf)
	return err
}

// writeUnknownFlag prints the unknown-flag verdict, a "did you mean" when a
// defined flag is close, and the command to run for the full list.
func writeUnknownFlag(w io.Writer, fs *flag.FlagSet, name string) {
	var known []string
	fs.VisitAll(func(f *flag.Flag) { known = append(known, f.Name) })
	fmt.Fprintf(w, "setura %s: unknown flag --%s\n", fs.Name(), name)
	if s := nearest(name, known); s != "" {
		dash := "--"
		if len(s) == 1 {
			dash = "-"
		}
		fmt.Fprintf(w, "  Did you mean %s%s?\n", dash, s)
	}
	fmt.Fprintf(w, "  Next: setura %s -h lists every flag, with examples.\n", fs.Name())
}
