package setura

import (
	"fmt"
	"io"
	"strings"
)

// roff escapes text for use in a man page body line.
func roff(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "-", `\-`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		s = `\&` + s
	}
	return s
}

// Man writes the setura(1) manual page in roff, derived from the help groups
// so the page cannot drift from the command list.
func Man(w io.Writer) error {
	var cmds [][2]string
	for _, g := range helpGroups {
		for _, e := range g.entries {
			name := e.name
			if e.args != "" {
				name += " " + e.args
			}
			cmds = append(cmds, [2]string{name, e.summary})
		}
	}
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p(".TH SETURA 1 \"\" \"Zyvor Setura\" \"User Commands\"\n")
	p(".SH NAME\nsetura \\- serve, publish and verify Gateway API routes\n")
	p(".SH SYNOPSIS\n.B setura\n[\\fB\\-\\-context\\fR \\fINAME\\fR[,\\fINAME\\fR...] | \\fB\\-\\-all\\-contexts\\fR] \\fICOMMAND\\fR [\\fIflags\\fR]\n")
	p(".SH DESCRIPTION\n.B setura\nforwards Kubernetes Gateway API listeners to IPv4 loopback and verifies\nroutes from the client side.\n")
	p(".SH COMMANDS\n")
	for _, c := range cmds {
		p(".TP\n.B %s\n%s\n", roff(c[0]), roff(c[1]))
	}
	p(".PP\nRun \\fBsetura COMMAND \\-h\\fR for the flags of a command.\n")
	p(".SH MULTIPLE CONTEXTS\n\\fBcheck\\fR, \\fBsnapshot\\fR, \\fBgate\\fR and \\fBlint\\fR accept a comma separated list of kube contexts, or \\fB\\-\\-all\\-contexts\\fR, and merge the results with a per\\-context field. The exit status is unchanged.\n")
	p(".SH ALERTING\n\\fBsetura watch\\fR can post failure and recovery transitions with \\fB\\-\\-alert\\-webhook\\fR and \\fB\\-\\-alert\\-slack\\fR. The URLs are secrets and are never printed. \\fBsetura history\\fR summarizes the file written by \\fB\\-\\-history\\fR.\n")
	p(".SH EXIT STATUS\n.TP\n.B 0\nsuccess\n.TP\n.B 1\nthe check, gate, lint, replay or migrate check failed or found differences\n.TP\n.B 2\nusage or input error\n")
	p(".SH SEE ALSO\nhttps://github.com/zyvorai/zyvor\\-setura\\-gateway\n")
	_, err := io.WriteString(w, b.String())
	return err
}
