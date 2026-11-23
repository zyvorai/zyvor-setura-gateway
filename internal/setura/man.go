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
	p(".SH ROUTING DECISIONS\n\\fBsetura why\\fR METHOD URL explains which listener, route, rule and backend the built\\-in gateway picks for a request and why every other candidate lost. It evaluates a gateway config (\\fB\\-\\-config\\fR, \\fB\\-\\-snapshot\\fR) or asks a running gateway (\\fB\\-\\-admin\\fR ADDR, endpoint /why) and sends no traffic. \\fB\\-H\\fR adds request headers, \\fB\\-\\-grpc\\fR service/method explains a gRPC call, \\fB\\-\\-sni\\fR host a TLSRoute connection, \\fB\\-\\-format\\fR json prints the trace. It also shows the trace headers and X\\-Forwarded\\-For the backend receives, the route's retry policy, the rate\\-limit bucket (\\fB\\-\\-rate\\-limit\\fR, \\fB\\-\\-rate\\-burst\\fR, \\fB\\-\\-rate\\-key\\fR model the gateway's policy offline, \\fB\\-\\-admin\\fR adds the live bucket) and mirrors with shadow\\-diff, and a file route's metadata.creationTimestamp breaks ties. It exits 0 when routed, 1 when no route matches and 2 on a usage error.\n.PP\n\\fBsetura replay\\fR reads the gateway's JSON and text access logs and Common or Combined Log Format (\\fB\\-\\-default\\-host\\fR supplies the Host those lack). Besides route, backend, outcome and weight changes it reports retry, timeout, mirror and rate\\-limit policy changes (\\fB\\-\\-before\\-rate\\-limit\\fR, \\fB\\-\\-after\\-rate\\-limit\\fR), flags backends that fail in the log, and replays gRPC calls and TLS passthrough connections through GRPCRoutes and TLSRoutes.\n")
	p(".SH GATEWAY TRAFFIC SECURITY\nThe built\\-in gateway can protect an HTTPRoute rule with an \\fBsetura.zyvor.dev/auth\\fR block (JWT, API key, basic auth, client address lists, required client certificate), validate client certificates on HTTPS listeners (Gateway API frontend TLS validation) and staple OCSP responses (\\fB\\-\\-ocsp\\-staple\\fR). \\fBsetura gateway hash\\fR \\fB\\-\\-kind\\fR apikey|password reads a secret on stdin and prints the hash to store. \\fB\\-\\-admin\\-token\\fR TOKEN (or SETURA_ADMIN_TOKEN) protects the admin endpoint and is required to bind it off loopback; \\fB\\-\\-admin\\-open\\-ready\\fR leaves /ready open. \\fBsetura why\\fR shows whether the credentials given with \\fB\\-H\\fR would pass. Credentials are redacted everywhere. See docs/security.md.\n.PP\nGRPCRoute rules take the same auth block; rejections are Trailers\\-Only gRPC statuses (UNAUTHENTICATED, PERMISSION_DENIED, RESOURCE_EXHAUSTED). \\fB\\-\\-client\\-allow\\-san\\fR and \\fB\\-\\-client\\-allow\\-cn\\fR (or a Gateway's \\fBsetura.zyvor.dev/client\\-allow\\fR annotation) restrict validated client certificates to named SANs or subject CNs, exact or *.suffix; refusals are logged and counted. \\fB\\-\\-client\\-cert\\-xfcc\\fR adds an Envoy\\-style X\\-Forwarded\\-Client\\-Cert header. A RequestHeaderModifier value may use {client_ip}, {request_id}, {host}, {scheme} and {listener}. \\fB\\-\\-access\\-log\\-exclude\\fR PATTERN and \\fB\\-\\-access\\-log\\-sample\\fR N keep requests out of the access log while they still count in metrics. See docs/client\\-cert\\-authz.md and docs/headers\\-and\\-logs.md.\n")
	p(".SH GATEWAY LIMITS AND RESPONSES\nA rule can answer without a backend with a \\fBsetura.zyvor.dev/direct\\-response\\fR block (status, body, headers), carry its own token bucket with \\fBsetura.zyvor.dev/rate\\-limit\\fR (rate, burst, key route|client\\-ip|header:NAME; the gateway\\-wide \\fB\\-\\-rate\\-limit\\fR still applies) and override the gateway limits with \\fBsetura.zyvor.dev/limits\\fR. \\fBsetura gateway run\\fR limits requests with \\fB\\-\\-max\\-request\\-body\\fR (413), \\fB\\-\\-max\\-header\\-bytes\\fR (431), \\fB\\-\\-header\\-read\\-timeout\\fR, \\fB\\-\\-idle\\-timeout\\fR and \\fB\\-\\-stream\\-idle\\-timeout\\fR, normalises paths before routing with \\fB\\-\\-normalize\\-path\\fR, \\fB\\-\\-merge\\-slashes\\fR and \\fB\\-\\-reject\\-escaped\\-slashes\\fR (all off by default) and bounds TLS with \\fB\\-\\-tls\\-min\\-version\\fR and \\fB\\-\\-tls\\-max\\-version\\fR. See docs/direct\\-response.md and docs/limits.md.\n")
	p(".SH EXIT STATUS\n.TP\n.B 0\nsuccess\n.TP\n.B 1\nthe check, gate, lint, replay or migrate check failed or found differences, or why found no route\n.TP\n.B 2\nusage or input error\n")
	p(".SH GATEWAY ROLLOUT\n\\fBsetura gateway rollout\\fR lints a candidate snapshot, backs up the live file in \\fI.setura\\-history\\fR, replaces it atomically, waits for the admin /status generation, runs a checks file for an observation window and restores the backup on any failure. The window is judged on the probes and on the gateway's own /stats and /metrics deltas (\\fB\\-\\-max\\-error\\-rate\\fR and \\fB\\-\\-max\\-p95\\fR apply to both). A candidate that changes canary weights is applied in stages 10,50,100 unless \\fB\\-\\-steps\\fR or \\fB\\-\\-no\\-steps\\fR is given. A rollout lock left by a killed rollout (dead process on this host, or a heartbeat older than \\fB\\-\\-lock\\-timeout\\fR) is taken over; a live owner never is. Relative certificate paths resolve against the candidate's directory. \\fBsetura gateway history\\fR lists the backups and \\fBsetura gateway rollback\\fR restores one.\n")
	p(".SH LICENCE\n\\fBsetura licence verify\\fR [KEY | \\fB\\-\\-file\\fR F] checks a signed ZYV1 licence key offline against the public keys embedded in the binary and prints the tier, cluster limit, expiry, licensee and status (valid, expired, bad signature, wrong product). \\fBsetura licence show\\fR checks the key in SETURA_LICENCE_KEY or the file named by SETURA_LICENCE_FILE (default: setura/licence.key in the user config directory). It exits 0 for a valid key, 1 for an invalid one and 2 on a usage error. Setura works without a key; \\fBsetura version \\-\\-verbose\\fR only reports the status and never blocks a command.\n")
	p(".SH SEE ALSO\nhttps://github.com/zyvorai/zyvor\\-setura\\-gateway\n")
	_, err := io.WriteString(w, b.String())
	return err
}
