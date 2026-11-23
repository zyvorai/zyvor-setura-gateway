package gateway

import (
	"fmt"
	"sort"
	"strings"
)

// Envoy Gateway compatibility. EnvoyCompatTable is the single list of the
// Envoy Gateway policy fields Setura knows about: what each becomes in Setura
// and whether it is applied. The translator (envoy_translate.go) takes its
// statuses and its messages for ignored fields from it, `setura migrate
// convert --compat-report` prints it and docs/envoy-gateway-compat.md is
// generated from it, so the controller, the converter and the documentation
// cannot drift apart.

// Support levels of a field.
const (
	CompatSupported   = "Supported"
	CompatPartial     = "Partial"
	CompatUnsupported = "Unsupported"
)

// Envoy Gateway API identifiers.
const (
	EnvoyGroup   = "gateway.envoyproxy.io"
	EnvoyVersion = "v1alpha1"
	// EnvoyFaultTTLAnnotation sets the ttl of the fault a faultInjection field becomes.
	EnvoyFaultTTLAnnotation = "setura.zyvor.dev/fault-ttl"
	// EnvoyFailOpenAnnotation on a policy keeps traffic open where a security field cannot be translated.
	EnvoyFailOpenAnnotation = "setura.zyvor.dev/compat-fail-open"
	// DefaultEnvoyFaultTTL is how long a translated fault lasts; Setura faults always end.
	DefaultEnvoyFaultTTL = "24h"
)

// Envoy policy kinds, with the plural resource name of each.
var EnvoyKinds = []struct{ Kind, Plural string }{
	{"BackendTrafficPolicy", "backendtrafficpolicies"},
	{"ClientTrafficPolicy", "clienttrafficpolicies"},
	{"SecurityPolicy", "securitypolicies"},
	{"HTTPRouteFilter", "httproutefilters"},
	{"Backend", "backends"},
}

// CompatRow is one Envoy Gateway field.
type CompatRow struct {
	Kind   string // BackendTrafficPolicy, ClientTrafficPolicy, SecurityPolicy, HTTPRouteFilter, Backend or All
	Field  string // path below spec
	Status string // Supported, Partial or Unsupported
	Setura string // what it becomes, or what to use instead
	Note   string // limits of the translation, or why it is ignored
}

func row(kind, field, status, setura, note string) CompatRow {
	return CompatRow{kind, field, status, setura, note}
}

const (
	kBT  = "BackendTrafficPolicy"
	kCT  = "ClientTrafficPolicy"
	kSP  = "SecurityPolicy"
	kHRF = "HTTPRouteFilter"
	kBK  = "Backend"
	kALL = "All"
	sS   = CompatSupported
	sP   = CompatPartial
	sU   = CompatUnsupported
)

// EnvoyCompatTable lists every field, in the order of the generated document.
var EnvoyCompatTable = []CompatRow{
	row(kALL, "targetRefs", sS, "targets resolved by the controller: Gateway, listener (sectionName), HTTPRoute, GRPCRoute, rule (sectionName)", "Envoy Gateway precedence: the most specific target wins"),
	row(kALL, "targetRef", sS, "same as targetRefs", "deprecated single target"),
	row(kALL, "targetSelectors", sS, "labels select HTTPRoutes, GRPCRoutes or Gateways", "matchLabels only; matchExpressions are not read"),
	row(kALL, "mergeType", sS, "StrategicMerge and JSONMerge merge the policy over the one it overrides", "lists of objects with a name merge by name under StrategicMerge, other lists are replaced"),

	row(kBT, "retry.numRetries", sS, "rule retry.attempts", "default 2 when retry is set without numRetries"),
	row(kBT, "retry.retryOn.httpStatusCodes", sS, "rule retry.codes", ""),
	row(kBT, "retry.retryOn.triggers", sP, "the gateway retries connection failures and the listed status codes", "other triggers (reset, retriable-4xx, ...) are ignored"),
	row(kBT, "retry.perRetry.timeout", sS, "rule retry.perTryTimeout", ""),
	row(kBT, "retry.perRetry.backOff.baseInterval", sS, "rule retry.backoff", ""),
	row(kBT, "retry.perRetry.backOff.maxInterval", sU, "none", "Setura doubles the backoff without a cap field"),
	row(kBT, "timeout.http.requestTimeout", sS, "rule timeouts.request", ""),
	row(kBT, "timeout.http.connectionIdleTimeout", sU, "gateway flag --idle-timeout (gateway wide)", "Setura has no per-route connection idle timeout"),
	row(kBT, "timeout.http.maxConnectionDuration", sU, "none", ""),
	row(kBT, "timeout.tcp.connectTimeout", sU, "none", "the dial timeout of the proxy is fixed"),
	row(kBT, "circuitBreaker.maxConnections", sS, "backend circuitBreaker.maxConnections", "applies to the Service the targeted rules send to, so every route using it shares the limit"),
	row(kBT, "circuitBreaker.maxPendingRequests", sS, "backend circuitBreaker.maxPending", ""),
	row(kBT, "circuitBreaker.maxParallelRequests", sS, "backend circuitBreaker.maxRequests", ""),
	row(kBT, "circuitBreaker.maxParallelRetries", sU, "gateway flag --retry-budget (a percentage of recent requests)", ""),
	row(kBT, "circuitBreaker.maxRequestsPerConnection", sU, "none", ""),
	row(kBT, "circuitBreaker.perEndpoint", sU, "none", "Setura limits per backend, not per endpoint"),
	row(kBT, "loadBalancer", sU, "none", "this Setura gateway balances weighted backendRefs and has no least request, random, consistent hash or slow start policy"),
	row(kBT, "healthCheck.active.type", sP, "backend healthCheck.protocol (http or grpc)", "TCP checks are ignored"),
	row(kBT, "healthCheck.active.interval", sS, "backend healthCheck.interval", ""),
	row(kBT, "healthCheck.active.timeout", sS, "backend healthCheck.timeout", ""),
	row(kBT, "healthCheck.active.unhealthyThreshold", sS, "backend healthCheck.unhealthyThreshold", ""),
	row(kBT, "healthCheck.active.healthyThreshold", sS, "backend healthCheck.healthyThreshold", ""),
	row(kBT, "healthCheck.active.http.path", sS, "backend healthCheck.path", ""),
	row(kBT, "healthCheck.active.http.method", sU, "none", "checks are GET requests"),
	row(kBT, "healthCheck.active.http.expectedStatuses", sU, "none", "any 2xx or 3xx answer is healthy"),
	row(kBT, "healthCheck.active.http.expectedResponse", sU, "none", ""),
	row(kBT, "healthCheck.active.grpc.service", sS, "backend healthCheck.service", ""),
	row(kBT, "healthCheck.active.tcp", sU, "none", ""),
	row(kBT, "healthCheck.passive.consecutive5XxErrors", sP, "backend circuitBreaker.failureThreshold", "Setura opens a circuit for the whole backend, Envoy ejects single endpoints; gateway flag --outlier-failures ejects endpoints"),
	row(kBT, "healthCheck.passive.baseEjectionTime", sP, "backend circuitBreaker.openFor", ""),
	row(kBT, "healthCheck.passive.interval", sU, "none", ""),
	row(kBT, "healthCheck.passive.maxEjectionPercent", sU, "none", ""),
	row(kBT, "healthCheck.passive.splitExternalLocalOriginErrors", sU, "none", ""),
	row(kBT, "healthCheck.passive.consecutiveLocalOriginFailures", sU, "none", ""),
	row(kBT, "healthCheck.passive.consecutiveGatewayErrors", sU, "none", ""),
	row(kBT, "rateLimit.type", sP, "Local is translated, Global is not", "Global needs a shared rate limit service"),
	row(kBT, "rateLimit.local.rules", sP, "rule setura.zyvor.dev/rate-limit (rate, key)", "one bucket per rule: the first rule is used; a rule with no clientSelectors limits the route (key route), one on sourceCIDR with type Distinct limits per client address (key client-ip) and ignores the CIDR"),
	row(kBT, "rateLimit.global", sU, "none", "Setura has no shared rate limit service"),
	row(kBT, "faultInjection.delay.fixedDelay", sP, "rule setura.zyvor.dev/fault latency.delay", "Setura faults always end: the fault gets ttl 24h, change it with the setura.zyvor.dev/fault-ttl annotation on the policy"),
	row(kBT, "faultInjection.delay.percentage", sP, "fault latency.percent", "rounded up to a whole percent"),
	row(kBT, "faultInjection.abort.httpStatus", sP, "fault abort.status", "same ttl rule as the delay"),
	row(kBT, "faultInjection.abort.percentage", sP, "fault abort.percent", "rounded up to a whole percent"),
	row(kBT, "faultInjection.abort.grpcStatus", sU, "none", "aborts answer with an HTTP status"),
	row(kBT, "mirrors", sS, "RequestMirror filter on the targeted rules", "the percentage becomes the mirror percent"),
	row(kBT, "proxyProtocol.version", sS, "backend proxyProtocol (v1 or v2)", ""),
	row(kBT, "compression", sU, "none", "this Setura gateway does not compress responses"),
	row(kBT, "tcpKeepalive", sU, "none", ""),
	row(kBT, "connection.bufferLimit", sU, "gateway flags --max-request-body and --max-header-bytes (different meaning)", "Envoy sizes connection buffers, Setura limits request bodies and headers"),
	row(kBT, "dns", sU, "none", ""),
	row(kBT, "http2", sU, "none", ""),
	row(kBT, "useClientProtocol", sU, "none", ""),
	row(kBT, "telemetry", sU, "gateway flags --otlp-endpoint and --access-log-*", ""),
	row(kBT, "httpUpgrade", sU, "none", "WebSocket and other upgrades are proxied as they come"),
	row(kBT, "requestBuffer", sU, "none", ""),
	row(kBT, "decompression", sU, "none", ""),
	row(kBT, "responseOverride", sU, "none", ""),
	row(kBT, "routingType", sU, "none", ""),

	row(kCT, "tls.minVersion", sP, "listener tls.options setura.zyvor.dev/tls-min-version", "1.2 and 1.3; 1.0 and 1.1 become 1.2, the floor of Setura"),
	row(kCT, "tls.maxVersion", sP, "listener tls.options setura.zyvor.dev/tls-max-version", "1.2 and 1.3; a maximum below 1.2 cannot be met and is ignored"),
	row(kCT, "tls.clientValidation.caCertificateRefs", sS, "Gateway spec.tls.frontend validation.caCertificateRefs (the port of the listener)", ""),
	row(kCT, "tls.clientValidation.optional", sS, "frontend validation mode AllowInsecureFallback", ""),
	row(kCT, "tls.ciphers", sU, "none", "Go picks the cipher suites"),
	row(kCT, "tls.ecdhCurves", sU, "none", ""),
	row(kCT, "tls.signatureAlgorithms", sU, "none", ""),
	row(kCT, "tls.alpnProtocols", sU, "none", "h2 and http/1.1 are always offered"),
	row(kCT, "tls.session", sU, "none", ""),
	row(kCT, "enableProxyProtocol", sU, "gateway flag --proxy-protocol PORT=CIDR[,..]", "Setura accepts PROXY headers only from named source networks, so it cannot be switched on by a bare boolean"),
	row(kCT, "clientIPDetection", sU, "gateway flag --trusted-proxies CIDR[,..]", "gateway wide, not per listener"),
	row(kCT, "path.escapedSlashesAction", sU, "gateway flag --reject-escaped-slashes", "gateway wide, not per listener"),
	row(kCT, "path.disableMergeSlashes", sU, "gateway flag --merge-slashes (off by default)", "gateway wide, not per listener"),
	row(kCT, "timeout.http.requestReceivedTimeout", sU, "gateway flag --header-read-timeout", "gateway wide, not per listener"),
	row(kCT, "timeout.http.idleTimeout", sU, "gateway flag --idle-timeout", "gateway wide, not per listener"),
	row(kCT, "timeout.tcp.idleTimeout", sU, "gateway flag --idle-timeout", "gateway wide, not per listener"),
	row(kCT, "connection.connectionLimit", sU, "none", ""),
	row(kCT, "connection.bufferLimit", sU, "gateway flag --max-request-body (different meaning)", ""),
	row(kCT, "connection.socketBufferLimit", sU, "none", ""),
	row(kCT, "tcpKeepalive", sU, "none", ""),
	row(kCT, "headers", sU, "none", ""),
	row(kCT, "http1", sU, "none", ""),
	row(kCT, "http2", sU, "none", ""),
	row(kCT, "http3", sU, "none", "put an HTTP/3 edge in front and set --alt-svc (see docs/http3.md)"),
	row(kCT, "healthCheck", sU, "none", ""),

	row(kSP, "cors.allowOrigins", sS, "CORS filter allowOrigins", ""),
	row(kSP, "cors.allowMethods", sS, "CORS filter allowMethods", ""),
	row(kSP, "cors.allowHeaders", sS, "CORS filter allowHeaders", ""),
	row(kSP, "cors.exposeHeaders", sS, "CORS filter exposeHeaders", ""),
	row(kSP, "cors.allowCredentials", sS, "CORS filter allowCredentials", ""),
	row(kSP, "cors.maxAge", sS, "CORS filter maxAge (seconds)", ""),
	row(kSP, "jwt.providers", sP, "rule auth jwt", "one issuer per rule: the first provider is used, tokens of the others are refused"),
	row(kSP, "jwt.providers.issuer", sS, "auth jwt.issuer", ""),
	row(kSP, "jwt.providers.audiences", sS, "auth jwt.audience", "always set one (lint rule SET016)"),
	row(kSP, "jwt.providers.remoteJWKS", sS, "auth jwt.jwksUri", ""),
	row(kSP, "jwt.providers.localJWKS", sS, "auth jwt.jwks", "inline key sets only"),
	row(kSP, "jwt.providers.claimToHeaders", sS, "auth jwt.claimHeaders", ""),
	row(kSP, "jwt.providers.forwardAccessToken", sS, "auth jwt.stripToken (the inverse)", ""),
	row(kSP, "jwt.providers.extractFrom", sU, "none", "the token is read from Authorization: Bearer"),
	row(kSP, "jwt.providers.recomputeRoute", sU, "none", ""),
	row(kSP, "jwt.optional", sU, "none", "a rule with a JWT policy always requires a valid token"),
	row(kSP, "apiKeyAuth.credentialRefs", sS, "auth apiKey.keys", "the controller reads the Secrets (one key per data entry) and stores salted hashes; the converter cannot read Secrets and leaves a TODO"),
	row(kSP, "apiKeyAuth.extractFrom", sP, "auth apiKey.header or apiKey.query", "the first header or query parameter is used; cookies are not supported"),
	row(kSP, "apiKeyAuth.sanitize", sS, "auth apiKey.forward (the inverse)", ""),
	row(kSP, "apiKeyAuth.forwardClientIDHeader", sU, "none", ""),
	row(kSP, "basicAuth", sU, "auth basic, with users made by setura gateway hash --kind password", "Envoy reads htpasswd entries (bcrypt, SHA-1), Setura stores pbkdf2-sha256 hashes, so no user can be carried over; the controller refuses the targeted traffic until the policy is fixed"),
	row(kSP, "oidc", sU, "auth jwt on the tokens your identity provider issues", "Setura does not run the authorization code flow; the controller refuses the targeted traffic"),
	row(kSP, "extAuth.http", sS, "ExternalAuth filter (protocol HTTP)", ""),
	row(kSP, "extAuth.grpc", sS, "ExternalAuth filter (protocol GRPC)", ""),
	row(kSP, "extAuth.headersToBackend", sS, "ExternalAuth http.allowedResponseHeaders", ""),
	row(kSP, "extAuth.headersToExtAuth", sS, "ExternalAuth allowedHeaders", ""),
	row(kSP, "extAuth.bodyToExtAuth", sU, "none", ""),
	row(kSP, "extAuth.failOpen", sU, "none", "the check fails closed"),
	row(kSP, "extAuth.recomputeRoute", sU, "none", ""),
	row(kSP, "authorization.defaultAction", sS, "auth ipAllow (Deny) or no restriction (Allow)", ""),
	row(kSP, "authorization.rules.principal.clientCIDRs", sS, "auth ipAllow and ipDeny", "rules that name only clientCIDRs"),
	row(kSP, "authorization.rules.principal.jwt", sU, "none", "claim and scope rules need a policy engine; the controller refuses the targeted traffic"),
	row(kSP, "authorization.rules.principal.headers", sU, "none", "the controller refuses the targeted traffic"),
	row(kSP, "authorization.rules.operation", sU, "none", "the controller refuses the targeted traffic"),

	row(kHRF, "directResponse.statusCode", sS, "rule setura.zyvor.dev/direct-response status", "an HTTPRoute rule with an ExtensionRef filter to the HTTPRouteFilter answers without backendRefs"),
	row(kHRF, "directResponse.contentType", sS, "direct-response headers Content-Type", ""),
	row(kHRF, "directResponse.body", sP, "direct-response body", "inline bodies only (64 KiB at most)"),
	row(kHRF, "urlRewrite.path.replaceRegexMatch", sU, "URLRewrite filter with replaceFullPath or replacePrefixMatch", "Setura rewrites paths without regular expressions; rewrite the route by hand"),
	row(kHRF, "urlRewrite.hostname", sU, "URLRewrite filter hostname", "only a fixed hostname maps; the Header and Backend types do not"),
	row(kHRF, "credentialInjection", sU, "none", ""),

	row(kBK, "endpoints.fqdn", sS, "upstream endpoint host:port", "backendRefs of kind Backend resolve to a backend made from the endpoints"),
	row(kBK, "endpoints.ip", sS, "upstream endpoint host:port", ""),
	row(kBK, "endpoints.unix", sU, "none", "unix sockets are not dialled"),
	row(kBK, "appProtocols", sP, "backend protocol h2c", "only gateway.envoyproxy.io/h2c is understood"),
	row(kBK, "type", sU, "none", "DynamicResolver backends are not supported"),
	row(kBK, "tls", sU, "BackendTLSPolicy on the Backend's Service", ""),
	row(kBK, "fallback", sU, "none", ""),
}

// compatRow finds the row of a field: the exact path, then its parents.
func compatRow(kind, field string) (CompatRow, bool) {
	for f := field; f != ""; {
		for _, r := range EnvoyCompatTable {
			if (r.Kind == kind || r.Kind == kALL) && r.Field == f {
				return r, true
			}
		}
		i := strings.LastIndex(f, ".")
		if i < 0 {
			break
		}
		f = f[:i]
	}
	return CompatRow{}, false
}

// EnvoyCompatRows returns the table, optionally for one kind.
func EnvoyCompatRows(kind string) []CompatRow {
	var out []CompatRow
	for _, r := range EnvoyCompatTable {
		if kind == "" || r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// EnvoyCompatCounts counts the rows of each status.
func EnvoyCompatCounts() map[string]int {
	c := map[string]int{}
	for _, r := range EnvoyCompatTable {
		c[r.Status]++
	}
	return c
}

// EnvoyCompatText renders the table for a terminal, one block per kind.
func EnvoyCompatText() string {
	var b strings.Builder
	for _, k := range compatKindOrder() {
		fmt.Fprintf(&b, "%s\n", compatHeading(k))
		for _, r := range EnvoyCompatRows(k) {
			fmt.Fprintf(&b, "  %-12s %-46s %s", r.Status, r.Field, r.Setura)
			if r.Note != "" {
				fmt.Fprintf(&b, " (%s)", r.Note)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

func compatKindOrder() []string { return []string{kALL, kBT, kCT, kSP, kHRF, kBK} }

func compatHeading(k string) string {
	if k == kALL {
		return "All policies"
	}
	return k
}

// EnvoyCompatMarkdown renders docs/envoy-gateway-compat.md.
func EnvoyCompatMarkdown() string {
	var b strings.Builder
	b.WriteString("# Envoy Gateway compatibility table\n\n")
	b.WriteString("<!-- Generated by `setura migrate convert --compat-report --format markdown`; do not edit. `make compat` regenerates it and TestEnvoyCompatDocInSync keeps it current. -->\n\n")
	b.WriteString("Every Envoy Gateway policy field Setura knows about, the Setura setting it becomes and whether it is applied. ")
	b.WriteString("The controller (`setura gateway run --kubernetes --envoy-compat`) and `setura migrate convert --from envoy-gateway` translate from this one table; ")
	b.WriteString("how to switch is in [envoy-compat.md](envoy-compat.md).\n\n")
	c := EnvoyCompatCounts()
	fmt.Fprintf(&b, "%d fields: %d Supported, %d Partial, %d Unsupported.\n\n", len(EnvoyCompatTable), c[sS], c[sP], c[sU])
	b.WriteString("- **Supported**: translated and enforced.\n- **Partial**: translated with the limits named in the notes.\n- **Unsupported**: ignored; the policy status lists it with reason `Unsupported`, and a field that guards traffic (`basicAuth`, `oidc`, JWT and header authorization rules) makes the controller refuse the targeted traffic instead of serving it open.\n\n")
	for _, k := range compatKindOrder() {
		fmt.Fprintf(&b, "## %s\n\n", compatHeading(k))
		b.WriteString("| Field | Status | Setura equivalent | Notes |\n|-------|--------|-------------------|-------|\n")
		for _, r := range EnvoyCompatRows(k) {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.Field, r.Status, mdCell(r.Setura), mdCell(r.Note))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func mdCell(s string) string {
	if s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "|", "\\|")
}

// EnvoyCompatFields lists the field paths of a kind (for tests and completion).
func EnvoyCompatFields(kind string) []string {
	var out []string
	for _, r := range EnvoyCompatRows(kind) {
		out = append(out, r.Field)
	}
	sort.Strings(out)
	return out
}
