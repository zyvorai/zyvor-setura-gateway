package setura

import (
	"fmt"
	"sort"
	"strings"
)

// Support levels for an ingress-nginx annotation on Gateway API.
const (
	// supportFilter: core or extended Gateway API can express it with a route
	// filter or field; the converted route should carry that filter.
	supportFilter = "translatable"
	// supportImpl: only a controller-specific policy resource can express it.
	supportImpl = "implementation-specific"
	// supportNone: nothing in Gateway API (or common policies) replaces it.
	supportNone = "unsupported"
	// supportUnknown: not in the table; review by hand.
	supportUnknown = "unknown"
	// supportIgnored: harmless to drop.
	supportIgnored = "ignored"
)

const nginxPrefix = "nginx.ingress.kubernetes.io/"

type annotationRule struct {
	support string
	filter  string // HTTPRoute filter type that implements it, when translatable
	hint    string
}

// annotationTable maps the part after nginx.ingress.kubernetes.io/ to advice.
// It is a hint table, not a converter: it tells a human where to look.
var annotationTable = map[string]annotationRule{
	"rewrite-target":          {supportFilter, "URLRewrite", "URLRewrite filter (ReplacePrefixMatch or ReplaceFullPath); regex capture groups ($1) have no portable equivalent"},
	"use-regex":               {supportImpl, "", "path match type RegularExpression is implementation-specific; prefer PathPrefix or Exact"},
	"ssl-redirect":            {supportFilter, "RequestRedirect", "RequestRedirect filter with scheme https on the HTTP listener route"},
	"force-ssl-redirect":      {supportFilter, "RequestRedirect", "RequestRedirect filter with scheme https on the HTTP listener route"},
	"permanent-redirect":      {supportFilter, "RequestRedirect", "RequestRedirect filter with statusCode 301"},
	"temporal-redirect":       {supportFilter, "RequestRedirect", "RequestRedirect filter with statusCode 302"},
	"app-root":                {supportFilter, "RequestRedirect", "extra rule matching Exact / with a RequestRedirect filter to the app root"},
	"upstream-vhost":          {supportFilter, "URLRewrite", "URLRewrite filter with hostname"},
	"x-forwarded-prefix":      {supportFilter, "RequestHeaderModifier", "RequestHeaderModifier filter setting X-Forwarded-Prefix"},
	"proxy-set-headers":       {supportFilter, "RequestHeaderModifier", "RequestHeaderModifier filter (header values come from a ConfigMap in nginx)"},
	"custom-headers":          {supportFilter, "ResponseHeaderModifier", "ResponseHeaderModifier filter"},
	"enable-cors":             {supportFilter, "CORS", "CORS filter (extended, newer Gateway API releases) or a controller policy"},
	"cors-allow-origin":       {supportFilter, "CORS", "CORS filter allowOrigins"},
	"cors-allow-methods":      {supportFilter, "CORS", "CORS filter allowMethods"},
	"cors-allow-headers":      {supportFilter, "CORS", "CORS filter allowHeaders"},
	"proxy-read-timeout":      {supportImpl, "", "HTTPRoute rule timeouts.request / backendRequest cover part of this; per-direction timeouts need a controller policy"},
	"proxy-send-timeout":      {supportImpl, "", "controller policy (for example BackendTrafficPolicy); rule timeouts only cover the whole request"},
	"proxy-connect-timeout":   {supportImpl, "", "controller policy; not part of core HTTPRoute"},
	"proxy-body-size":         {supportImpl, "", "no HTTPRoute field; use a controller policy (for example ClientTrafficPolicy or BackendTrafficPolicy) to cap request bodies"},
	"client-body-buffer-size": {supportImpl, "", "controller policy; no portable equivalent"},
	"proxy-buffering":         {supportImpl, "", "controller policy; no portable equivalent"},
	"proxy-buffer-size":       {supportImpl, "", "controller policy; no portable equivalent"},
	"limit-rps":               {supportImpl, "", "rate limiting needs a controller policy (for example BackendTrafficPolicy rateLimit)"},
	"limit-rpm":               {supportImpl, "", "rate limiting needs a controller policy"},
	"limit-connections":       {supportImpl, "", "connection limits need a controller policy"},
	"whitelist-source-range":  {supportImpl, "", "client IP allow list needs a controller policy (for example SecurityPolicy authorization)"},
	"allowlist-source-range":  {supportImpl, "", "client IP allow list needs a controller policy (for example SecurityPolicy authorization)"},
	"denylist-source-range":   {supportImpl, "", "client IP deny list needs a controller policy"},
	"auth-url":                {supportImpl, "", "external auth: ExternalAuth filter (experimental) or a controller policy (for example SecurityPolicy extAuth)"},
	"auth-signin":             {supportImpl, "", "external auth redirect; controller policy"},
	"auth-type":               {supportImpl, "", "basic auth: controller policy (for example SecurityPolicy basicAuth)"},
	"auth-secret":             {supportImpl, "", "basic auth credentials Secret; controller policy"},
	"auth-tls-secret":         {supportImpl, "", "client certificate verification: Gateway listener tls.frontend validation or a controller policy"},
	"auth-tls-verify-client":  {supportImpl, "", "client certificate verification: Gateway listener tls.frontend validation or a controller policy"},
	"backend-protocol":        {supportImpl, "", "set appProtocol on the Service port; HTTPS backends need BackendTLSPolicy, GRPC needs GRPCRoute"},
	"ssl-passthrough":         {supportImpl, "", "use a TLSRoute on a listener with tls.mode Passthrough"},
	"proxy-ssl-secret":        {supportImpl, "", "upstream mTLS: BackendTLSPolicy or a controller policy"},
	"proxy-ssl-verify":        {supportImpl, "", "upstream TLS verification: BackendTLSPolicy"},
	"affinity":                {supportImpl, "", "sessionPersistence on the HTTPRoute rule (experimental) or a controller policy"},
	"session-cookie-name":     {supportImpl, "", "sessionPersistence on the HTTPRoute rule (experimental) or a controller policy"},
	"canary":                  {supportImpl, "", "weighted backendRefs on one rule; header and cookie canary need extra match rules"},
	"canary-weight":           {supportImpl, "", "weighted backendRefs on one rule"},
	"canary-by-header":        {supportImpl, "", "separate rule with a headers match to the canary backend"},
	"canary-by-cookie":        {supportImpl, "", "cookie matching is not part of HTTPRoute; use a controller policy"},
	"load-balance":            {supportImpl, "", "controller policy (for example BackendTrafficPolicy loadBalancer)"},
	"upstream-hash-by":        {supportImpl, "", "controller policy (consistent hash)"},
	"service-upstream":        {supportNone, "", "Gateway API always routes to Service endpoints; verify the controller's behavior"},
	"configuration-snippet":   {supportNone, "", "unsupported: arbitrary nginx config has no Gateway API equivalent; re-express each directive as a filter or policy"},
	"server-snippet":          {supportNone, "", "unsupported: arbitrary nginx config has no Gateway API equivalent; re-express each directive as a filter or policy"},
	"stream-snippet":          {supportNone, "", "unsupported: arbitrary nginx config has no Gateway API equivalent"},
	"location-snippet":        {supportNone, "", "unsupported: arbitrary nginx config has no Gateway API equivalent"},
	"modsecurity-snippet":     {supportNone, "", "unsupported: WAF rules need a controller or external WAF"},
	"enable-modsecurity":      {supportNone, "", "unsupported: WAF needs a controller or external WAF"},
	"enable-owasp-core-rules": {supportNone, "", "unsupported: WAF needs a controller or external WAF"},
	"mirror-target":           {supportFilter, "RequestMirror", "RequestMirror filter"},
	"mirror-host":             {supportFilter, "RequestMirror", "RequestMirror filter"},
	"server-alias":            {supportFilter, "", "add the alias to the route hostnames"},
	"ingress.class":           {supportIgnored, "", "replaced by Gateway parentRefs"},
}

// annotationFinding is one flagged annotation on one Ingress.
type annotationFinding struct {
	Ingress    string `json:"ingress"`
	Annotation string `json:"annotation"`
	Value      string `json:"value,omitempty"`
	Support    string `json:"support"`
	Filter     string `json:"filter,omitempty"`
	Handled    bool   `json:"handled"`
	Hint       string `json:"hint"`
}

// Flagged reports whether the finding should count as a migration difference.
func (a annotationFinding) Flagged() bool {
	return !a.Handled && a.Support != supportIgnored
}

// classifyAnnotations inspects the annotations of one Ingress. filters is the
// set of HTTPRoute filter types present on routes matched to that Ingress.
func classifyAnnotations(ingress string, annotations map[string]string, filters map[string]bool) []annotationFinding {
	var out []annotationFinding
	for _, key := range sortedKeys(annotations) {
		val := annotations[key]
		var name string
		switch {
		case strings.HasPrefix(key, nginxPrefix):
			name = strings.TrimPrefix(key, nginxPrefix)
		case key == "kubernetes.io/ingress.class":
			name = "ingress.class"
		default:
			continue
		}
		if (name == "ssl-redirect" || name == "force-ssl-redirect") && strings.EqualFold(val, "false") {
			continue
		}
		f := annotationFinding{Ingress: ingress, Annotation: key, Value: truncate(val, 80)}
		if r, ok := annotationTable[name]; ok {
			f.Support, f.Filter, f.Hint = r.support, r.filter, r.hint
		} else {
			f.Support = supportUnknown
			f.Hint = "not in the Setura table; check the ingress-nginx docs and the Gateway API implementation guide"
		}
		f.Handled = f.Support == supportFilter && (f.Filter == "" || filters[f.Filter])
		if f.Support == supportFilter && f.Filter == "" {
			f.Handled = false
		}
		out = append(out, f)
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}

// annotationsOf extracts string annotations from an object's metadata.
func annotationsOf(o obj) map[string]string {
	out := map[string]string{}
	for k, v := range asMap(dig(o, "metadata", "annotations")) {
		out[k] = fmt.Sprint(v)
	}
	return out
}

// annotationHintTable returns the table sorted by name, for documentation and
// tests.
func annotationHintTable() []string {
	names := make([]string, 0, len(annotationTable))
	for k := range annotationTable {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}
