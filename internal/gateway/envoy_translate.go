package gateway

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Translation of Envoy Gateway policy specs into Setura settings. Specs are
// plain decoded JSON or YAML (map[string]any), which is what both the
// offline converter and the controller hold. The result uses the JSON names
// of Setura's own types (a rule's retry, timeouts and setura.zyvor.dev/*
// fields, a BackendDef, a listener's TLS options), so the controller decodes
// it straight into them and the converter writes it into manifests.

// FieldNote says what happened to one field of a policy.
type FieldNote struct {
	Kind    string `json:"kind"`
	Field   string `json:"field"`
	Value   string `json:"value,omitempty"`
	Status  string `json:"status"`          // Supported, Partial or Unsupported, from the table
	Where   string `json:"where,omitempty"` // rule, backend, listener, frontend or none
	Setura  string `json:"setura,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Ignored bool   `json:"ignored,omitempty"` // the field, or part of it, has no effect
}

// Applied reports whether the field was translated.
func (n FieldNote) Applied() bool { return n.Status != CompatUnsupported }

// EnvoySecretRef is a Secret a policy field names.
type EnvoySecretRef struct {
	Purpose   string // apiKey
	Name      string
	Namespace string
}

// EnvoyOptions tune a translation.
type EnvoyOptions struct {
	// TargetKind is HTTPRoute (default), GRPCRoute or Gateway: GRPCRoute rules take auth only.
	TargetKind string
	// FaultTTL is the ttl of a translated fault (default 24h).
	FaultTTL string
	// Name labels a translated fault.
	Name string
	// Namespace is the namespace of the policy, where the Secrets it names live.
	Namespace string
	// Redis is the NAME of the --redis server a global rate limit counts in; empty ignores the field.
	Redis string
	// OIDCCookieKey is where the OIDC session cookie key comes from (env:NAME, file:PATH, secret:[NS/]NAME#KEY).
	OIDCCookieKey string
}

// EnvoyOptionsFor reads the translation options of a policy: its annotations and namespace.
func EnvoyOptionsFor(annotations map[string]string, ns, name, targetKind string) EnvoyOptions {
	return EnvoyOptions{
		TargetKind: targetKind, Name: "envoy-" + name, Namespace: ns,
		FaultTTL:      annotations[EnvoyFaultTTLAnnotation],
		Redis:         strings.TrimSpace(annotations[EnvoyRedisAnnotation]),
		OIDCCookieKey: strings.TrimSpace(annotations[EnvoyOIDCCookieKeyAnnotation]),
	}
}

// EnvoyTranslation is what one policy spec becomes.
type EnvoyTranslation struct {
	Rule     map[string]any   // rule fields: retry, timeouts, setura.zyvor.dev/rate-limit, /fault, /compress, /limits
	Auth     map[string]any   // the rule's setura.zyvor.dev/auth block, without secrets
	APIKey   map[string]any   // apiKey block (header, query, forward) waiting for the keys of SecretRefs
	Filters  []map[string]any // filters to add to every targeted rule
	Backend  map[string]any   // BackendDef fields of the Services the rules send to (circuitBreaker, healthCheck, proxyProtocol, loadBalancer)
	Listener map[string]any   // tlsMinVersion, tlsMaxVersion, tlsCipherSuites, tlsSessionResumption, limits
	Frontend map[string]any   // caCertificateRefs, mode and setura.zyvor.dev/client-allow of client certificate validation
	// SecretRefs name the Secrets APIKey needs; FailClosed lists the fields that guard traffic and could
	// not be translated.
	SecretRefs []EnvoySecretRef
	FailClosed []string
	Notes      []FieldNote
}

// Empty reports whether the policy produced no setting at all.
func (t *EnvoyTranslation) Empty() bool {
	return len(t.Rule) == 0 && len(t.Auth) == 0 && len(t.APIKey) == 0 && len(t.Filters) == 0 && len(t.Backend) == 0 &&
		len(t.Listener) == 0 && len(t.Frontend) == 0
}

// Ignored lists the fields that have no effect, for status messages.
func (t *EnvoyTranslation) Ignored() []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range t.Notes {
		if !n.Ignored {
			continue
		}
		f := n.Field
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

type translator struct {
	kind string
	opts EnvoyOptions
	out  *EnvoyTranslation
}

func (t *translator) note(where, field string, v any, status string, ignored bool, reason string) {
	row, _ := compatRow(t.kind, field)
	if status == "" {
		status = row.Status
		if status == "" {
			status = CompatUnsupported
		}
	}
	if reason == "" {
		reason = row.Note
	}
	n := FieldNote{Kind: t.kind, Field: field, Status: status, Where: where, Setura: row.Setura, Reason: reason, Ignored: ignored}
	if row.Field == "" {
		n.Setura = ""
	}
	if v != nil {
		switch x := v.(type) {
		case map[string]any, []any:
			// structures are not echoed
		default:
			n.Value = fmt.Sprint(x)
		}
	}
	t.out.Notes = append(t.out.Notes, n)
}

// ok records a translated field (its table status says whether fully).
func (t *translator) ok(where, field string, v any) { t.note(where, field, v, "", false, "") }

// part records a field translated with something left out.
func (t *translator) part(where, field string, v any, reason string) {
	t.note(where, field, v, CompatPartial, true, reason)
}

// no records an ignored field; reason "" uses the table's note.
func (t *translator) no(field string, v any, reason string) {
	t.note("none", field, v, CompatUnsupported, true, reason)
	row, _ := compatRow(t.kind, field)
	if reason == "" && row.Note == "" && row.Setura != "" && row.Setura != "none" {
		t.out.Notes[len(t.out.Notes)-1].Reason = "use " + row.Setura
	}
}

// noTree records an ignored object field by field where the table lists them.
func (t *translator) noTree(path string, v any) {
	m := ecMap(v)
	if m == nil {
		t.no(path, v, "")
		return
	}
	if r, ok := compatRow(t.kind, path); ok && r.Field == path {
		if _, deeper := t.hasChildRows(path); !deeper {
			t.no(path, nil, "")
			return
		}
	}
	for _, k := range sortedKeys(m) {
		t.noTree(path+"."+k, m[k])
	}
}

func (t *translator) hasChildRows(path string) (CompatRow, bool) {
	for _, r := range EnvoyCompatTable {
		if (r.Kind == t.kind || r.Kind == kALL) && strings.HasPrefix(r.Field, path+".") {
			return r, true
		}
	}
	return CompatRow{}, false
}

func (t *translator) rule(key string, v map[string]any) {
	if t.out.Rule == nil {
		t.out.Rule = map[string]any{}
	}
	if old, ok := t.out.Rule[key].(map[string]any); ok {
		for k, x := range v {
			old[k] = x
		}
		return
	}
	t.out.Rule[key] = v
}

// httpRule reports whether a rule-level setting applies to the target kind;
// otherwise the field is recorded as ignored.
func (t *translator) httpRule(field string, v any) bool {
	if t.opts.TargetKind == "GRPCRoute" {
		t.no(field, v, "GRPCRoute rules take auth policies only")
		return false
	}
	return true
}

// TranslateEnvoyPolicy translates the spec of a BackendTrafficPolicy,
// SecurityPolicy or ClientTrafficPolicy.
func TranslateEnvoyPolicy(kind string, spec map[string]any, opts EnvoyOptions) *EnvoyTranslation {
	t := &translator{kind: kind, opts: opts, out: &EnvoyTranslation{}}
	if opts.FaultTTL == "" {
		t.opts.FaultTTL = DefaultEnvoyFaultTTL
	}
	for _, k := range sortedKeys(spec) {
		switch k {
		case "targetRef", "targetRefs", "targetSelectors", "mergeType":
			continue
		}
		switch kind {
		case kBT:
			t.backendTraffic(k, spec[k])
		case kSP:
			t.security(k, spec[k])
		case kCT:
			t.clientTraffic(k, spec[k])
		default:
			t.no(k, spec[k], "not a policy kind Setura translates")
		}
	}
	sort.SliceStable(t.out.Notes, func(i, j int) bool { return t.out.Notes[i].Field < t.out.Notes[j].Field })
	return t.out
}

func (t *translator) backendTraffic(k string, v any) {
	spec := map[string]any{k: v}
	switch k {
	case "timeout":
		tm := ecMap(v)
		for _, tk := range sortedKeys(tm) {
			sub := ecMap(tm[tk])
			for _, f := range sortedKeys(sub) {
				path := "timeout." + tk + "." + f
				if path != "timeout.http.requestTimeout" {
					t.no(path, sub[f], "")
					continue
				}
				d, ok := ecDuration(sub[f])
				switch {
				case !ok:
					t.no(path, sub[f], "the value is not a duration Setura can read")
				case t.httpRule(path, sub[f]):
					t.rule("timeouts", map[string]any{"request": d})
					t.ok("rule", path, sub[f])
				}
			}
		}
	case "retry":
		t.retry(ecMap(v))
	case "rateLimit":
		t.rateLimit(ecMap(v))
	case "circuitBreaker":
		cb := ecMap(v)
		out := map[string]any{}
		for _, f := range sortedKeys(cb) {
			path := "circuitBreaker." + f
			target := map[string]string{"maxConnections": "maxConnections", "maxPendingRequests": "maxPending", "maxParallelRequests": "maxRequests"}[f]
			n, isNum := ecNum(cb[f])
			if target == "" || !isNum {
				t.no(path, cb[f], "")
				continue
			}
			out[target] = int(n)
			t.ok("backend", path, cb[f])
		}
		t.backend("circuitBreaker", out)
	case "healthCheck":
		t.healthCheck(ecMap(v))
	case "faultInjection":
		t.fault(ecMap(v))
	case "mirrors":
		if !t.httpRule("mirrors", nil) {
			return
		}
		for _, m := range ecList(v) {
			mm := ecMap(m)
			ref := ecMap(mm["backendRef"])
			if ref == nil {
				ref = mm
			}
			port, _ := ecNum(ref["port"])
			br := map[string]any{"name": ecStr(ref["name"])}
			if ns := ecStr(ref["namespace"]); ns != "" {
				br["namespace"] = ns
			}
			if port > 0 {
				br["port"] = int(port)
			}
			rm := map[string]any{"backendRef": br}
			if p, ok := ecNum(firstOf(mm["percentage"], mm["percent"])); ok {
				rm["percent"] = int(math.Ceil(p))
			}
			t.out.Filters = append(t.out.Filters, map[string]any{"type": "RequestMirror", "requestMirror": rm})
		}
		t.ok("rule", "mirrors", nil)
	case "loadBalancer":
		t.loadBalancer(ecMap(v))
	case "compression":
		t.compression(ecList(v))
	case "requestBuffer":
		t.requestBuffer(ecMap(v))
	case "proxyProtocol":
		ver := strings.ToLower(ecStr(ecMap(v)["version"]))
		if ver == "v1" || ver == "v2" {
			t.backend("proxyProtocol", ver)
			t.ok("backend", "proxyProtocol.version", ver)
		} else {
			t.no("proxyProtocol.version", ver, "want V1 or V2")
		}
	default:
		t.noTree(k, spec[k])
	}
}

func (t *translator) backend(key string, v any) {
	if t.out.Backend == nil {
		t.out.Backend = map[string]any{}
	}
	if old, ok := t.out.Backend[key].(map[string]any); ok {
		if nv, ok := v.(map[string]any); ok {
			for k, x := range nv {
				old[k] = x
			}
			return
		}
	}
	t.out.Backend[key] = v
}

func (t *translator) retry(rt map[string]any) {
	if !t.httpRule("retry", nil) {
		return
	}
	retry := map[string]any{}
	attempts := 2
	if n, ok := ecNum(rt["numRetries"]); ok {
		attempts = int(n)
	}
	retry["attempts"] = attempts
	t.ok("rule", "retry.numRetries", rt["numRetries"])
	var codes []any
	for _, c := range ecList(ecDig(rt, "retryOn", "httpStatusCodes")) {
		if n, ok := ecNum(c); ok {
			codes = append(codes, int(n))
		}
	}
	if len(codes) > 0 {
		t.ok("rule", "retry.retryOn.httpStatusCodes", nil)
	}
	for _, trig := range ecList(ecDig(rt, "retryOn", "triggers")) {
		s := fmt.Sprint(trig)
		switch s {
		case "connect-failure", "retriable-status-codes":
			t.ok("rule", "retry.retryOn.triggers", s)
		case "5xx":
			codes = appendCodes(codes, 500, 502, 503, 504)
			t.ok("rule", "retry.retryOn.triggers", s)
		case "gateway-error":
			codes = appendCodes(codes, 502, 503, 504)
			t.ok("rule", "retry.retryOn.triggers", s)
		default:
			t.part("rule", "retry.retryOn.triggers", s, "the gateway retries connection failures and the listed status codes only; this trigger has no equivalent")
		}
	}
	if len(codes) > 0 {
		retry["codes"] = codes
	}
	if d, ok := ecDuration(ecDig(rt, "perRetry", "timeout")); ok {
		retry["perTryTimeout"] = d
		t.ok("rule", "retry.perRetry.timeout", nil)
	}
	if d, ok := ecDuration(ecDig(rt, "perRetry", "backOff", "baseInterval")); ok {
		retry["backoff"] = d
		t.ok("rule", "retry.perRetry.backOff.baseInterval", nil)
	}
	if ecDig(rt, "perRetry", "backOff", "maxInterval") != nil {
		t.no("retry.perRetry.backOff.maxInterval", ecDig(rt, "perRetry", "backOff", "maxInterval"), "")
	}
	t.rule("retry", retry)
}

func appendCodes(codes []any, add ...int) []any {
	have := map[int]bool{}
	for _, c := range codes {
		have[c.(int)] = true
	}
	for _, a := range add {
		if !have[a] {
			codes = append(codes, a)
		}
	}
	return codes
}

var rateUnits = map[string]string{"Second": "s", "Minute": "m", "Hour": "h"}

func (t *translator) rateLimit(rl map[string]any) {
	if !t.httpRule("rateLimit", nil) {
		return
	}
	typ := ecStr(rl["type"])
	switch typ {
	case "", "Local":
		t.ok("rule", "rateLimit.type", typ)
		for i, r := range ecList(ecDig(rl, "local", "rules")) {
			t.rateRule("rateLimit.local.rules", i, r, false)
		}
		if rl["global"] != nil {
			t.no("rateLimit.global", nil, "the policy type is Local")
		}
	case "Global":
		if rl["local"] != nil {
			t.no("rateLimit.local.rules", nil, "the policy type is Global")
		}
		if t.opts.Redis == "" {
			t.no("rateLimit.type", typ, "a global limit needs a Redis server: set the annotation "+EnvoyRedisAnnotation+" on the policy to the NAME of a --redis server")
			if rl["global"] != nil {
				t.no("rateLimit.global", nil, "no Redis server is named (annotation "+EnvoyRedisAnnotation+"), so nothing is counted across replicas and the route is not rate limited")
			}
			return
		}
		t.ok("rule", "rateLimit.type", typ)
		for i, r := range ecList(ecDig(rl, "global", "rules")) {
			t.rateRule("rateLimit.global", i, r, true)
		}
	default:
		t.no("rateLimit.type", typ, "")
	}
}

// rateRule translates one rate limit rule of a local or global policy: the
// first becomes the rule's bucket, the others cannot (one bucket per rule).
func (t *translator) rateRule(field string, i int, r any, global bool) {
	limit := ecMap(r)
	sel := ecList(limit["clientSelectors"])
	if i > 0 {
		t.no(field, nil, "Setura keeps one rate limit bucket per rule; only the first policy rule is translated")
		return
	}
	n, okN := ecNum(ecDig(limit, "limit", "requests"))
	unit := rateUnits[ecStr(ecDig(limit, "limit", "unit"))]
	if !okN || unit == "" {
		t.no(field, nil, "the limit needs requests and a unit of Second, Minute or Hour")
		return
	}
	block := map[string]any{"rate": strconv.Itoa(int(n)) + "/" + unit, "key": "route"}
	partial := ""
	switch {
	case len(sel) == 0:
	case len(sel) == 1 && ecMap(sel[0])["sourceCIDR"] != nil && len(ecMap(sel[0])) == 1 && ecStr(ecDig(sel[0], "sourceCIDR", "type")) == "Distinct":
		block["key"] = "client-ip"
		partial = "limits every client address, the sourceCIDR value is ignored"
	case len(sel) == 1 && len(ecMap(sel[0])) == 1 && len(ecList(ecMap(sel[0])["headers"])) == 1 && ecMap(ecList(ecMap(sel[0])["headers"])[0])["value"] == nil &&
		ecStr(ecMap(ecList(ecMap(sel[0])["headers"])[0])["name"]) != "" && ecMap(ecList(ecMap(sel[0])["headers"])[0])["invert"] == nil:
		block["key"] = "header:" + ecStr(ecMap(ecList(ecMap(sel[0])["headers"])[0])["name"])
	default:
		t.no(field, nil, "clientSelectors other than a distinct sourceCIDR or a distinct header cannot be expressed; the rule is not applied")
		return
	}
	if global {
		block["shared"] = map[string]any{"redis": t.opts.Redis}
	}
	if partial != "" {
		t.part("rule", field, nil, partial)
	} else {
		t.ok("rule", field, nil)
	}
	t.rule("setura.zyvor.dev/rate-limit", block)
}

func (t *translator) healthCheck(hc map[string]any) {
	active := ecMap(hc["active"])
	if active != nil {
		out := map[string]any{}
		typ := strings.ToUpper(ecStr(active["type"]))
		switch typ {
		case "", "HTTP":
			out["protocol"] = "http"
			if p := ecStr(ecDig(active, "http", "path")); p != "" {
				out["path"] = p
				t.ok("backend", "healthCheck.active.http.path", p)
			} else {
				out["path"] = "/"
			}
			t.ok("backend", "healthCheck.active.type", typ)
		case "GRPC":
			out["protocol"] = "grpc"
			out["path"] = "/"
			if s := ecStr(ecDig(active, "grpc", "service")); s != "" {
				out["service"] = s
				t.ok("backend", "healthCheck.active.grpc.service", s)
			}
			t.ok("backend", "healthCheck.active.type", typ)
		default:
			t.no("healthCheck.active.type", typ, "TCP health checks are not supported")
			if active["tcp"] != nil {
				t.no("healthCheck.active.tcp", nil, "")
			}
			active = nil
		}
		if active != nil {
			for _, f := range []string{"interval", "timeout"} {
				if d, ok := ecDuration(active[f]); ok {
					out[f] = d
					t.ok("backend", "healthCheck.active."+f, active[f])
				}
			}
			for _, f := range []string{"unhealthyThreshold", "healthyThreshold"} {
				if n, ok := ecNum(active[f]); ok {
					out[f] = int(n)
					t.ok("backend", "healthCheck.active."+f, active[f])
				}
			}
			for _, f := range []string{"http.method", "http.expectedStatuses", "http.expectedResponse"} {
				if ecDig(active, strings.Split(f, ".")...) != nil {
					t.no("healthCheck.active."+f, nil, "")
				}
			}
			if active["tcp"] != nil {
				t.no("healthCheck.active.tcp", nil, "")
			}
			t.backend("healthCheck", out)
		}
	}
	if passive := ecMap(hc["passive"]); passive != nil {
		cb := map[string]any{}
		for _, f := range sortedKeys(passive) {
			path := "healthCheck.passive." + f
			switch f {
			case "consecutive5XxErrors":
				if n, ok := ecNum(passive[f]); ok {
					cb["failureThreshold"] = int(n)
					t.ok("backend", path, passive[f])
				}
			case "baseEjectionTime":
				if d, ok := ecDuration(passive[f]); ok {
					cb["openFor"] = d
					t.ok("backend", path, passive[f])
				}
			default:
				t.no(path, passive[f], "")
			}
		}
		t.backend("circuitBreaker", cb)
	}
}

func (t *translator) fault(fi map[string]any) {
	if !t.httpRule("faultInjection", nil) {
		return
	}
	fault := map[string]any{"percent": 100, "ttl": t.opts.FaultTTL}
	if t.opts.Name != "" {
		fault["name"] = t.opts.Name
	}
	pct := func(v any) int {
		if p, ok := ecNum(v); ok {
			return min(100, max(1, int(math.Ceil(p))))
		}
		return 100
	}
	if d := ecMap(fi["delay"]); d != nil {
		if dur, ok := ecDuration(d["fixedDelay"]); ok {
			fault["latency"] = map[string]any{"delay": dur, "percent": pct(d["percentage"])}
			t.ok("rule", "faultInjection.delay.fixedDelay", d["fixedDelay"])
			if d["percentage"] != nil {
				t.ok("rule", "faultInjection.delay.percentage", d["percentage"])
			}
		}
	}
	if a := ecMap(fi["abort"]); a != nil {
		if n, ok := ecNum(a["httpStatus"]); ok {
			fault["abort"] = map[string]any{"status": int(n), "percent": pct(a["percentage"])}
			t.ok("rule", "faultInjection.abort.httpStatus", a["httpStatus"])
			if a["percentage"] != nil {
				t.ok("rule", "faultInjection.abort.percentage", a["percentage"])
			}
		}
		if a["grpcStatus"] != nil {
			t.no("faultInjection.abort.grpcStatus", a["grpcStatus"], "")
		}
	}
	if fault["latency"] != nil || fault["abort"] != nil {
		t.rule("setura.zyvor.dev/fault", fault)
	}
}

func (t *translator) clientTraffic(k string, v any) {
	switch k {
	case "tls":
		tl := ecMap(v)
		for _, f := range sortedKeys(tl) {
			path := "tls." + f
			switch f {
			case "minVersion", "maxVersion":
				ver := ecStr(tl[f])
				mapped, ok := tlsVersionOf(ver, f == "minVersion")
				key := "tlsMinVersion"
				if f == "maxVersion" {
					key = "tlsMaxVersion"
				}
				switch {
				case !ok:
					t.no(path, ver, "a maximum below TLS 1.2 cannot be met by Setura")
				default:
					t.listener(key, mapped)
					if mapped != ver {
						t.part("listener", path, ver, "Setura serves TLS 1.2 and 1.3 only: "+ver+" becomes "+mapped)
					} else {
						t.ok("listener", path, ver)
					}
				}
			case "clientValidation":
				cv := ecMap(tl[f])
				fe := map[string]any{"mode": "AllowValidOnly"}
				var refs []any
				for _, r := range ecList(cv["caCertificateRefs"]) {
					rm := ecMap(r)
					ref := map[string]any{"kind": firstStr(ecStr(rm["kind"]), "ConfigMap"), "name": ecStr(rm["name"])}
					if ns := ecStr(rm["namespace"]); ns != "" {
						ref["namespace"] = ns
					}
					if g := ecStr(rm["group"]); g != "" {
						ref["group"] = g
					}
					refs = append(refs, ref)
				}
				fe["caCertificateRefs"] = refs
				if len(refs) > 0 {
					t.ok("frontend", "tls.clientValidation.caCertificateRefs", nil)
				}
				if b, _ := cv["optional"].(bool); b {
					fe["mode"] = "AllowInsecureFallback"
					t.ok("frontend", "tls.clientValidation.optional", true)
				}
				if sans := ecList(cv["subjectAltNames"]); len(sans) > 0 {
					t.clientAllow(fe, sans)
				}
				t.out.Frontend = fe
			case "ciphers":
				t.tlsCiphers(ecList(tl[f]))
			case "session":
				t.tlsSession(ecMap(tl[f]))
			default:
				t.no(path, tl[f], "")
			}
		}
	case "connection":
		t.connection(ecMap(v))
	case "headers":
		hd := ecMap(v)
		for _, f := range sortedKeys(hd) {
			if f == "xForwardedClientCert" {
				t.no("headers.xForwardedClientCert", nil, "")
			} else {
				t.no("headers", nil, "")
			}
		}
		if len(hd) == 0 {
			t.no("headers", nil, "")
		}
	default:
		t.noTree(k, v)
	}
}

// tlsVersionOf maps an Envoy TLS version to one Setura serves.
func tlsVersionOf(v string, min bool) (string, bool) {
	switch strings.TrimPrefix(strings.ToLower(v), "tls") {
	case "1.3":
		return "1.3", true
	case "1.2":
		return "1.2", true
	case "1.0", "1.1":
		return "1.2", min
	}
	return "", false
}

func (t *translator) security(k string, v any) {
	sp := ecMap(v)
	switch k {
	case "cors":
		if !t.httpRule(k, nil) {
			return
		}
		cors := map[string]any{}
		var origins []any
		for _, o := range ecList(sp["allowOrigins"]) {
			origins = append(origins, fmt.Sprint(o))
		}
		cors["allowOrigins"] = origins
		t.ok("rule", "cors.allowOrigins", nil)
		for _, f := range []string{"allowMethods", "allowHeaders", "exposeHeaders", "allowCredentials"} {
			if val, ok := sp[f]; ok {
				cors[f] = val
				t.ok("rule", "cors."+f, nil)
			}
		}
		if val, ok := sp["maxAge"]; ok {
			if d, ok := ecDuration(val); ok {
				cors["maxAge"] = int(ecSeconds(d))
				t.ok("rule", "cors.maxAge", val)
			}
		}
		for _, f := range sortedKeys(sp) {
			if _, known := compatRow(kSP, "cors."+f); !known {
				t.no("cors."+f, sp[f], "")
			}
		}
		t.out.Filters = append(t.out.Filters, map[string]any{"type": "CORS", "cors": cors})
	case "jwt":
		t.jwt(sp)
	case "apiKeyAuth":
		t.apiKey(sp)
	case "basicAuth":
		t.no("basicAuth", ecStr(ecDig(sp, "users", "name")), "")
		t.out.FailClosed = append(t.out.FailClosed, "basicAuth")
	case "oidc":
		t.oidc(sp)
	case "authorization":
		t.authorization(sp)
	case "extAuth":
		t.extAuth(sp)
	default:
		t.noTree(k, v)
		t.out.FailClosed = append(t.out.FailClosed, k)
	}
}

func (t *translator) auth(field string, v any) {
	if t.out.Auth == nil {
		t.out.Auth = map[string]any{}
	}
	t.out.Auth[field] = v
}

func (t *translator) jwt(sp map[string]any) {
	provs := ecList(sp["providers"])
	if sp["optional"] != nil {
		t.no("jwt.optional", sp["optional"], "")
	}
	for i, pv := range provs {
		pm := ecMap(pv)
		if i > 0 {
			t.part("rule", "jwt.providers", ecStr(pm["name"]), "an auth block accepts one JWT issuer: tokens of provider "+ecStr(pm["name"])+" are refused")
			continue
		}
		jwt := map[string]any{}
		if v := ecStr(pm["issuer"]); v != "" {
			jwt["issuer"] = v
			t.ok("rule", "jwt.providers.issuer", v)
		}
		if a := ecList(pm["audiences"]); len(a) > 0 {
			jwt["audience"] = a
			t.ok("rule", "jwt.providers.audiences", nil)
		} else {
			t.part("rule", "jwt.providers.audiences", ecStr(pm["name"]), "no audience is set, so any audience is accepted; always set one (lint rule SET016)")
		}
		if v := ecStr(ecDig(pm, "remoteJWKS", "uri")); v != "" {
			jwt["jwksUri"] = v
			t.ok("rule", "jwt.providers.remoteJWKS", v)
		}
		if inline := ecStr(ecDig(pm, "localJWKS", "inline")); inline != "" {
			var raw json.RawMessage
			if json.Unmarshal([]byte(inline), &raw) == nil {
				jwt["jwks"] = raw
				t.ok("rule", "jwt.providers.localJWKS", nil)
			} else {
				t.no("jwt.providers.localJWKS", nil, "the inline key set is not JSON")
			}
		} else if pm["localJWKS"] != nil {
			t.no("jwt.providers.localJWKS", nil, "only inline key sets are supported")
		}
		ch := map[string]any{}
		for _, m := range ecList(pm["claimToHeaders"]) {
			mm := ecMap(m)
			ch[ecStr(mm["header"])] = ecStr(mm["claim"])
		}
		if len(ch) > 0 {
			jwt["claimHeaders"] = ch
			t.ok("rule", "jwt.providers.claimToHeaders", nil)
		}
		if b, ok := pm["forwardAccessToken"].(bool); ok {
			jwt["stripToken"] = !b
			t.ok("rule", "jwt.providers.forwardAccessToken", b)
		}
		for _, f := range []string{"extractFrom", "recomputeRoute"} {
			if pm[f] != nil {
				t.no("jwt.providers."+f, ecStr(pm["name"]), "")
			}
		}
		t.auth("jwt", jwt)
	}
}

func (t *translator) apiKey(sp map[string]any) {
	block := map[string]any{}
	if h := ecList(ecDig(sp, "extractFrom")); len(h) > 0 {
		ef := ecMap(h[0])
		if hs := ecList(ef["headers"]); len(hs) > 0 {
			block["header"] = fmt.Sprint(hs[0])
			t.ok("rule", "apiKeyAuth.extractFrom", nil)
			if len(hs) > 1 {
				t.part("rule", "apiKeyAuth.extractFrom", nil, "only the first header is read")
			}
		} else if ps := ecList(ef["params"]); len(ps) > 0 {
			block["query"] = fmt.Sprint(ps[0])
			t.ok("rule", "apiKeyAuth.extractFrom", nil)
		} else if ef["cookies"] != nil {
			t.no("apiKeyAuth.extractFrom", nil, "cookies are not read")
		}
	} else if m := ecMap(sp["extractFrom"]); m != nil {
		if hs := ecList(m["headers"]); len(hs) > 0 {
			block["header"] = fmt.Sprint(hs[0])
			t.ok("rule", "apiKeyAuth.extractFrom", nil)
		} else if ps := ecList(m["params"]); len(ps) > 0 {
			block["query"] = fmt.Sprint(ps[0])
			t.ok("rule", "apiKeyAuth.extractFrom", nil)
		} else if m["cookies"] != nil {
			t.no("apiKeyAuth.extractFrom", nil, "cookies are not read")
		}
	}
	if b, ok := sp["sanitize"].(bool); ok {
		block["forward"] = !b
		t.ok("rule", "apiKeyAuth.sanitize", b)
	}
	if sp["forwardClientIDHeader"] != nil {
		t.no("apiKeyAuth.forwardClientIDHeader", sp["forwardClientIDHeader"], "")
	}
	for _, c := range ecList(sp["credentialRefs"]) {
		cm := ecMap(c)
		t.out.SecretRefs = append(t.out.SecretRefs, EnvoySecretRef{Purpose: "apiKey", Name: ecStr(cm["name"]), Namespace: ecStr(cm["namespace"])})
	}
	t.ok("rule", "apiKeyAuth.credentialRefs", nil)
	t.out.APIKey = block
	if len(t.out.SecretRefs) == 0 {
		t.out.FailClosed = append(t.out.FailClosed, "apiKeyAuth")
	}
}

func (t *translator) authorizationCIDRs(sp map[string]any) {
	allow, deny := []any{}, []any{}
	bad := false
	for _, r := range ecList(sp["rules"]) {
		rm := ecMap(r)
		principal := ecMap(rm["principal"])
		cidrs := ecList(principal["clientCIDRs"])
		clean := len(cidrs) > 0
		for _, pk := range sortedKeys(principal) {
			if pk != "clientCIDRs" {
				t.no("authorization.rules.principal."+pk, nil, "")
				clean = false
			}
		}
		if rm["operation"] != nil {
			t.no("authorization.rules.operation", nil, "")
			clean = false
		}
		if !clean {
			bad = true
			continue
		}
		if strings.EqualFold(ecStr(rm["action"]), "Allow") {
			allow = append(allow, cidrs...)
		} else {
			deny = append(deny, cidrs...)
		}
		t.ok("rule", "authorization.rules.principal.clientCIDRs", nil)
	}
	if bad {
		t.out.FailClosed = append(t.out.FailClosed, "authorization")
		return
	}
	if sp["defaultAction"] != nil {
		t.ok("rule", "authorization.defaultAction", sp["defaultAction"])
	}
	if len(allow) > 0 && strings.EqualFold(ecStr(sp["defaultAction"]), "Deny") {
		t.auth("ipAllow", allow)
	} else if len(allow) > 0 {
		t.part("rule", "authorization.defaultAction", nil, "an Allow rule with defaultAction Allow permits everyone; there is nothing to enforce")
	}
	if len(deny) > 0 {
		t.auth("ipDeny", deny)
	}
}

func (t *translator) extAuth(sp map[string]any) {
	if !t.httpRule("extAuth", nil) {
		return
	}
	proto, body := "HTTP", ecMap(sp["http"])
	if g := ecMap(sp["grpc"]); g != nil {
		proto, body = "GRPC", g
	}
	refs := ecList(body["backendRefs"])
	if len(refs) == 0 {
		refs = []any{body["backendRef"]}
	}
	bm := ecMap(refs[0])
	if bm == nil {
		t.no("extAuth."+strings.ToLower(proto), nil, "the policy has no backendRef (a Service is required by ExternalAuth)")
		t.out.FailClosed = append(t.out.FailClosed, "extAuth")
		return
	}
	port, _ := ecNum(bm["port"])
	br := map[string]any{"name": ecStr(bm["name"])}
	if ns := ecStr(bm["namespace"]); ns != "" {
		br["namespace"] = ns
	}
	if port > 0 {
		br["port"] = int(port)
	}
	ea := map[string]any{"protocol": proto, "backendRef": br}
	hdrs := ecList(sp["headersToExtAuth"])
	if proto == "HTTP" {
		h := map[string]any{}
		if p := ecStr(body["path"]); p != "" {
			h["path"] = p
		}
		if hs := ecList(body["headersToBackend"]); len(hs) > 0 {
			h["allowedResponseHeaders"] = hs
			t.ok("rule", "extAuth.headersToBackend", nil)
		}
		if len(hdrs) > 0 {
			h["allowedHeaders"] = hdrs
			t.ok("rule", "extAuth.headersToExtAuth", nil)
		}
		if len(h) > 0 {
			ea["http"] = h
		}
	} else if len(hdrs) > 0 {
		ea["grpc"] = map[string]any{"allowedHeaders": hdrs}
		t.ok("rule", "extAuth.headersToExtAuth", nil)
	}
	for _, f := range []string{"bodyToExtAuth", "failOpen", "recomputeRoute"} {
		if sp[f] != nil {
			t.no("extAuth."+f, sp[f], "")
		}
	}
	t.ok("rule", "extAuth."+strings.ToLower(proto), proto)
	t.out.Filters = append(t.out.Filters, map[string]any{"type": "ExternalAuth", "externalAuth": ea})
}

// EnvoyDirectResponse is a translated HTTPRouteFilter.
type EnvoyDirectResponse struct {
	Block map[string]any // setura.zyvor.dev/direct-response; nil when the filter has none
	// Inject is the auth inject entry of a credentialInjection: the header and the Secret that fills it.
	Inject map[string]any
	Notes  []FieldNote
}

// TranslateHTTPRouteFilter translates the spec of an HTTPRouteFilter: a
// direct response becomes the rule's direct-response block and a credential
// injection an auth inject entry (ns is the namespace of the filter, where its
// Secret lives); URL regex rewrites are reported as unsupported.
func TranslateHTTPRouteFilter(spec map[string]any, ns string) *EnvoyDirectResponse {
	out := &EnvoyDirectResponse{}
	t := &translator{kind: kHRF, out: &EnvoyTranslation{}}
	for _, k := range sortedKeys(spec) {
		switch k {
		case "directResponse":
			dr := ecMap(spec[k])
			block := map[string]any{"status": 200}
			if n, ok := ecNum(dr["statusCode"]); ok {
				block["status"] = int(n)
			}
			t.ok("rule", "directResponse.statusCode", dr["statusCode"])
			if ct := ecStr(dr["contentType"]); ct != "" {
				block["headers"] = map[string]any{"Content-Type": ct}
				t.ok("rule", "directResponse.contentType", ct)
			}
			if b := ecMap(dr["body"]); b != nil {
				if s, ok := b["inline"].(string); ok && (ecStr(b["type"]) == "" || ecStr(b["type"]) == "Inline") {
					block["body"] = s
					t.ok("rule", "directResponse.body", nil)
				} else {
					t.no("directResponse.body", nil, "only inline bodies are supported, not ValueRef")
				}
			}
			out.Block = block
		case "credentialInjection":
			out.Inject = t.credentialInjection(ecMap(spec[k]), ns)
		default:
			t.noTree(k, spec[k])
		}
	}
	out.Notes = t.out.Notes
	return out
}

// EnvoyBackend is a translated Backend.
type EnvoyBackend struct {
	Endpoints []string
	Protocol  string
	Notes     []FieldNote
}

// TranslateEnvoyBackend translates the spec of a Backend into upstream endpoints.
func TranslateEnvoyBackend(spec map[string]any) *EnvoyBackend {
	out := &EnvoyBackend{}
	t := &translator{kind: kBK, out: &EnvoyTranslation{}}
	for _, k := range sortedKeys(spec) {
		switch k {
		case "endpoints":
			for _, e := range ecList(spec[k]) {
				em := ecMap(e)
				if f := ecMap(em["fqdn"]); f != nil {
					port, _ := ecNum(f["port"])
					out.Endpoints = append(out.Endpoints, ecStr(f["hostname"])+":"+strconv.Itoa(int(port)))
					t.ok("backend", "endpoints.fqdn", ecStr(f["hostname"]))
				}
				if i := ecMap(em["ip"]); i != nil {
					port, _ := ecNum(i["port"])
					out.Endpoints = append(out.Endpoints, hostPort(ecStr(i["address"]), int(port)))
					t.ok("backend", "endpoints.ip", ecStr(i["address"]))
				}
				if em["unix"] != nil {
					t.no("endpoints.unix", nil, "")
				}
			}
		case "appProtocols":
			for _, p := range ecList(spec[k]) {
				if fmt.Sprint(p) == "gateway.envoyproxy.io/h2c" {
					out.Protocol = "h2c"
					t.ok("backend", "appProtocols", p)
				} else {
					t.part("backend", "appProtocols", p, "only gateway.envoyproxy.io/h2c is understood")
				}
			}
		default:
			t.noTree(k, spec[k])
		}
	}
	out.Notes = t.out.Notes
	return out
}

func hostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// ---- decoded JSON/YAML helpers ----

func ecMap(v any) map[string]any { m, _ := v.(map[string]any); return m }
func ecList(v any) []any         { l, _ := v.([]any); return l }
func ecStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

func ecDig(v any, keys ...string) any {
	for _, k := range keys {
		m := ecMap(v)
		if m == nil {
			return nil
		}
		v = m[k]
	}
	return v
}

func ecNum(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case float64:
		return x, true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	}
	return 0, false
}

func firstOf(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

func firstStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// ecDuration reads a Go style duration (30s, 1h30m, 100ms) or a bare number
// of seconds; nil and the empty string are not durations.
func ecDuration(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" {
		return "", false
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return strconv.Itoa(n) + "s", true
	}
	if d, err := time.ParseDuration(s); err == nil && d >= 0 {
		return s, true
	}
	return "", false
}

func ecSeconds(d string) float64 {
	v, err := time.ParseDuration(d)
	if err != nil {
		return 0
	}
	return v.Seconds()
}
