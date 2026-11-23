package gateway

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// The part of the Envoy Gateway translation that covers Setura's load
// balancing, compression, request limits, TLS suites, client certificate
// allow-lists, OIDC login, authorization rules and credential injection.

func (t *translator) listener(key string, v any) {
	if t.out.Listener == nil {
		t.out.Listener = map[string]any{}
	}
	t.out.Listener[key] = v
}

// ---- BackendTrafficPolicy ----

// loadBalancer translates loadBalancer into the loadBalancer block of the
// backends the targeted rules send to.
func (t *translator) loadBalancer(lb map[string]any) {
	cfg := map[string]any{}
	if typ := ecStr(lb["type"]); typ != "" {
		algo := map[string]string{"RoundRobin": AlgoRoundRobin, "LeastRequest": AlgoLeastRequest, "Random": AlgoRandom, "ConsistentHash": AlgoConsistentHash}[typ]
		if algo == "" {
			t.no("loadBalancer.type", typ, "want RoundRobin, LeastRequest, Random or ConsistentHash")
			return
		}
		cfg["algorithm"] = algo
		t.ok("backend", "loadBalancer.type", typ)
	}
	if ch := ecMap(lb["consistentHash"]); ch != nil || ecStr(lb["type"]) == "ConsistentHash" {
		t.consistentHash(cfg, ch)
	}
	if ss := ecMap(lb["slowStart"]); ss != nil {
		if d, ok := ecDuration(ss["window"]); ok {
			cfg["slowStart"] = map[string]any{"window": d}
			t.ok("backend", "loadBalancer.slowStart", ss["window"])
		} else {
			t.no("loadBalancer.slowStart", ss["window"], "slowStart needs a window that is a duration")
		}
	}
	if za := ecMap(lb["zoneAware"]); za != nil {
		pl := ecMap(za["preferLocal"])
		if pl == nil {
			t.no("loadBalancer.zoneAware", nil, "only preferLocal is understood")
		} else {
			cfg["locality"] = map[string]any{"preferLocalZone": true}
			if pl["force"] != nil || pl["minEndpointsThreshold"] != nil {
				t.part("backend", "loadBalancer.zoneAware", nil, "preferLocal is translated; force and minEndpointsThreshold are ignored (Setura spills to every zone when the local zone is under 70 percent healthy)")
			} else {
				t.ok("backend", "loadBalancer.zoneAware", nil)
			}
		}
	}
	if lb["endpointOverride"] != nil {
		t.no("loadBalancer.endpointOverride", nil, "")
	}
	if len(cfg) == 0 {
		return
	}
	raw, _ := json.Marshal(cfg)
	if _, err := ParseLBBlock(raw); err != nil {
		t.no("loadBalancer.type", ecStr(lb["type"]), "the load balancer is not valid for Setura: "+strings.TrimPrefix(err.Error(), LoadBalancerKey+": "))
		return
	}
	t.backend("loadBalancer", cfg)
}

func (t *translator) consistentHash(cfg, ch map[string]any) {
	hash := map[string]any{}
	partial := ""
	switch typ := ecStr(ch["type"]); typ {
	case "SourceIP":
		hash["on"] = "sourceIP"
	case "Header":
		hash["on"], hash["name"] = "header", ecStr(ecDig(ch, "header", "name"))
	case "Headers":
		hs := ecList(ch["headers"])
		hash["on"], hash["name"] = "header", ecStr(ecMap(firstOf(append(hs, nil)...))["name"])
		if len(hs) > 1 {
			partial = "only the first of the hashed headers is used"
		}
	case "QueryParams":
		qs := ecList(ch["queryParams"])
		hash["on"], hash["name"] = "query", ecStr(ecMap(firstOf(append(qs, nil)...))["name"])
		if len(qs) > 1 {
			partial = "only the first of the hashed query parameters is used"
		}
	case "Cookie":
		c := ecMap(ch["cookie"])
		hash["on"], hash["name"] = "cookie", ecStr(c["name"])
		if d, ok := ecDuration(c["ttl"]); ok {
			hash["ttl"] = d
		}
		if p := ecStr(ecDig(c, "attributes", "path")); p != "" {
			hash["path"] = p
		}
	default:
		t.no("loadBalancer.consistentHash", typ, "want a type of SourceIP, Header, Headers, Cookie or QueryParams")
		return
	}
	if hash["on"] != "sourceIP" && hash["name"] == "" {
		t.no("loadBalancer.consistentHash", ecStr(ch["type"]), "the hash key has no name")
		return
	}
	if n, ok := ecNum(ch["tableSize"]); ok {
		hash["type"], hash["tableSize"] = "maglev", int(n)
	}
	cfg["algorithm"] = AlgoConsistentHash
	cfg["consistentHash"] = hash
	if partial != "" {
		t.part("backend", "loadBalancer.consistentHash", ecStr(ch["type"]), partial)
		return
	}
	t.ok("backend", "loadBalancer.consistentHash", ecStr(ch["type"]))
}

// compression translates compression: Gzip becomes the rule's compress block.
func (t *translator) compression(list []any) {
	if !t.httpRule("compression", nil) {
		return
	}
	var encs []any
	for _, c := range list {
		switch typ := ecStr(ecMap(c)["type"]); typ {
		case "Gzip":
			if len(encs) == 0 {
				encs = append(encs, "gzip")
			}
		case "Brotli":
			t.no("compression.brotli", nil, "")
		case "Zstd":
			t.no("compression.zstd", nil, "")
		default:
			t.no("compression", typ, "want Gzip (Brotli and Zstd are not available)")
		}
	}
	if len(encs) > 0 {
		t.rule(CompressKey, map[string]any{"enabled": true, "encodings": encs})
		t.ok("rule", "compression", "Gzip")
	}
}

// requestBuffer translates requestBuffer.limit into the rule's body limit.
func (t *translator) requestBuffer(rb map[string]any) {
	if !t.httpRule("requestBuffer.limit", nil) {
		return
	}
	n, ok := ecQuantity(rb["limit"])
	if !ok || n <= 0 {
		t.no("requestBuffer.limit", rb["limit"], "the limit is not a quantity such as 1Mi")
		return
	}
	t.rule(LimitsKey, map[string]any{"maxRequestBody": strconv.FormatInt(n, 10)})
	t.ok("rule", "requestBuffer.limit", rb["limit"])
}

// ecQuantity reads a Kubernetes quantity (1048576, 512k, 1Mi, 2G) as bytes.
func ecQuantity(v any) (int64, bool) {
	if f, ok := ecNum(v); ok {
		return int64(f), true
	}
	s := strings.TrimSpace(ecStr(v))
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"Ti", 1 << 40}, {"k", 1e3}, {"K", 1e3}, {"M", 1e6}, {"G", 1e9}, {"T", 1e12}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n * mult, true
}

// ---- ClientTrafficPolicy ----

var (
	cipherOnce  sync.Once
	cipherNames map[string]string // lower case OpenSSL or Go name -> Go name
	cipherTLS13 map[string]bool
)

// openSSLCipherName spells a Go TLS 1.2 suite name the OpenSSL way, which is
// how Envoy configures suites (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 is
// ECDHE-RSA-AES128-GCM-SHA256).
func openSSLCipherName(goName string) string {
	n := strings.TrimPrefix(goName, "TLS_")
	kex, rest, ok := strings.Cut(n, "_WITH_")
	if !ok {
		return n
	}
	rest = strings.NewReplacer("AES_128", "AES128", "AES_256", "AES256", "_CBC", "", "_GCM", "-GCM", "CHACHA20_POLY1305_SHA256", "CHACHA20-POLY1305").Replace(rest)
	rest = strings.ReplaceAll(rest, "_", "-")
	if kex == "RSA" {
		return rest
	}
	return strings.ReplaceAll(kex, "_", "-") + "-" + rest
}

func loadCipherNames() {
	cipherOnce.Do(func() {
		cipherNames, cipherTLS13 = map[string]string{}, map[string]bool{}
		for _, c := range tls.CipherSuites() {
			if strings.HasPrefix(c.Name, "TLS_AES_") || strings.HasPrefix(c.Name, "TLS_CHACHA20_") {
				cipherTLS13[strings.ToLower(c.Name)] = true
				continue
			}
			cipherNames[strings.ToLower(c.Name)] = c.Name
			cipherNames[strings.ToLower(openSSLCipherName(c.Name))] = c.Name
		}
	})
}

// tlsCiphers translates tls.ciphers into the cipher suite option of the listener.
func (t *translator) tlsCiphers(list []any) {
	loadCipherNames()
	var names []string
	var dropped []string
	seen := map[string]bool{}
	for _, c := range list {
		s := strings.ToLower(strings.TrimSpace(ecStr(c)))
		if g, ok := cipherNames[s]; ok {
			if !seen[g] {
				seen[g] = true
				names = append(names, g)
			}
			continue
		}
		dropped = append(dropped, ecStr(c))
	}
	if len(names) == 0 {
		t.no("tls.ciphers", nil, "no TLS 1.2 suite Setura allows is named (TLS 1.3 suites are always on; Go's secure suites stay in use)")
		return
	}
	t.listener("tlsCipherSuites", strings.Join(names, ","))
	if len(dropped) > 0 {
		t.part("listener", "tls.ciphers", nil, "ignored: "+strings.Join(dropped, ", ")+" (TLS 1.3, insecure or unknown suites)")
		return
	}
	t.ok("listener", "tls.ciphers", nil)
}

// tlsSession translates tls.session.resumption.
func (t *translator) tlsSession(sess map[string]any) {
	res := ecMap(sess["resumption"])
	if res["stateful"] != nil {
		t.no("tls.session.resumption.stateful", nil, "")
	}
	if res["stateless"] != nil {
		t.listener("tlsSessionResumption", "on")
		t.ok("listener", "tls.session", nil)
		return
	}
	t.no("tls.session", nil, "only stateless resumption is available; nothing was changed")
}

// clientAllow translates clientValidation.subjectAltNames into the allow-list.
func (t *translator) clientAllow(fe map[string]any, list []any) {
	var sans []any
	for _, e := range list {
		var pat string
		if m := ecMap(e); m != nil {
			pat = firstStr(ecStr(m["value"]), ecStr(m["exact"]), ecStr(m["name"]))
			switch strings.ToLower(ecStr(m["type"])) {
			case "", "dns":
				if m["type"] != nil {
					pat = "dns:" + pat
				}
			case "uri":
				pat = "uri:" + pat
			case "email":
				pat = "email:" + pat
			default:
				t.no("tls.clientValidation.subjectAltNames", ecStr(m["type"]), "want a type of DNS, URI or Email")
				return
			}
		} else {
			pat = ecStr(e)
		}
		sans = append(sans, pat)
	}
	if len(sans) == 0 {
		return
	}
	strs := make([]string, len(sans))
	for i, s := range sans {
		strs[i] = s.(string)
	}
	if _, err := (&ClientAllow{SAN: strs}).compile(); err != nil {
		t.no("tls.clientValidation.subjectAltNames", nil, strings.TrimPrefix(err.Error(), ClientAllowKey+": "))
		return
	}
	fe[ClientAllowKey] = map[string]any{"san": sans}
	t.ok("frontend", "tls.clientValidation.subjectAltNames", nil)
}

// connection translates the connection block: the connection limit becomes the listener's.
func (t *translator) connection(cn map[string]any) {
	for _, k := range sortedKeys(cn) {
		path := "connection." + k
		if k != "connectionLimit" {
			t.no(path, cn[k], "")
			continue
		}
		cl := ecMap(cn[k])
		n, ok := ecNum(cl["value"])
		if !ok || n < 1 {
			t.no(path, cl["value"], "the limit needs a value of at least 1")
			continue
		}
		t.listener("limits", map[string]any{"maxConnections": int(n)})
		t.ok("listener", path, cl["value"])
		if cl["closeDelay"] != nil {
			t.no(path+".closeDelay", cl["closeDelay"], "")
		}
	}
}

// ---- SecurityPolicy ----

// secretSource reads env:NAME, file:PATH or secret:[NAMESPACE/]NAME#KEY into a secret reference.
func secretSource(s, defaultNS string) (map[string]any, bool) {
	kind, v, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || v == "" {
		return nil, false
	}
	switch kind {
	case "env":
		return map[string]any{"env": v}, true
	case "file":
		return map[string]any{"file": v}, true
	case "secret":
		ref, key, ok := strings.Cut(v, "#")
		if !ok || key == "" || ref == "" {
			return nil, false
		}
		ns, name := defaultNS, ref
		if a, b, found := strings.Cut(ref, "/"); found {
			ns, name = a, b
		}
		out := map[string]any{"name": name, "key": key}
		if ns != "" {
			out["namespace"] = ns
		}
		return map[string]any{"secret": out}, true
	}
	return nil, false
}

// oidc translates the oidc field into the rule's auth oidc block.
func (t *translator) oidc(sp map[string]any) {
	fail := func(reason string) {
		t.no("oidc", nil, reason)
		t.out.FailClosed = append(t.out.FailClosed, "oidc")
	}
	key, ok := secretSource(t.opts.OIDCCookieKey, t.opts.Namespace)
	if !ok {
		reason := "the session cookie needs a key: set the annotation " + EnvoyOIDCCookieKeyAnnotation + " on the policy to env:NAME, file:PATH or secret:NAME#KEY"
		if t.opts.OIDCCookieKey != "" {
			reason = "the annotation " + EnvoyOIDCCookieKeyAnnotation + " is not env:NAME, file:PATH or secret:[NAMESPACE/]NAME#KEY"
		}
		fail(reason)
		return
	}
	oc := map[string]any{"cookieKeys": []any{key}}
	prov := ecMap(sp["provider"])
	issuer := ecStr(prov["issuer"])
	if issuer == "" {
		fail("provider.issuer is required")
		return
	}
	oc["issuer"] = issuer
	t.ok("rule", "oidc.provider.issuer", issuer)
	for _, f := range []string{"authorizationEndpoint", "tokenEndpoint", "endSessionEndpoint"} {
		if v := ecStr(prov[f]); v != "" {
			oc[f] = v
			t.ok("rule", "oidc.provider."+f, v)
		}
	}
	if prov["backendRefs"] != nil || prov["backendSettings"] != nil {
		t.no("oidc.provider.backendRefs", nil, "")
	}
	if sp["clientIDRef"] != nil {
		t.no("oidc.clientIDRef", nil, "")
		t.out.FailClosed = append(t.out.FailClosed, "oidc")
		return
	}
	id := ecStr(sp["clientID"])
	if id == "" {
		fail("clientID is required")
		return
	}
	oc["clientId"] = id
	t.ok("rule", "oidc.clientID", nil)
	if name := ecStr(ecDig(sp, "clientSecret", "name")); name != "" {
		sec := map[string]any{"name": name, "key": "client-secret"}
		if ns := firstStr(ecStr(ecDig(sp, "clientSecret", "namespace")), t.opts.Namespace); ns != "" {
			sec["namespace"] = ns
		}
		oc["clientSecret"] = map[string]any{"secret": sec}
		t.ok("rule", "oidc.clientSecret", nil)
	}
	if sc := ecList(sp["scopes"]); len(sc) > 0 {
		oc["scopes"] = sc
		t.ok("rule", "oidc.scopes", nil)
	}
	redirect := ecStr(sp["redirectURL"])
	if redirect == "" {
		redirect = "/oauth2/callback"
	} else {
		t.ok("rule", "oidc.redirectURL", redirect)
	}
	oc["redirectUrl"] = redirect
	if v := ecStr(sp["logoutPath"]); v != "" {
		oc["logoutPath"] = v
		t.ok("rule", "oidc.logoutPath", v)
	}
	if b, ok := sp["forwardAccessToken"].(bool); ok && b {
		oc["accessTokenHeader"], oc["accessTokenScheme"] = "Authorization", "Bearer"
		t.ok("rule", "oidc.forwardAccessToken", b)
	}
	cookie := map[string]any{}
	if v := ecStr(sp["cookieDomain"]); v != "" {
		cookie["domain"] = v
		t.ok("rule", "oidc.cookieDomain", v)
	}
	if v := ecStr(ecDig(sp, "cookieConfig", "sameSite")); v != "" {
		cookie["sameSite"] = v
		t.ok("rule", "oidc.cookieConfig.sameSite", v)
	}
	if len(cookie) > 0 {
		oc["cookie"] = cookie
	}
	rt, _ := sp["refreshToken"].(bool)
	oc["disableRefresh"] = !rt
	if sp["refreshToken"] != nil {
		t.ok("rule", "oidc.refreshToken", rt)
	}
	if b, _ := sp["disableTokenEncryption"].(bool); b {
		oc["cookieMode"] = "signed"
		t.ok("rule", "oidc.disableTokenEncryption", b)
	}
	for _, f := range []string{"cookieNames", "defaultTokenTTL", "defaultRefreshTokenTTL", "denyRedirect", "resources"} {
		if sp[f] != nil {
			t.no("oidc."+f, nil, "")
		}
	}
	t.auth("oidc", oc)
	t.ok("rule", "oidc", nil)
}

// authorization translates the authorization rules. Rules that name client
// CIDRs only become ipAllow and ipDeny; anything else becomes an
// authorization block, which keeps the order of the rules.
func (t *translator) authorization(sp map[string]any) {
	rules := ecList(sp["rules"])
	cidrOnly := true
	for _, r := range rules {
		rm := ecMap(r)
		p := ecMap(rm["principal"])
		if rm["operation"] != nil || len(ecList(p["clientCIDRs"])) == 0 || len(p) != 1 {
			cidrOnly = false
		}
	}
	if cidrOnly {
		t.authorizationCIDRs(sp)
		return
	}
	def := "deny"
	if strings.EqualFold(ecStr(sp["defaultAction"]), "Allow") {
		def = "allow"
	}
	var out []any
	bad := false
	for i, r := range rules {
		rm := ecMap(r)
		rule, ok := t.authzRule(i, rm)
		if !ok {
			bad = true
			continue
		}
		out = append(out, rule...)
	}
	if bad {
		t.out.FailClosed = append(t.out.FailClosed, "authorization")
		return
	}
	if sp["defaultAction"] != nil {
		t.ok("rule", "authorization.defaultAction", sp["defaultAction"])
	}
	t.auth("authorization", map[string]any{"defaultAction": def, "rules": out})
}

// authzRule translates one rule; header alternatives expand into several Setura rules.
func (t *translator) authzRule(i int, rm map[string]any) ([]any, bool) {
	action := strings.ToLower(ecStr(rm["action"]))
	if action != "allow" && action != "deny" {
		t.no("authorization.rules", nil, "rule "+strconv.Itoa(i+1)+" has no action of Allow or Deny")
		return nil, false
	}
	principal := map[string]any{}
	p := ecMap(rm["principal"])
	for _, pk := range sortedKeys(p) {
		switch pk {
		case "clientCIDRs":
			principal["cidrs"] = ecList(p[pk])
			t.ok("rule", "authorization.rules.principal.clientCIDRs", nil)
		case "jwt":
			j := ecMap(p[pk])
			var claims []any
			for _, c := range ecList(j["claims"]) {
				cm := ecMap(c)
				if ecStr(cm["name"]) == "" || len(ecList(cm["values"])) == 0 {
					t.no("authorization.rules.principal.jwt", nil, "a claim needs a name and values")
					return nil, false
				}
				claims = append(claims, map[string]any{"name": ecStr(cm["name"]), "in": ecList(cm["values"])})
			}
			if len(claims) > 0 {
				principal["claims"] = claims
			}
			if sc := ecList(j["scopes"]); len(sc) > 0 {
				principal["scopes"] = sc
			}
			if len(claims) == 0 && len(ecList(j["scopes"])) == 0 {
				t.no("authorization.rules.principal.jwt", nil, "the rule names neither claims nor scopes")
				return nil, false
			}
			t.ok("rule", "authorization.rules.principal.jwt", nil)
		case "headers":
		default:
			t.no("authorization.rules.principal."+pk, nil, "")
			return nil, false
		}
	}
	// Headers of the principal and methods of the operation are all conditions of one request:
	// they combine into operations, alternatives of one header value multiply.
	ops := []map[string]any{{}}
	if hs := ecList(p["headers"]); len(hs) > 0 {
		for _, h := range hs {
			hm := ecMap(h)
			vals := ecList(hm["values"])
			if v := hm["value"]; v != nil {
				vals = []any{v}
			}
			if ecStr(hm["name"]) == "" || len(vals) == 0 {
				t.no("authorization.rules.principal.headers", nil, "a header needs a name and values")
				return nil, false
			}
			var next []map[string]any
			for _, op := range ops {
				for _, v := range vals {
					n := map[string]any{}
					for k, x := range op {
						n[k] = x
					}
					n["headers"] = append(append([]any{}, ecList(op["headers"])...), map[string]any{"name": ecStr(hm["name"]), "exact": ecStr(v)})
					next = append(next, n)
				}
			}
			if len(next) > 32 {
				t.no("authorization.rules.principal.headers", nil, "the header alternatives expand to more than 32 combinations")
				return nil, false
			}
			ops = next
		}
		t.ok("rule", "authorization.rules.principal.headers", nil)
	}
	if o := ecMap(rm["operation"]); o != nil {
		for _, k := range sortedKeys(o) {
			if k != "methods" {
				t.no("authorization.rules.operation", nil, "operation."+k+" cannot be expressed; only methods are translated")
				return nil, false
			}
		}
		if ms := ecList(o["methods"]); len(ms) > 0 {
			for _, op := range ops {
				op["methods"] = ms
			}
		}
		t.ok("rule", "authorization.rules.operation", nil)
	}
	var out []any
	for n, op := range ops {
		r := map[string]any{"action": action}
		if len(principal) > 0 {
			r["principals"] = []any{principal}
		}
		if len(op) > 0 {
			r["operations"] = []any{op}
		}
		r["name"] = fmt.Sprintf("rule-%d", i+1)
		if len(ops) > 1 {
			r["name"] = fmt.Sprintf("rule-%d.%d", i+1, n+1)
		}
		out = append(out, r)
	}
	return out, true
}

// ---- HTTPRouteFilter credentialInjection ----

// credentialInjection translates credentialInjection into an auth inject entry.
func (t *translator) credentialInjection(ci map[string]any, ns string) map[string]any {
	name := ecStr(ecDig(ci, "credential", "valueRef", "name"))
	if name == "" {
		t.no("credentialInjection", nil, "credential.valueRef.name is required")
		return nil
	}
	if k := ecStr(ecDig(ci, "credential", "valueRef", "kind")); k != "" && k != "Secret" {
		t.no("credentialInjection", nil, "the credential must be a Secret")
		return nil
	}
	sec := map[string]any{"name": name, "key": "credential"}
	if n := firstStr(ecStr(ecDig(ci, "credential", "valueRef", "namespace")), ns); n != "" {
		sec["namespace"] = n
	}
	t.ok("rule", "credentialInjection", nil)
	if b, ok := ci["overwrite"].(bool); ok && !b {
		t.part("rule", "credentialInjection.overwrite", b, "")
	}
	return map[string]any{"header": firstStr(ecStr(ci["header"]), "Authorization"), "secret": map[string]any{"secret": sec}}
}
