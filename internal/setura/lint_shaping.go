package setura

import (
	"encoding/json"
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// blockFor returns the raw block of rule i for an extension key: the rule's
// own field, or its annotation (rule specific over route wide).
func blockFor(spec obj, key string, i int, rule obj) (raw []byte, where string, ok bool) {
	if b, has := rule[key]; has {
		raw, _ := json.Marshal(b)
		return raw, fmt.Sprintf("rule %d", i+1), true
	}
	if k, v, has := annotationFor(spec, key, i); has {
		return []byte(v), "annotation " + k, true
	}
	return nil, "", false
}

// alreadyCompressed are content types whose bytes do not shrink.
var alreadyCompressed = []string{"image/png", "image/jpeg", "image/gif", "image/webp", "image/avif", "image/*", "video/*", "audio/*",
	"application/zip", "application/gzip", "application/x-gzip", "application/pdf", "application/octet-stream", "application/x-tar", "application/wasm"}

func isCompressedType(t string) bool {
	t = strings.ToLower(t)
	for _, c := range alreadyCompressed {
		if t == c {
			return true
		}
	}
	return false
}

// shapingRules evaluates SET070 to SET076: the traffic shaping blocks
// (compress, grpc-web, bandwidth) must parse and validate the way the gateway
// compiles them, and a few settings that work but defeat their purpose are flagged.
func shapingRules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		spec := asMap(specs[key])
		switch resource {
		case route:
			id := "HTTPRoute/" + ns + "/" + name
			add := func(rule, msg string) {
				findings = append(findings, obj{"id": rule, "severity": ruleSeverity(rule), "resource": id, "message": msg})
			}
			rules := asList(spec["rules"])
			rawAnn := map[string]map[string]string{}
			ann := asMap(spec[builtin.SeturaAnnotationsKey])
			for _, base := range builtin.ShapingKeys {
				rawAnn[base] = map[string]string{}
				for _, k := range sortedKeys(ann) {
					if !strings.HasPrefix(k, base) {
						continue
					}
					v, ok := ann[k].(string)
					if !ok {
						add("SET070", fmt.Sprintf("annotation %s: the value must be a JSON string", k))
						continue
					}
					rawAnn[base][k] = v
				}
				for _, k := range builtin.OrphanRuleAnnotations(rawAnn[base], base, len(rules)) {
					add("SET070", fmt.Sprintf("annotation %s names no rule: use %s for the whole route or %s.rule-N with N from 1 to %d", k, base, base, len(rules)))
				}
			}
			for i, r := range rules {
				rule := asMap(r)
				if raw, where, ok := blockFor(spec, builtin.CompressKey, i, rule); ok {
					if c, err := builtin.ParseCompressBlock(raw); err != nil {
						add("SET070", fmt.Sprintf("%s: %v", where, err))
					} else {
						for _, t := range c.Types {
							if isCompressedType(t) {
								add("SET073", fmt.Sprintf("%s: type %s is already compressed, so compressing it burns CPU for no gain", where, t))
							}
						}
					}
				}
				if raw, where, ok := blockFor(spec, builtin.BandwidthKey, i, rule); ok {
					if _, err := builtin.ParseBandwidthBlock(raw); err != nil {
						add("SET070", fmt.Sprintf("%s: %v", where, err))
					}
				}
				if raw, where, ok := blockFor(spec, builtin.GRPCWebKey, i, rule); ok {
					g, err := builtin.ParseGRPCWebBlock(raw)
					if err != nil {
						add("SET070", fmt.Sprintf("%s: %v", where, err))
					} else if g.Enabled == nil || *g.Enabled {
						hasCORS := false
						hasMirror := false
						for _, f := range asList(rule["filters"]) {
							switch asStr(asMap(f)["type"]) {
							case "CORS":
								hasCORS = true
							case "RequestMirror":
								hasMirror = true
							}
						}
						if len(g.AllowOrigins) == 0 && !hasCORS {
							add("SET074", where+": gRPC-web is for browsers, but the rule has neither allowOrigins nor a CORS filter, so a browser's preflight gets no CORS grant and the call is blocked")
						}
						if _, has := rule["retry"]; has || hasMirror {
							add("SET075", where+": retries and mirroring do not apply to bridged gRPC-web calls")
						}
					}
				}
				if raw, where, ok := blockFor(spec, builtin.RateLimitKey, i, rule); ok {
					if rl, err := builtin.ParseRateLimitBlock(raw); err == nil && rl.Shared != nil {
						if rl.Shared.FailOpen != nil && !*rl.Shared.FailOpen {
							add("SET071", where+": shared rate limit fails closed: while Redis is unreachable every request to this rule is answered 503")
						} else if rl.Shared.Fallback == "none" {
							add("SET071", where+": shared rate limit has fallback none: while Redis is unreachable this rule is not rate limited at all")
						}
						if strings.HasPrefix(rl.Key, "header:") && authFor(spec, i, rule) == nil {
							add("SET072", fmt.Sprintf("%s: the shared limit counts per %s, a header the client chooses, so a client can dodge the limit by changing it", where, rl.Key))
						}
					}
				}
			}
		case gateway:
			id := "Gateway/" + ns + "/" + name
			for _, l := range asList(spec["listeners"]) {
				lm := asMap(l)
				lim, ok := lm[builtin.LimitsKey]
				if !ok {
					continue
				}
				raw, _ := json.Marshal(lim)
				ll, err := builtin.ParseListenerLimitsBlock(raw)
				if err == nil && ll.MaxConnections > 0 && ll.MaxConnectionsPerIP > ll.MaxConnections {
					findings = append(findings, obj{"id": "SET076", "severity": ruleSeverity("SET076"), "resource": id,
						"message": fmt.Sprintf("listener %q: maxConnectionsPerIP (%d) is above maxConnections (%d), so the per-IP limit can never be reached", asStr(lm["name"]), ll.MaxConnectionsPerIP, ll.MaxConnections)})
				}
			}
		}
	}
	return findings
}
