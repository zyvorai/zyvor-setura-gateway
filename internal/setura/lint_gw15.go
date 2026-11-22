package setura

import (
	"encoding/json"
	"fmt"
	"strings"

	builtin "github.com/zyvorai/zyvor-setura-gateway/internal/gateway"
)

// Gateway API 1.5 resource kinds a snapshot may carry.
const (
	tcpRoute         = "tcproutes." + group
	udpRoute         = "udproutes." + group
	listenerSetRes   = "listenersets." + group
	backendTLSPolicy = "backendtlspolicies." + group
)

// gw15Kinds are captured best effort, like GRPCRoutes (the CRDs are optional).
var gw15Kinds = []string{tcpRoute, udpRoute, listenerSetRes, backendTLSPolicy}

// gw15Rules evaluates SET019: HTTPRoute rules and BackendTLSPolicies that use
// a Gateway API 1.5 feature the built-in gateway would refuse (a CORS filter
// with a malformed origin, an ExternalAuth filter without a protocol or
// backend, invalid session persistence, a backendRequest timeout longer than
// the request timeout, a BackendTLSPolicy without hostname or CA source). The
// checks are the gateway's own, so the linter cannot disagree with it.
func gw15Rules(specs obj, ns string) []obj {
	var findings []obj
	for _, key := range sortedKeys(specs) {
		resource, name, _ := strings.Cut(key, "/")
		var id string
		add := func(msg string) {
			findings = append(findings, obj{"id": "SET019", "severity": ruleSeverity("SET019"), "resource": id, "message": msg})
		}
		spec := asMap(specs[key])
		switch resource {
		case route:
			id = "HTTPRoute/" + ns + "/" + name
			for i, r := range asList(spec["rules"]) {
				raw, _ := json.Marshal(r)
				if err := builtin.CheckRule(raw); err != nil {
					add(fmt.Sprintf("rule %d: %v", i+1, err))
				}
			}
		case backendTLSPolicy:
			id = "BackendTLSPolicy/" + ns + "/" + name
			raw, _ := json.Marshal(spec)
			if err := builtin.CheckBackendTLSPolicy(raw); err != nil {
				add(err.Error())
			}
		}
	}
	return findings
}

// captureCACertificates reads the ConfigMaps the snapshot's BackendTLSPolicies
// name as CA bundles (key ca.crt) into the snapshot's caCertificates section.
// Secrets are never copied.
func captureCACertificates(c *Cluster, namespace string, resources obj) obj {
	out := obj{}
	for key, spec := range resources {
		if resource, _, _ := strings.Cut(key, "/"); resource != backendTLSPolicy {
			continue
		}
		for _, ref := range asList(asMap(asMap(spec)["validation"])["caCertificateRefs"]) {
			rm := asMap(ref)
			name := asStr(rm["name"])
			if name == "" || asStr(rm["kind"]) != "ConfigMap" || out[name] != nil {
				continue
			}
			cm, err := c.getMap(namespace, "configmaps/"+name)
			if err != nil {
				continue
			}
			if pem := asStr(asMap(cm["data"])["ca.crt"]); pem != "" {
				out[name] = obj{"pem": pem}
			}
		}
	}
	return out
}
