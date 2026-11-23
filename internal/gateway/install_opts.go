package gateway

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var quantityRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?(m|k|Ki|M|Mi|G|Gi|T|Ti|P|Pi|E|Ei)?$`)

// ParseNodePorts reads "HTTP=30080,HTTPS=30443" or "7443=30743": Service port
// names (any case) or numbers mapped to node ports. dst may be nil.
func ParseNodePorts(spec string, dst map[string]int) (map[string]int, error) {
	if dst == nil {
		dst = map[string]int{}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("--node-port %q: want NAME=PORT, for example HTTP=30080,HTTPS=30443", part)
		}
		k = strings.ToLower(strings.TrimSpace(k))
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if k == "" || err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--node-port %q: want NAME=PORT with PORT 1-65535, for example HTTP=30080", part)
		}
		if _, dup := dst[k]; dup {
			return nil, fmt.Errorf("--node-port names %s twice", k)
		}
		dst[k] = n
	}
	return dst, nil
}

// ParseKeyValues reads "a=b,c=d" into dst (flag --node-selector). dst may be nil.
func ParseKeyValues(flag, spec string, dst map[string]string) (map[string]string, error) {
	if dst == nil {
		dst = map[string]string{}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("--%s %q: want KEY=VALUE[,KEY=VALUE...]", flag, part)
		}
		dst[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return dst, nil
}

// ParseResources reads "requests.cpu=100m,limits.memory=256Mi" into dst.
func ParseResources(spec string, dst map[string]string) (map[string]string, error) {
	if dst == nil {
		dst = map[string]string{}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "requests.cpu", "requests.memory", "limits.cpu", "limits.memory":
		default:
			if !ok {
				k = part
			}
			return nil, fmt.Errorf("--resources %q: want requests.cpu, requests.memory, limits.cpu or limits.memory, for example requests.cpu=100m,limits.memory=256Mi", k)
		}
		if !quantityRe.MatchString(v) {
			return nil, fmt.Errorf("--resources %s=%q is not a Kubernetes quantity such as 100m, 1 or 256Mi", k, v)
		}
		dst[k] = v
	}
	return dst, nil
}

// Validate reports the first problem with the options, in operator terms.
func (o InstallOptions) Validate() error {
	switch o.ServiceType {
	case "", "ClusterIP", "NodePort", "LoadBalancer":
	default:
		return fmt.Errorf("--service-type %q: want ClusterIP, NodePort or LoadBalancer", o.ServiceType)
	}
	exposed := o.ServiceType == "NodePort" || o.ServiceType == "LoadBalancer"
	switch o.ExternalTrafficPolicy {
	case "":
	case "Local", "Cluster":
		if !exposed {
			return fmt.Errorf("--external-traffic-policy needs --service-type NodePort or LoadBalancer (a ClusterIP Service has no external traffic)")
		}
	default:
		return fmt.Errorf("--external-traffic-policy %q: want Local or Cluster", o.ExternalTrafficPolicy)
	}
	if len(o.NodePorts) > 0 && !exposed {
		return fmt.Errorf("--node-port needs --service-type NodePort or LoadBalancer")
	}
	known := map[string]bool{"http": true, "https": true, "80": true, "443": true}
	for _, p := range o.ListenerPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("--listener-port %d is out of range", p)
		}
		if p == 80 || p == 443 || p == adminPort {
			return fmt.Errorf("--listener-port %d is already a port of the controller Service", p)
		}
		known[strconv.Itoa(p)] = true
	}
	if o.WithMonitoring {
		known["admin"], known[strconv.Itoa(adminPort)] = true, true
	}
	used := map[int]string{}
	for k, np := range o.NodePorts {
		if !known[k] {
			return fmt.Errorf("--node-port %s=%d: the Service has no port %q (it has http, https and the --listener-port values)", k, np, k)
		}
		if other, dup := used[np]; dup {
			return fmt.Errorf("--node-port: %s and %s both use node port %d", other, k, np)
		}
		used[np] = k
	}
	for _, a := range o.Args {
		if !strings.HasPrefix(a, "-") || strings.ContainsAny(a, "\n\r") {
			return fmt.Errorf("--arg %q: want one controller flag per --arg, such as --arg --rate-limit=100", a)
		}
	}
	for k, v := range o.Resources {
		if !quantityRe.MatchString(v) {
			return fmt.Errorf("--resources %s=%q is not a Kubernetes quantity", k, v)
		}
	}
	if o.CRDs || o.GatewayAPIVersion != "" {
		if o.GatewayAPIVersion != "" {
			if _, err := ParseGatewayAPIVersion(o.GatewayAPIVersion); err != nil {
				return fmt.Errorf("--gateway-api-version: %w", err)
			}
		}
	}
	switch o.GatewayAPIChannel {
	case "", "standard", "experimental":
	default:
		return fmt.Errorf("--gateway-api-channel %q: want standard or experimental", o.GatewayAPIChannel)
	}
	if o.AdminTokenSecret != "" && !regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`).MatchString(o.AdminTokenSecret) {
		return fmt.Errorf("--admin-token-secret %q is not a valid Secret name", o.AdminTokenSecret)
	}
	if o.Replicas < 0 {
		return fmt.Errorf("--replicas must not be negative")
	}
	return nil
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
