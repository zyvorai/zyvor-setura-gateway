package setura

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// kubectlError reports a failed or timed-out kubectl invocation.
type kubectlError struct{ msg string }

func (e *kubectlError) Error() string { return e.msg }

// ExecFunc runs a command and returns stdout, stderr and the exit code.
type ExecFunc func(args []string) (stdout, stderr string, code int, err error)

func defaultExec(args []string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", "", -1, &kubectlError{"kubectl timed out after 20s"}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), errb.String(), ee.ExitCode(), nil
	}
	return out.String(), errb.String(), 0, err
}

// Cluster reads Gateway evidence through kubectl's selected context.
type Cluster struct {
	Context string
	Exec    ExecFunc
}

func NewCluster(context string) *Cluster { return &Cluster{Context: context, Exec: defaultExec} }

func (c *Cluster) cmd() []string {
	if c.Context != "" {
		return []string{"kubectl", "--context", c.Context}
	}
	return []string{"kubectl"}
}

func (c *Cluster) Get(namespace, resource string, options ...string) (any, error) {
	ns, err := label(namespace)
	if err != nil {
		return nil, err
	}
	args := append(c.cmd(), "-n", ns, "get", resource)
	args = append(args, options...)
	args = append(args, "-o", "json", "--request-timeout=10s")
	out, errs, code, err := c.Exec(args)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		msg := strings.TrimSpace(errs)
		if msg == "" {
			msg = "kubectl get " + resource + " failed"
		}
		return nil, &kubectlError{msg}
	}
	var v any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		return nil, fmt.Errorf("kubectl returned invalid JSON: %w", err)
	}
	return v, nil
}

func (c *Cluster) getMap(namespace, resource string, options ...string) (obj, error) {
	v, err := c.Get(namespace, resource, options...)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected kubectl output for %s", resource)
	}
	return m, nil
}

// Publication builds the kubectl port-forward command for a Gateway listener.
// servicePort < 0 means unset.
func (c *Cluster) Publication(namespace, gateway, listener, proxyNamespace string, localPort int, service string, servicePort int) ([]string, error) {
	if localPort < 1 || localPort > 65535 {
		return nil, userError("local port must be between 1 and 65535")
	}
	gw, err := label(gateway)
	if err != nil {
		return nil, err
	}
	o, err := c.getMap(namespace, "gateway.gateway.networking.k8s.io/"+gw)
	if err != nil {
		return nil, err
	}
	var target obj
	for _, item := range asList(dig(o, "spec", "listeners")) {
		if m := asMap(item); m["name"] == listener {
			target = m
			break
		}
	}
	if target == nil || (target["protocol"] != "HTTP" && target["protocol"] != "HTTPS") {
		return nil, userError("choose an existing HTTP or HTTPS listener")
	}
	selector := fmt.Sprintf("gateway.envoyproxy.io/owning-gateway-name=%s,gateway.envoyproxy.io/owning-gateway-namespace=%s", gateway, namespace)
	if servicePort >= 0 && (service == "" || servicePort < 1 || servicePort > 65535) {
		return nil, userError("service-port requires an explicit Service and a port from 1 to 65535")
	}
	remotePort := 0
	if servicePort >= 0 {
		remotePort = servicePort
	} else if p, ok := num(target["port"]); ok {
		remotePort = int(p)
	}
	var services []any
	if service != "" {
		name, err := label(service)
		if err != nil {
			return nil, err
		}
		s, err := c.getMap(proxyNamespace, "service/"+name)
		if err != nil {
			return nil, err
		}
		services = []any{s}
	} else {
		list, err := c.getMap(proxyNamespace, "services", "-l", selector)
		if err != nil {
			return nil, err
		}
		services = asList(list["items"])
	}
	var matches []string
	for _, s := range services {
		for _, p := range asList(dig(s, "spec", "ports")) {
			pm := asMap(p)
			port, _ := num(pm["port"])
			if int(port) == remotePort && str(pm, "protocol", "TCP") == "TCP" {
				matches = append(matches, asStr(dig(s, "metadata", "name")))
				break
			}
		}
	}
	if len(matches) != 1 {
		return nil, userErrorf("expected one proxy Service for this listener, found %d", len(matches))
	}
	name, err := label(matches[0])
	if err != nil {
		return nil, err
	}
	pn, err := label(proxyNamespace)
	if err != nil {
		return nil, err
	}
	return append(c.cmd(), "-n", pn, "port-forward", "--address", "127.0.0.1",
		"service/"+name, strconv.Itoa(localPort)+":"+strconv.Itoa(remotePort)), nil
}

// Inspect reads per-parent route status and backend inventory.
func (c *Cluster) Inspect(namespace, route string) (obj, error) {
	name, err := label(route)
	if err != nil {
		return nil, err
	}
	o, err := c.getMap(namespace, "httproute.gateway.networking.k8s.io/"+name)
	if err != nil {
		return nil, err
	}
	generation := req(asMap(req(o, "metadata")), "generation")
	parents := []any{}
	for _, e := range asList(dig(o, "status", "parents")) {
		entry := asMap(e)
		conds := []any{}
		for _, cc := range asList(entry["conditions"]) {
			cm := asMap(cc)
			row := obj{}
			for k, v := range cm {
				row[k] = v
			}
			row["current"] = eq(cm["observedGeneration"], generation)
			conds = append(conds, row)
		}
		parents = append(parents, obj{"parent": req(entry, "parentRef"), "controller": req(entry, "controllerName"), "conditions": conds})
	}
	backends := []any{}
	seen := map[string]bool{}
	for _, r := range asList(dig(o, "spec", "rules")) {
		for _, b := range asList(asMap(r)["backendRefs"]) {
			ref := asMap(b)
			ns := str(ref, "namespace", namespace)
			kind, group := str(ref, "kind", "Service"), str(ref, "group", "")
			key := fmt.Sprint(ns, "|", req(ref, "name"), "|", ref["port"], "|", kind, "|", group)
			if seen[key] {
				continue
			}
			seen[key] = true
			row := obj{"reference": ref, "namespace": ns}
			backends = append(backends, row)
			if kind != "Service" || group != "" {
				row["observation"] = "unsupported backend kind"
				continue
			}
			bn, err := label(asStr(ref["name"]))
			if err != nil {
				return nil, err
			}
			svc, err := c.getMap(ns, "service/"+bn)
			var slices obj
			if err == nil {
				slices, err = c.getMap(ns, "endpointslices.discovery.k8s.io", "-l", "kubernetes.io/service-name="+bn)
			}
			var ke *kubectlError
			if errors.As(err, &ke) {
				row["observation_error"] = ke.msg
				continue
			} else if err != nil {
				return nil, err
			}
			found := false
			for _, p := range asList(dig(svc, "spec", "ports")) {
				if eq(asMap(p)["port"], ref["port"]) {
					found = true
				}
			}
			row["service_port_found"] = found
			counts := obj{"true": 0, "false": 0, "unknown": 0}
			for _, s := range asList(slices["items"]) {
				for _, e := range asList(asMap(s)["endpoints"]) {
					switch dig(e, "conditions", "ready") {
					case true:
						counts["true"] = counts["true"].(int) + 1
					case false:
						counts["false"] = counts["false"].(int) + 1
					default:
						counts["unknown"] = counts["unknown"].(int) + 1
					}
				}
			}
			row["endpoint_records_by_ready_condition"] = counts
		}
	}
	return obj{"namespace": namespace, "route": route, "generation": generation, "parents": parents, "backends": backends}, nil
}
