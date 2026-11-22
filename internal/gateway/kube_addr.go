package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
)

// GatewayAddress is one entry of Gateway status.addresses.
type GatewayAddress struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// noteStale remembers a route that no longer names one of our Gateways but
// still carries status written by this controller, so WriteStatus can remove it.
func noteStale(stale map[string]extraRaw, base, plural, kind string, o kobj, raw json.RawMessage) {
	var st struct {
		Parents []ParentStatus `json:"parents"`
	}
	if json.Unmarshal(o.Status, &st) != nil {
		return
	}
	for _, p := range st.Parents {
		if p.ControllerName == ControllerName {
			stale[kind+"|"+o.Metadata.Namespace+"/"+o.Metadata.Name] = extraRaw{base: base, plural: plural, raw: raw}
			return
		}
	}
}

// gatewayAddresses derives Gateway status.addresses from the Service that
// "setura gateway install" creates: its LoadBalancer ingress IPs and hostnames,
// else its ClusterIP. It also returns that Service's raw object.
func (k *KubeSource) gatewayAddresses(svcs []kobj, raw []json.RawMessage) ([]GatewayAddress, json.RawMessage) {
	if k.SvcName == "" {
		return nil, nil
	}
	for i, s := range svcs {
		if s.Metadata.Name != k.SvcName || s.Metadata.Namespace != k.SvcNS {
			continue
		}
		var spec struct {
			Type      string `json:"type"`
			ClusterIP string `json:"clusterIP"`
		}
		var st struct {
			LoadBalancer struct {
				Ingress []struct {
					IP       string `json:"ip"`
					Hostname string `json:"hostname"`
				} `json:"ingress"`
			} `json:"loadBalancer"`
		}
		json.Unmarshal(s.Spec, &spec)
		json.Unmarshal(s.Status, &st)
		var out []GatewayAddress
		if spec.Type == "LoadBalancer" {
			for _, in := range st.LoadBalancer.Ingress {
				if in.IP != "" {
					out = append(out, GatewayAddress{"IPAddress", in.IP})
				}
				if in.Hostname != "" {
					out = append(out, GatewayAddress{"Hostname", in.Hostname})
				}
			}
		}
		if len(out) == 0 && spec.ClusterIP != "" && spec.ClusterIP != "None" {
			out = append(out, GatewayAddress{"IPAddress", spec.ClusterIP})
		}
		return out, raw[i]
	}
	return nil, nil
}

// listenerPorts returns the distinct spec ports of the HTTP, HTTPS and TLS
// listeners of the Gateways we serve.
func listenerPorts(cfg *Config) []int {
	seen := map[int]bool{}
	var out []int
	var lists [][]Listener
	for _, g := range cfg.Gateways {
		lists = append(lists, g.Listeners)
	}
	for _, ls := range cfg.ListenerSets { // listeners added through ListenerSets need Service ports too
		lists = append(lists, ls.Listeners)
	}
	for _, listeners := range lists {
		for _, l := range listeners {
			switch strings.ToUpper(l.Protocol) {
			case "HTTP", "HTTPS", "TLS", "TCP":
				if l.Port >= 1 && l.Port <= 65535 && !seen[l.Port] {
					seen[l.Port] = true
					out = append(out, l.Port)
				}
			}
		}
	}
	sort.Ints(out)
	return out
}

// servicePortPrefix marks Service ports this controller added; only those are
// ever removed again.
const servicePortPrefix = "gw-"

// reconcileServicePorts (--expose-gateway-ports) makes the install Service
// carry a port for every listener port of our Gateways, so listeners other
// than 80 and 443 are reachable. Ports it did not add are left alone.
func (k *KubeSource) reconcileServicePorts(ctx context.Context) error {
	k.mu.Lock()
	raw, ports := k.svcRaw, k.gwPorts
	k.mu.Unlock()
	if !k.ExposePorts || raw == nil {
		return nil
	}
	var o kobj
	if json.Unmarshal(raw, &o) != nil {
		return nil
	}
	var spec struct {
		Ports []map[string]any `json:"ports"`
	}
	json.Unmarshal(o.Spec, &spec)
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	have := map[int]bool{}
	var next []map[string]any
	for _, sp := range spec.Ports {
		port, _ := sp["port"].(float64)
		name, _ := sp["name"].(string)
		if strings.HasPrefix(name, servicePortPrefix) && !want[int(port)] {
			continue // ours, no longer needed
		}
		have[int(port)] = true
		next = append(next, sp)
	}
	for _, p := range ports {
		if have[p] {
			continue
		}
		target := p
		if to, ok := k.PortMap[p]; ok {
			if to == 0 {
				continue // random port: nothing stable to expose
			}
			target = to
		} else if p < 1024 {
			target += k.PortOffset
		}
		next = append(next, map[string]any{"name": fmt.Sprintf("%s%d", servicePortPrefix, p), "protocol": "TCP", "port": p, "targetPort": target})
	}
	if next == nil {
		next = []map[string]any{}
	}
	if len(next) == len(spec.Ports) && reflect.DeepEqual(portNumbers(next), portNumbers(spec.Ports)) {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"spec": map[string]any{"ports": next}})
	_, err := k.do(ctx, http.MethodPatch, "/api/v1/namespaces/"+url.PathEscape(o.Metadata.Namespace)+"/services/"+url.PathEscape(o.Metadata.Name), body, "application/merge-patch+json")
	return err
}

func portNumbers(ps []map[string]any) []int {
	out := make([]int, 0, len(ps))
	for _, p := range ps {
		n, _ := p["port"].(float64)
		if n == 0 {
			if i, ok := p["port"].(int); ok {
				n = float64(i)
			}
		}
		out = append(out, int(n))
	}
	return out
}
