package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func init() {
	for plural, coll := range map[string]string{"listenersets": "listenersets", "tcproutes": "tcproutes", "udproutes": "udproutes", "backendtlspolicies": "backendtlspolicies"} {
		fakeColl["/apis/gateway.networking.k8s.io/v1/"+plural] = coll
	}
}

func (f *fakeAPI) configMap(ns, name string, data m) {
	f.put("configmaps", ns, name, m{"data": data})
}

func TestKubernetesGatewayAPI15(t *testing.T) {
	up := newUpstream(t, "plain")
	p := newPKI(t)
	secureAddr, _ := httpsBackend(t, p, nil, []string{"secure.internal"})
	tcpAddr := tcpBackend(t, "T")

	api := newFakeAPI(t)
	api.seed(up.addr())
	api.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura",
		"addresses":        l{m{"type": "IPAddress", "value": "203.0.113.50"}},
		"allowedListeners": m{"namespaces": m{"from": "All"}},
		"listeners": l{
			m{"name": "web", "protocol": "HTTP", "port": 8080, "allowedRoutes": m{"namespaces": m{"from": "All"}}},
			m{"name": "tcp", "protocol": "TCP", "port": 9000, "allowedRoutes": m{"namespaces": m{"from": "All"}}},
		}}})
	// A ListenerSet adds a hostname listener and a route attaches through it.
	api.put("listenersets", "shop", "team", m{"spec": m{"parentRef": m{"kind": "Gateway", "name": "edge", "namespace": "infra"},
		"listeners": l{m{"name": "api", "protocol": "HTTP", "port": 8081, "hostname": "set.test", "allowedRoutes": m{"namespaces": m{"from": "Same"}}}}}})
	api.put("httproutes", "shop", "viaset", m{"spec": m{"parentRefs": l{m{"kind": "ListenerSet", "name": "team"}},
		"rules": l{m{"backendRefs": l{m{"name": "orders", "port": 80}}}}}})
	// TCPRoute to a Service.
	api.put("services", "shop", "tcpsvc", m{"spec": m{"ports": l{m{"name": "raw", "port": 9100}}}})
	api.put("endpointslices", "shop", "tcpsvc-a", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "tcpsvc"}},
		"endpoints": l{m{"addresses": l{hostOf(tcpAddr)}, "conditions": m{"ready": true}}}, "ports": l{m{"name": "raw", "port": portOf(tcpAddr)}}})
	api.put("tcproutes", "shop", "raw", m{"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra", "sectionName": "tcp"}},
		"rules": l{m{"backendRefs": l{m{"name": "tcpsvc", "port": 9100}}}}}})
	// A Service whose pods speak TLS, a CA ConfigMap and the BackendTLSPolicy.
	api.put("services", "shop", "secure", m{"spec": m{"ports": l{m{"name": "https", "port": 443}}}})
	api.put("endpointslices", "shop", "secure-a", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "secure"}},
		"endpoints": l{m{"addresses": l{hostOf(secureAddr)}, "conditions": m{"ready": true}}}, "ports": l{m{"name": "https", "port": portOf(secureAddr)}}})
	api.configMap("shop", "secure-ca", m{"ca.crt": caPEM(p)})
	api.put("backendtlspolicies", "shop", "secure", m{"metadata": m{"generation": 4}, "spec": m{
		"targetRefs": l{m{"group": "", "kind": "Service", "name": "secure"}},
		"validation": m{"hostname": "secure.internal", "caCertificateRefs": l{m{"group": "", "kind": "ConfigMap", "name": "secure-ca"}}}},
		"status": m{"ancestors": l{m{"ancestorRef": m{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "other-gw"}, "controllerName": "example.com/other",
			"conditions": l{m{"type": "Accepted", "status": "True", "reason": "Accepted", "message": "", "observedGeneration": 4, "lastTransitionTime": "2026-01-01T00:00:00Z"}}}}}})
	api.put("httproutes", "shop", "securer", m{"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra", "sectionName": "web"}}, "hostnames": l{"secure.test"},
		"rules": l{m{"backendRefs": l{m{"name": "secure", "port": 443}}}}}})

	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.Poll = true
	s := New(Options{PortMap: map[int]int{8080: 0, 8081: 0, 9000: 0}, Admin: "off"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ks, 20*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done; s.Close() })
	waitFor(t, "controller ready", func() bool { return s.Ready() })

	if r := req(t, client(s.Addr(8081), nil), "http", "GET", "set.test:8081", "/orders/1", ""); r.Status != 200 {
		t.Errorf("route through the ListenerSet: %d", r.Status)
	}
	if r := req(t, client(s.Addr(8080), nil), "http", "GET", "secure.test:8080", "/", ""); r.Status != 200 || r.Body != "secure" {
		t.Errorf("BackendTLSPolicy over the kube source: %d %q", r.Status, r.Body)
	}
	c, err := net.Dial("tcp", s.Addr(9000))
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "ping")
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if got, _ := io.ReadAll(c); string(got) != "T:ping" {
		t.Errorf("TCPRoute over the kube source: %q", got)
	}
	c.Close()

	// Status written back.
	waitFor(t, "ListenerSet and policy status", func() bool {
		ls, _ := api.get("listenersets", "shop", "team")["status"].(m)
		pol, _ := api.get("backendtlspolicies", "shop", "secure")["status"].(m)
		anc, _ := pol["ancestors"].([]any)
		return ls != nil && len(anc) == 2
	})
	ls := api.get("listenersets", "shop", "team")["status"].(m)
	if conds, _ := ls["conditions"].([]any); len(conds) != 2 || conds[0].(m)["status"] != "True" {
		t.Errorf("ListenerSet conditions: %v", ls["conditions"])
	}
	pol := api.get("backendtlspolicies", "shop", "secure")["status"].(m)["ancestors"].([]any)
	var ours, foreign m
	for _, a := range pol {
		am := a.(m)
		if am["controllerName"] == ControllerName {
			ours = am
		} else {
			foreign = am
		}
	}
	if foreign == nil || ours == nil || ours["ancestorRef"].(m)["name"] != "edge" {
		t.Fatalf("policy ancestors (other controllers' status must be kept): %v", pol)
	}
	for _, cnd := range ours["conditions"].([]any) {
		if cm := cnd.(m); cm["status"] != "True" || cm["observedGeneration"].(float64) != 4 {
			t.Errorf("policy condition %v", cm)
		}
	}
	gw := api.get("gateways", "infra", "edge")["status"].(m)
	addrs, _ := json.Marshal(gw["addresses"])
	if !strings.Contains(string(addrs), "203.0.113.50") || gw["attachedListenerSets"].(float64) != 1 {
		t.Errorf("gateway status: addresses %s attachedListenerSets %v", addrs, gw["attachedListenerSets"])
	}
	if st, _ := api.get("tcproutes", "shop", "raw")["status"].(m); st == nil {
		t.Errorf("TCPRoute status not written")
	}
	_ = http.StatusOK
}
