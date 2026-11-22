package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI is a tiny Kubernetes API server: it lists objects by path prefix and
// applies JSON merge patches to the status subresource.
type fakeAPI struct {
	*httptest.Server
	mu      sync.Mutex
	objects map[string]map[string]any // collection path -> "ns/name" -> object
	patches []string
	denySA  bool
	t       *testing.T
	rv      int // resourceVersion counter
	watch   fakeWatchState
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{objects: map[string]map[string]any{}, t: t}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAPI) put(collection, ns, name string, obj m) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects[collection] == nil {
		f.objects[collection] = map[string]any{}
	}
	md, _ := obj["metadata"].(m)
	if md == nil {
		md = m{}
		obj["metadata"] = md
	}
	md["name"] = name
	if ns != "" {
		md["namespace"] = ns
	}
	if _, ok := md["generation"]; !ok {
		md["generation"] = 1
	}
	typ := "MODIFIED"
	if f.objects[collection][ns+"/"+name] == nil {
		typ = "ADDED"
	}
	f.objects[collection][ns+"/"+name] = obj
	f.emit(collection, typ, obj)
}

// del removes an object and tells watchers.
func (f *fakeAPI) del(collection, ns, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := f.objects[collection][ns+"/"+name]
	delete(f.objects[collection], ns+"/"+name)
	if obj != nil {
		f.emit(collection, "DELETED", obj)
	}
}

func (f *fakeAPI) get(collection, ns, name string) m {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, _ := f.objects[collection][ns+"/"+name].(m)
	raw, _ := json.Marshal(o)
	var cp m
	json.Unmarshal(raw, &cp)
	return cp
}

func (f *fakeAPI) patchLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.patches...)
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, "unauthorized", 401)
		return
	}
	if f.serveExtra(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	if r.Method == http.MethodPatch {
		if r.Header.Get("Content-Type") != "application/merge-patch+json" {
			http.Error(w, "bad patch type", 415)
			return
		}
		f.patches = append(f.patches, path)
		// /apis/gateway.networking.k8s.io/v1/namespaces/NS/KIND/NAME/status or .../gatewayclasses/NAME/status
		parts := strings.Split(strings.TrimSuffix(path, "/status"), "/")
		var coll, key string
		if parts[len(parts)-2] == "gatewayclasses" {
			coll, key = "gatewayclasses", "/"+parts[len(parts)-1]
		} else {
			coll, key = parts[len(parts)-2], parts[len(parts)-3]+"/"+parts[len(parts)-1]
		}
		obj, _ := f.objects[coll][key].(m)
		if obj == nil {
			http.NotFound(w, r)
			return
		}
		var patch struct {
			Status m `json:"status"`
		}
		b, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(b, &patch); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		st, _ := obj["status"].(m)
		if st == nil {
			st = m{}
		}
		for k, v := range patch.Status {
			st[k] = v
		}
		obj["status"] = st
		f.emit(coll, "MODIFIED", obj)
		w.Write([]byte("{}"))
		return
	}
	// secret and configmap GET: /api/v1/namespaces/NS/{secrets,configmaps}/NAME
	if strings.Contains(path, "/secrets/") || strings.Contains(path, "/configmaps/") {
		parts := strings.Split(path, "/")
		o := f.objects[parts[5]][parts[4]+"/"+parts[6]]
		if o == nil {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(o)
		return
	}
	coll := fakeColl[path]
	if coll == "" || (coll == "referencegrants" && f.denySA) {
		http.Error(w, "forbidden", 403)
		return
	}
	items := []any{}
	for _, k := range sortedKeys(f.objects[coll]) {
		items = append(items, f.objects[coll][k])
	}
	json.NewEncoder(w).Encode(m{"items": items, "metadata": m{"resourceVersion": fmt.Sprint(f.rv)}})
}

func (f *fakeAPI) seed(upstream string) {
	f.put("gatewayclasses", "", "setura", m{"spec": m{"controllerName": ControllerName}})
	f.put("gatewayclasses", "", "other", m{"spec": m{"controllerName": "example.com/other"}})
	f.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "web", "protocol": "HTTP", "port": 8080, "allowedRoutes": m{"namespaces": m{"from": "All"}}}}}})
	f.put("gateways", "infra", "foreign", m{"spec": m{"gatewayClassName": "other", "listeners": l{m{"name": "web", "protocol": "HTTP", "port": 8081}}}})
	f.put("httproutes", "shop", "orders", m{"metadata": m{"creationTimestamp": "2026-01-01T00:00:00Z", "generation": 3},
		"spec": m{"parentRefs": l{m{"name": "edge", "namespace": "infra"}, m{"name": "foreign", "namespace": "infra"}},
			"rules": l{m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/orders"}}}, "backendRefs": l{m{"name": "orders", "port": 80}}}}},
		"status": m{"parents": l{m{"parentRef": m{"name": "foreign", "namespace": "infra"}, "controllerName": "example.com/other",
			"conditions": l{m{"type": "Accepted", "status": "True", "reason": "Accepted", "message": "", "observedGeneration": 3, "lastTransitionTime": "2026-01-01T00:00:00Z"}}}}}})
	f.put("services", "shop", "orders", m{"spec": m{"ports": l{m{"name": "http", "port": 80, "targetPort": 8080}}}})
	f.put("endpointslices", "shop", "orders-abc", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "orders"}},
		"endpoints": l{m{"addresses": l{hostOf(upstream)}, "conditions": m{"ready": true}}, m{"addresses": l{"203.0.113.9"}, "conditions": m{"ready": false}}},
		"ports":     l{m{"name": "http", "port": portOf(upstream)}}})
}

func hostOf(addr string) string { return addr[:strings.LastIndex(addr, ":")] }
func portOf(addr string) int {
	var p int
	for _, c := range addr[strings.LastIndex(addr, ":")+1:] {
		p = p*10 + int(c-'0')
	}
	return p
}

func kubeServer(t *testing.T, api *fakeAPI, token func() string) (*Server, *KubeSource, func()) {
	t.Helper()
	if token == nil {
		token = func() string { return "test-token" }
	}
	ks := NewKubeSource(api.URL, api.Client(), token, nil)
	ks.Poll = true // these tests drive the polling path; watch_test.go covers watches
	s := New(Options{PortMap: map[int]int{8080: 0}, Admin: "off"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ks, 20*time.Millisecond) }()
	waitFor(t, "controller ready", func() bool { return s.Ready() })
	stop := func() { cancel(); <-done; s.Close() }
	t.Cleanup(stop)
	return s, ks, stop
}

func TestKubernetesModeServesAndWritesStatus(t *testing.T) {
	up1, up2 := newUpstream(t, "u1"), newUpstream(t, "u2")
	api := newFakeAPI(t)
	api.seed(up1.addr())
	s, _, _ := kubeServer(t, api, nil)

	r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders/1", "")
	if r.Status != 200 || r.Header.Get(BackendHeader) != "orders" || r.Echo.Name != "u1" {
		t.Fatalf("status %d backend header %q body %s", r.Status, r.Header.Get(BackendHeader), r.Body)
	}
	if n := len(up1.seen()); n != 1 {
		t.Fatalf("upstream saw %d requests", n)
	}
	// The foreign Gateway is not served: its port is not bound.
	for _, e := range s.Table().Cfg.Gateways {
		if e.Name == "foreign" {
			t.Fatal("foreign Gateway must be ignored")
		}
	}

	waitFor(t, "route status", func() bool {
		st, _ := api.get("httproutes", "shop", "orders")["status"].(m)
		parents, _ := st["parents"].([]any)
		return len(parents) == 2
	})
	st := api.get("httproutes", "shop", "orders")["status"].(m)["parents"].([]any)
	var ours, foreign m
	for _, p := range st {
		pm := p.(m)
		if pm["controllerName"] == ControllerName {
			ours = pm
		} else {
			foreign = pm
		}
	}
	if foreign == nil || foreign["controllerName"] != "example.com/other" {
		t.Fatalf("another controller's parent status was clobbered: %v", st)
	}
	if ours["parentRef"].(m)["name"] != "edge" || ours["parentRef"].(m)["kind"] != "Gateway" {
		t.Fatalf("our parentRef: %v", ours)
	}
	want := map[string]string{"Accepted": "True", "ResolvedRefs": "True"}
	for _, c := range ours["conditions"].([]any) {
		cm := c.(m)
		if want[cm["type"].(string)] != cm["status"] || cm["observedGeneration"].(float64) != 3 {
			t.Errorf("condition %v", cm)
		}
		if _, ok := cm["message"]; !ok {
			t.Errorf("message is required by the API schema: %v", cm)
		}
		delete(want, cm["type"].(string))
	}
	if len(want) != 0 {
		t.Errorf("missing conditions %v", want)
	}

	waitFor(t, "gateway status", func() bool {
		st, _ := api.get("gateways", "infra", "edge")["status"].(m)
		return st != nil && st["listeners"] != nil
	})
	gst := api.get("gateways", "infra", "edge")["status"].(m)
	types := map[string]string{}
	for _, c := range gst["conditions"].([]any) {
		types[c.(m)["type"].(string)] = c.(m)["status"].(string)
	}
	if types["Accepted"] != "True" || types["Programmed"] != "True" {
		t.Errorf("gateway conditions %v", types)
	}
	ls := gst["listeners"].([]any)[0].(m)
	if ls["attachedRoutes"].(float64) != 1 || ls["name"] != "web" {
		t.Errorf("listener status %v", ls)
	}
	if api.get("gateways", "infra", "foreign")["status"] != nil {
		t.Error("foreign Gateway status must not be touched")
	}
	waitFor(t, "class status", func() bool { return api.get("gatewayclasses", "", "setura")["status"] != nil })
	if api.get("gatewayclasses", "", "other")["status"] != nil {
		t.Error("foreign GatewayClass status must not be touched")
	}

	// Converged: further polls issue no more writes.
	n := len(api.patchLog())
	time.Sleep(200 * time.Millisecond)
	if got := len(api.patchLog()); got != n {
		t.Fatalf("status was rewritten while converged: %d -> %d patches", n, got)
	}
	for _, p := range api.patchLog() {
		if !strings.HasSuffix(p, "/status") {
			t.Errorf("patch outside the status subresource: %s", p)
		}
	}

	// Endpoints move: the data plane follows within a poll.
	api.put("endpointslices", "shop", "orders-abc", m{"metadata": m{"labels": m{"kubernetes.io/service-name": "orders"}},
		"endpoints": l{m{"addresses": l{hostOf(up2.addr())}, "conditions": m{"ready": true}}},
		"ports":     l{m{"name": "http", "port": portOf(up2.addr())}}})
	waitFor(t, "endpoint change", func() bool {
		return req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders", "").Echo.Name == "u2"
	})

	// Drift repair: someone wipes our status; the controller writes it back.
	before := len(api.patchLog())
	api.mu.Lock()
	api.objects["httproutes"]["shop/orders"].(m)["status"] = m{}
	api.mu.Unlock()
	waitFor(t, "status repair", func() bool { return len(api.patchLog()) > before })
}

func TestKubernetesModeUnresolvedBackendStatus(t *testing.T) {
	api := newFakeAPI(t)
	api.seed("127.0.0.1:1")
	api.put("services", "shop", "orders", m{"spec": m{"ports": l{m{"name": "http", "port": 8080}}}}) // wrong port: backendRef is 80
	s, _, _ := kubeServer(t, api, nil)
	if r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders", ""); r.Status != 500 {
		t.Fatalf("unresolved backend served %d, want 500", r.Status)
	}
	waitFor(t, "ResolvedRefs=False", func() bool {
		st, _ := api.get("httproutes", "shop", "orders")["status"].(m)
		for _, p := range st["parents"].([]any) {
			for _, c := range p.(m)["conditions"].([]any) {
				if c.(m)["type"] == "ResolvedRefs" && c.(m)["status"] == "False" && c.(m)["reason"] == "BackendNotFound" {
					return true
				}
			}
		}
		return false
	})
}

func TestKubernetesModeTLSFromSecretAndGrants(t *testing.T) {
	p := newPKI(t)
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	c, k := p.issue("secure.test")
	api.put("gateways", "infra", "edge", m{"spec": m{"gatewayClassName": "setura", "listeners": l{
		m{"name": "tls", "protocol": "HTTPS", "port": 8443, "hostname": "secure.test", "allowedRoutes": m{"namespaces": m{"from": "All"}},
			"tls": m{"certificateRefs": l{m{"name": "edge-cert", "namespace": "certs"}}}}}}})
	api.put("secrets", "certs", "edge-cert", m{"type": "kubernetes.io/tls", "data": m{
		"tls.crt": base64.StdEncoding.EncodeToString(c), "tls.key": base64.StdEncoding.EncodeToString(k)}})
	api.put("referencegrants", "certs", "g", m{"spec": m{"from": l{m{"group": APIGroup, "kind": "Gateway", "namespace": "infra"}}, "to": l{m{"group": "", "kind": "Secret"}}}})
	ks := NewKubeSource(api.URL, api.Client(), func() string { return "test-token" }, nil)
	ks.Poll = true
	s := New(Options{PortMap: map[int]int{8443: 0}, Admin: "off"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx, ks, 20*time.Millisecond) }()
	t.Cleanup(func() { cancel(); <-done })
	waitFor(t, "ready", s.Ready)
	r := req(t, tlsClient(s.Addr(8443), p, "secure.test"), "https", "GET", "secure.test", "/orders", "")
	if r.Status != 200 || r.Echo.Name != "u" {
		t.Fatalf("status %d %s", r.Status, r.Body)
	}
}

func TestKubernetesAPIErrorsKeepServing(t *testing.T) {
	up := newUpstream(t, "u")
	api := newFakeAPI(t)
	api.seed(up.addr())
	var tok atomic.Value
	tok.Store("test-token")
	s, _, _ := kubeServer(t, api, func() string { return tok.Load().(string) })
	// Break the credentials: loads fail, the old table keeps serving.
	tok.Store("expired")
	waitFor(t, "failed reload recorded", func() bool { return !s.Status().LastReload.OK })
	if !strings.Contains(s.Status().LastReload.Error, "401") {
		t.Fatalf("error %q", s.Status().LastReload.Error)
	}
	if r := req(t, client(s.Addr(8080), nil), "http", "GET", "any.test", "/orders", ""); r.Status != 200 {
		t.Fatalf("serving stopped: %d", r.Status)
	}
	tok.Store("test-token")
	waitFor(t, "recovery", func() bool { return s.Status().LastReload.OK })
}
