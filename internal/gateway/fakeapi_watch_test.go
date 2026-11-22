package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// This file extends fakeAPI (kube_test.go) with watch streams, a Lease
// endpoint and Service patches.

var fakeColl = map[string]string{
	"/apis/gateway.networking.k8s.io/v1/gatewayclasses": "gatewayclasses",
	"/apis/gateway.networking.k8s.io/v1/gateways":       "gateways",
	"/apis/gateway.networking.k8s.io/v1/httproutes":     "httproutes",
	"/apis/gateway.networking.k8s.io/v1/grpcroutes":     "grpcroutes",
	"/apis/gateway.networking.k8s.io/v1/tlsroutes":      "tlsroutes",
	"/api/v1/services":                                        "services",
	"/apis/discovery.k8s.io/v1/endpointslices":                "endpointslices",
	"/apis/gateway.networking.k8s.io/v1beta1/referencegrants": "referencegrants",
	"/api/v1/namespaces":                                      "namespaces",
}

type fakeEv struct {
	rv   int
	line []byte
}

type fakeSub struct {
	coll string
	ch   chan []byte
	quit chan struct{}
}

type fakeWatchState struct {
	hist         map[string][]fakeEv
	subs         map[*fakeSub]bool
	compactBelow int            // watch from an older resourceVersion gets 410
	goneOnce     map[string]int // next N watch requests for a collection get 410
	noWatch      bool           // watch requests get 404
	bookmarks    bool           // send a BOOKMARK on connect
	log          []string       // "collection@resourceVersion" per watch request
	leases       map[string]m
	leaseFail    bool
	svcPatches   []m
}

func (f *fakeAPI) watchLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.watch.log...)
}

func (f *fakeAPI) watchCount(coll string) int {
	n := 0
	for _, l := range f.watchLog() {
		if strings.HasPrefix(l, coll+"@") {
			n++
		}
	}
	return n
}

// emit records and broadcasts a change. The caller holds f.mu.
func (f *fakeAPI) emit(coll, typ string, obj any) {
	f.rv++
	if om, ok := obj.(m); ok {
		md, _ := om["metadata"].(m)
		if md == nil {
			md = m{}
			om["metadata"] = md
		}
		md["resourceVersion"] = fmt.Sprint(f.rv)
	}
	line, _ := json.Marshal(m{"type": typ, "object": obj})
	line = append(line, '\n')
	if f.watch.hist == nil {
		f.watch.hist = map[string][]fakeEv{}
	}
	f.watch.hist[coll] = append(f.watch.hist[coll], fakeEv{f.rv, line})
	for s := range f.watch.subs {
		if s.coll == coll {
			select {
			case s.ch <- line:
			default:
			}
		}
	}
}

// dropWatches ends every open watch stream cleanly, like a server timeout.
func (f *fakeAPI) dropWatches() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for s := range f.watch.subs {
		close(s.quit)
		delete(f.watch.subs, s)
	}
}

// sendGone pushes an in-stream 410 ERROR event to every watcher.
func (f *fakeAPI) sendGone() {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := []byte(`{"type":"ERROR","object":{"kind":"Status","code":410,"reason":"Expired"}}` + "\n")
	for s := range f.watch.subs {
		s.ch <- line
	}
}

func (f *fakeAPI) setWatch(fn func(w *fakeWatchState)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.watch)
}

func (f *fakeAPI) serveExtra(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	switch {
	case r.URL.Query().Get("watch") == "1":
		f.serveWatch(w, r)
		return true
	case strings.Contains(path, "/leases"):
		f.serveLease(w, r)
		return true
	case r.Method == http.MethodPatch && strings.HasPrefix(path, "/api/v1/namespaces/") && strings.Contains(path, "/services/"):
		parts := strings.Split(path, "/") // "", api, v1, namespaces, NS, services, NAME
		var patch m
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &patch)
		f.mu.Lock()
		defer f.mu.Unlock()
		obj, _ := f.objects["services"][parts[4]+"/"+parts[6]].(m)
		if obj == nil {
			http.NotFound(w, r)
			return true
		}
		spec, _ := obj["spec"].(m)
		for k, v := range patch["spec"].(m) {
			spec[k] = v
		}
		f.watch.svcPatches = append(f.watch.svcPatches, patch)
		f.emit("services", "MODIFIED", obj)
		w.Write([]byte("{}"))
		return true
	}
	return false
}

func (f *fakeAPI) serveWatch(w http.ResponseWriter, r *http.Request) {
	coll := fakeColl[r.URL.Path]
	rvq := r.URL.Query().Get("resourceVersion")
	f.mu.Lock()
	f.watch.log = append(f.watch.log, coll+"@"+rvq)
	rv, _ := strconv.Atoi(rvq)
	switch {
	case coll == "" || f.watch.noWatch:
		f.mu.Unlock()
		http.NotFound(w, r)
		return
	case f.watch.goneOnce[coll] > 0 || (rvq != "" && rv < f.watch.compactBelow):
		if f.watch.goneOnce[coll] > 0 {
			f.watch.goneOnce[coll]--
		}
		f.mu.Unlock()
		http.Error(w, `{"kind":"Status","code":410,"reason":"Expired"}`, http.StatusGone)
		return
	}
	sub := &fakeSub{coll: coll, ch: make(chan []byte, 1024), quit: make(chan struct{})}
	if f.watch.subs == nil {
		f.watch.subs = map[*fakeSub]bool{}
	}
	for _, ev := range f.watch.hist[coll] {
		if ev.rv > rv {
			sub.ch <- ev.line
		}
	}
	if f.watch.bookmarks {
		sub.ch <- []byte(fmt.Sprintf(`{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"%d"}}}`+"\n", f.rv))
	}
	f.watch.subs[sub] = true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.watch.subs, sub)
		f.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fl := w.(http.Flusher)
	fl.Flush()
	for {
		select {
		case line := <-sub.ch:
			w.Write(line)
			fl.Flush()
		case <-sub.quit:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (f *fakeAPI) serveLease(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.watch.leaseFail {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	if f.watch.leases == nil {
		f.watch.leases = map[string]m{}
	}
	parts := strings.Split(r.URL.Path, "/") // ... namespaces NS leases [NAME]
	ns := parts[5]
	name := ""
	if len(parts) > 7 {
		name = parts[7]
	}
	var body m
	b, _ := io.ReadAll(r.Body)
	json.Unmarshal(b, &body)
	switch r.Method {
	case http.MethodGet:
		o := f.watch.leases[ns+"/"+name]
		if o == nil {
			http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(o)
	case http.MethodPost:
		name = body["metadata"].(m)["name"].(string)
		if f.watch.leases[ns+"/"+name] != nil {
			http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
			return
		}
		f.rv++
		body["metadata"].(m)["resourceVersion"] = fmt.Sprint(f.rv)
		f.watch.leases[ns+"/"+name] = body
		json.NewEncoder(w).Encode(body)
	case http.MethodPut:
		cur := f.watch.leases[ns+"/"+name]
		if cur == nil {
			http.NotFound(w, r)
			return
		}
		if body["metadata"].(m)["resourceVersion"] != cur["metadata"].(m)["resourceVersion"] {
			http.Error(w, `{"kind":"Status","code":409}`, http.StatusConflict)
			return
		}
		f.rv++
		body["metadata"].(m)["resourceVersion"] = fmt.Sprint(f.rv)
		f.watch.leases[ns+"/"+name] = body
		json.NewEncoder(w).Encode(body)
	}
}

// leaseSpec returns a copy of the stored Lease spec ("" holder when released).
func (f *fakeAPI) leaseSpec(ns, name string) (holder string, transitions int, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	o := f.watch.leases[ns+"/"+name]
	if o == nil {
		return "", 0, false
	}
	spec := o["spec"].(m)
	holder, _ = spec["holderIdentity"].(string)
	t, _ := spec["leaseTransitions"].(float64)
	return holder, int(t), true
}

// setLease makes another replica the holder, renewed now.
func (f *fakeAPI) setLease(ns, name, holder string, seconds int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.watch.leases == nil {
		f.watch.leases = map[string]m{}
	}
	f.rv++
	now := time.Now().UTC().Format(microTime)
	f.watch.leases[ns+"/"+name] = m{"metadata": m{"name": name, "namespace": ns, "resourceVersion": fmt.Sprint(f.rv)},
		"spec": m{"holderIdentity": holder, "leaseDurationSeconds": seconds, "acquireTime": now, "renewTime": now, "leaseTransitions": 1}}
}
