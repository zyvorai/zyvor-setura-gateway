package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	saDir        = "/var/run/secrets/kubernetes.io/serviceaccount"
	apiGatewayV1 = "/apis/gateway.networking.k8s.io/v1"
)

type kubeFlags struct {
	api, tokenFile, caFile string
	ctl                    controllerFlags
}

func addKubeFlags(fs *flag.FlagSet) *kubeFlags {
	k := &kubeFlags{}
	fs.StringVar(&k.api, "kube-api", "", "Kubernetes API URL (default: in-cluster service address)")
	fs.StringVar(&k.tokenFile, "kube-token-file", saDir+"/token", "bearer token file, re-read on every request")
	fs.StringVar(&k.caFile, "kube-ca-file", saDir+"/ca.crt", "CA bundle for the API server")
	addControllerFlags(fs, &k.ctl)
	return k
}

func (k *kubeFlags) source(diag io.Writer) (Source, error) {
	base := k.api
	if base == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, errors.New("not running in a cluster: set --kube-api (and --kube-token-file/--kube-ca-file)")
		}
		base = "https://" + net.JoinHostPort(host, port)
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	if strings.HasPrefix(base, "https://") {
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(k.caFile)
		if err != nil {
			return nil, fmt.Errorf("reading API CA: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificates", k.caFile)
		}
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	}
	token := func() string {
		b, err := os.ReadFile(k.tokenFile)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	ks := NewKubeSource(base, hc, token, diag)
	k.ctl.apply(ks)
	return ks, nil
}

// KubeSource reads Gateways, HTTPRoutes, Services, EndpointSlices and Secrets
// through plain HTTPS calls to the Kubernetes API, and writes status back
// through the status subresource. It watches the API (watch.go) unless Poll is
// set, and can elect a leader through a Lease (lease.go).
type KubeSource struct {
	base  string
	hc    *http.Client
	token func() string
	diag  io.Writer

	mu      sync.Mutex
	classes map[string]json.RawMessage // our GatewayClasses, raw
	gwRaw   map[string]json.RawMessage
	rtRaw   map[string]json.RawMessage
	extra   map[string]extraRaw // GRPCRoutes and TLSRoutes by status key
	stale   map[string]extraRaw // routes that no longer attach to us but still carry our status
	addrs   []GatewayAddress    // Gateway status.addresses, from the install Service
	svcRaw  json.RawMessage     // that Service, for --expose-gateway-ports
	gwPorts []int               // spec ports of the listeners we serve

	kubeCtl
}

// NewKubeSource builds a source for the API at base.
func NewKubeSource(base string, hc *http.Client, token func() string, diag io.Writer) *KubeSource {
	return &KubeSource{base: strings.TrimRight(base, "/"), hc: hc, token: token, diag: diag}
}

type apiError struct {
	Status int
	Path   string
	Body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("kubernetes API %s: %d %s", e.Path, e.Status, strings.TrimSpace(e.Body))
}

func (k *KubeSource) do(ctx context.Context, method, path string, body []byte, ctype string) ([]byte, error) {
	if method == http.MethodGet {
		k.refs.note(path)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if tok := k.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := k.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode >= 300 {
		return nil, &apiError{Status: resp.StatusCode, Path: path, Body: string(b)}
	}
	return b, nil
}

func (k *KubeSource) list(ctx context.Context, path string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	cont := ""
	for {
		p := path + "?limit=500"
		if cont != "" {
			p += "&continue=" + url.QueryEscape(cont)
		}
		b, err := k.do(ctx, http.MethodGet, p, nil, "")
		if err != nil {
			return nil, err
		}
		var page struct {
			Items    []json.RawMessage `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(b, &page); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, page.Items...)
		if cont = page.Metadata.Continue; cont == "" {
			return all, nil
		}
	}
}

type meta struct {
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	Generation        int64             `json:"generation"`
	CreationTimestamp string            `json:"creationTimestamp"`
	Labels            map[string]string `json:"labels"`
	Annotations       map[string]string `json:"annotations"`
}

type kobj struct {
	Metadata meta            `json:"metadata"`
	Spec     json.RawMessage `json:"spec"`
	Status   json.RawMessage `json:"status"`
	Data     map[string]string
}

func decode(items []json.RawMessage) ([]kobj, error) {
	out := make([]kobj, 0, len(items))
	for _, it := range items {
		var o kobj
		if err := json.Unmarshal(it, &o); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

func (k *KubeSource) warn(format string, a ...any) {
	if k.diag != nil {
		fmt.Fprintf(k.diag, format+"\n", a...)
	}
}

// Load implements Source.
func (k *KubeSource) Load(ctx context.Context) (*Loaded, error) {
	k.refs.begin()
	classItems, err := k.list(ctx, apiGatewayV1+"/gatewayclasses")
	if err != nil {
		return nil, err
	}
	classes, _ := decode(classItems)
	ours := map[string]json.RawMessage{}
	for i, c := range classes {
		var spec struct {
			ControllerName string `json:"controllerName"`
		}
		json.Unmarshal(c.Spec, &spec)
		if spec.ControllerName == ControllerName {
			ours[c.Metadata.Name] = classItems[i]
		}
	}
	gwItems, err := k.list(ctx, apiGatewayV1+"/gateways")
	if err != nil {
		return nil, err
	}
	rtItems, err := k.list(ctx, apiGatewayV1+"/httproutes")
	if err != nil {
		return nil, err
	}
	svcItems, err := k.list(ctx, "/api/v1/services")
	if err != nil {
		return nil, err
	}
	sliceItems, err := k.list(ctx, "/apis/discovery.k8s.io/v1/endpointslices")
	if err != nil {
		return nil, err
	}

	cfg := &Config{Namespace: "", Backends: map[string]*BackendDef{}, Secrets: map[string]SecretDef{}, Namespaces: map[string]map[string]string{}}
	gws, _ := decode(gwItems)
	gwRaw, rtRaw := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	mine := map[string]bool{}
	for i, g := range gws {
		var spec gatewaySpec
		if err := json.Unmarshal(g.Spec, &spec); err != nil {
			k.warn("skipping Gateway %s/%s: %v", g.Metadata.Namespace, g.Metadata.Name, err)
			continue
		}
		if _, ok := ours[spec.GatewayClassName]; !ok {
			continue
		}
		gw := spec.gateway(g.Metadata.Namespace, g.Metadata.Name, g.Metadata.Generation)
		gw.Annotations = g.Metadata.Annotations
		cfg.Gateways = append(cfg.Gateways, gw)
		mine[gw.Key()] = true
		gwRaw[gw.Key()] = gwItems[i]
	}
	stale := map[string]extraRaw{}
	gw15 := map[string]extraRaw{}
	if err := k.loadListenerSets(ctx, cfg, mine, gw15); err != nil {
		return nil, err
	}
	rts, _ := decode(rtItems)
	for i, r := range rts {
		var spec routeSpec
		if err := json.Unmarshal(r.Spec, &spec); err != nil {
			k.warn("skipping HTTPRoute %s/%s: %v", r.Metadata.Namespace, r.Metadata.Name, err)
			continue
		}
		var parents []ParentRef // only the parentRefs that name our Gateways are ours to judge
		for _, p := range spec.ParentRefs {
			if ourParent(mine, p, r.Metadata.Namespace) {
				parents = append(parents, p)
			}
		}
		if len(parents) == 0 {
			noteStale(stale, apiGatewayV1, "httproutes", "httproute", r, rtItems[i])
			continue
		}
		created, _ := time.Parse(time.RFC3339, r.Metadata.CreationTimestamp)
		cfg.Routes = append(cfg.Routes, &Route{NS: r.Metadata.Namespace, Name: r.Metadata.Name, Generation: r.Metadata.Generation,
			Created: created, Parents: parents, Hostnames: spec.Hostnames, Rules: spec.Rules})
		k.shadowAnnotations("HTTPRoute", r.Metadata, len(spec.Rules), func() {
			annotateHTTP(spec.Rules, r.Metadata.Annotations)
			annotateAuth(spec.Rules, r.Metadata.Annotations)
			annotateExt(spec.Rules, r.Metadata.Annotations)
			annotateFault(spec.Rules, r.Metadata.Annotations)
			annotateContract(spec.Rules, r.Metadata.Annotations)
			annotateAI(spec.Rules, r.Metadata.Annotations)
			annotateLB(spec.Rules, r.Metadata.Annotations)
		})
		cfg.annotateBackends(r.Metadata.Namespace, spec.Rules, r.Metadata.Annotations)
		for _, key := range OrphanRuleAnnotations(r.Metadata.Annotations, LoadBalancerKey, len(spec.Rules)) {
			k.warn("HTTPRoute %s/%s: annotation %s matches no rule (want %s.rule-N with N from 1 to %d)", r.Metadata.Namespace, r.Metadata.Name, key, LoadBalancerKey, len(spec.Rules))
		}
		for _, base := range RuleExtKeys {
			for _, key := range OrphanRuleAnnotations(r.Metadata.Annotations, base, len(spec.Rules)) {
				k.warn("HTTPRoute %s/%s: annotation %s matches no rule (want %s.rule-N with N from 1 to %d)", r.Metadata.Namespace, r.Metadata.Name, key, base, len(spec.Rules))
			}
		}
		rtRaw[cfg.Routes[len(cfg.Routes)-1].Key()] = rtItems[i]
	}

	extra, err := k.loadExtraRoutes(ctx, cfg, mine, stale)
	if err != nil {
		return nil, err
	}
	if err := k.loadL4Routes(ctx, cfg, mine, stale, extra); err != nil {
		return nil, err
	}
	if err := k.loadBackendTLS(ctx, cfg, gw15); err != nil {
		return nil, err
	}
	for key, x := range gw15 {
		extra[key] = x
	}

	// Services and ready endpoints become backends.
	slices, _ := decode(sliceItems)
	type slice struct {
		Endpoints []struct {
			Addresses  []string `json:"addresses"`
			Conditions struct {
				Ready *bool `json:"ready"`
			} `json:"conditions"`
			Zone string `json:"zone"` // topology.kubernetes.io/zone, for locality aware load balancing
		} `json:"endpoints"`
		Ports []struct {
			Name *string `json:"name"`
			Port int     `json:"port"`
		} `json:"ports"`
	}
	svcSlices := map[string][]json.RawMessage{}
	for i, s := range slices {
		if name := s.Metadata.Labels["kubernetes.io/service-name"]; name != "" {
			svcSlices[s.Metadata.Namespace+"/"+name] = append(svcSlices[s.Metadata.Namespace+"/"+name], sliceItems[i])
		}
	}
	svcs, _ := decode(svcItems)
	for _, s := range svcs {
		var spec struct {
			Type         string `json:"type"`
			ExternalName string `json:"externalName"`
			Ports        []struct {
				Name        string  `json:"name"`
				Port        int     `json:"port"`
				AppProtocol *string `json:"appProtocol"`
			} `json:"ports"`
		}
		if json.Unmarshal(s.Spec, &spec) != nil {
			continue
		}
		key := s.Metadata.Namespace + "/" + s.Metadata.Name
		for _, sp := range spec.Ports {
			def := &BackendDef{PortName: sp.Name}
			kubeBackendProtocol(def, sp.AppProtocol, s.Metadata.Annotations)
			if v := s.Metadata.Annotations[LoadBalancerKey]; v != "" {
				if lb, err := ParseLBBlock([]byte(v)); err != nil {
					k.warn("Service %s: annotation %s: %v", key, LoadBalancerKey, err)
				} else {
					def.LoadBalancer = lb
				}
			}
			if spec.Type == "ExternalName" && spec.ExternalName != "" {
				def.Endpoints = []string{net.JoinHostPort(spec.ExternalName, fmt.Sprint(sp.Port))}
				def.DNS = &DNSDef{Enabled: true} // the gateway resolves the external name and honours its TTL
			}
			for _, raw := range svcSlices[key] {
				var sl slice
				if json.Unmarshal(raw, &sl) != nil {
					continue
				}
				port := 0
				for _, p := range sl.Ports {
					if (p.Name == nil && sp.Name == "") || (p.Name != nil && *p.Name == sp.Name) {
						port = p.Port
					}
				}
				if port == 0 {
					continue
				}
				for _, e := range sl.Endpoints {
					if e.Conditions.Ready != nil && !*e.Conditions.Ready {
						continue
					}
					for _, a := range e.Addresses {
						addr := net.JoinHostPort(a, fmt.Sprint(port))
						def.Endpoints = append(def.Endpoints, addr)
						if e.Zone != "" {
							if def.EndpointMeta == nil {
								def.EndpointMeta = map[string]EndpointDef{}
							}
							def.EndpointMeta[addr] = EndpointDef{Address: addr, Zone: e.Zone}
						}
					}
				}
			}
			sort.Strings(def.Endpoints)
			cfg.Backends[backendKey(s.Metadata.Namespace, s.Metadata.Name, sp.Port)] = def
		}
	}

	addrs, svcRaw := k.gatewayAddresses(svcs, svcItems)
	gwPorts := listenerPorts(cfg)

	// Referenced TLS Secrets, fetched one by one so RBAC needs only "get".
	for _, gw := range cfg.Gateways {
		for _, l := range gw.Listeners {
			if l.TLS == nil {
				continue
			}
			for _, ref := range l.TLS.CertificateRefs {
				ns := ref.Namespace
				if ns == "" {
					ns = gw.NS
				}
				skey := ns + "/" + ref.Name
				if _, done := cfg.Secrets[skey]; done {
					continue
				}
				b, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(ns)+"/secrets/"+url.PathEscape(ref.Name), nil, "")
				if err != nil {
					k.warn("secret %s: %v", skey, err)
					continue
				}
				var sec kobj
				json.Unmarshal(b, &sec)
				crt, _ := base64.StdEncoding.DecodeString(sec.Data["tls.crt"])
				key, _ := base64.StdEncoding.DecodeString(sec.Data["tls.key"])
				cfg.Secrets[skey] = SecretDef{Cert: string(crt), Key: string(key)}
			}
		}
	}

	k.loadAIKeys(ctx, cfg)
	k.loadClientCAs(ctx, cfg)

	// ReferenceGrants and namespace labels are optional extras: a 403 or 404
	// simply means "none".
	if items, err := k.list(ctx, "/apis/gateway.networking.k8s.io/v1beta1/referencegrants"); err == nil {
		cfg.GrantsCaptured = true
		gs, _ := decode(items)
		for _, g := range gs {
			var spec struct {
				From []struct{ Group, Kind, Namespace string } `json:"from"`
				To   []struct{ Group, Kind, Name string }      `json:"to"`
			}
			if json.Unmarshal(g.Spec, &spec) == nil {
				cfg.Grants = append(cfg.Grants, Grant{Namespace: g.Metadata.Namespace, From: spec.From, To: spec.To})
			}
		}
	}
	if items, err := k.list(ctx, "/api/v1/namespaces"); err == nil {
		ns, _ := decode(items)
		for _, n := range ns {
			cfg.Namespaces[n.Metadata.Name] = n.Metadata.Labels
		}
	}

	k.mu.Lock()
	k.classes, k.gwRaw, k.rtRaw, k.extra = ours, gwRaw, rtRaw, extra
	k.stale, k.addrs, k.svcRaw, k.gwPorts = stale, addrs, svcRaw, gwPorts
	k.mu.Unlock()
	sig, _ := json.Marshal(struct {
		G []*Gateway
		R []*Route
		B map[string]*BackendDef
		S map[string]SecretDef
		P []Grant
		N map[string]map[string]string
		X []*GRPCRoute
		T []*TLSRoute
		Y []any
	}{cfg.Gateways, cfg.Routes, cfg.Backends, cfg.Secrets, cfg.Grants, cfg.Namespaces, cfg.GRPCRoutes, cfg.TLSRoutes,
		[]any{cfg.ListenerSets, cfg.TCPRoutes, cfg.UDPRoutes, cfg.BackendTLS, cfg.CACerts, cfg.AIKeys}})
	sum := sha256.Sum256(sig)
	k.syncRefWatches()
	return &Loaded{Config: cfg, Hash: hex.EncodeToString(sum[:])}, nil
}

// normConds strips volatile fields so status comparisons ignore timestamps.
func normConds(cs []Condition) []Condition {
	out := make([]Condition, len(cs))
	for i, c := range cs {
		c.LastTransitionTime = ""
		out[i] = c
	}
	return out
}

func sameConds(a, b []Condition) bool {
	if len(a) != len(b) {
		return false
	}
	return reflect.DeepEqual(normConds(a), normConds(b))
}

func sameListeners(a, b []ListenerStatus) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].AttachedRoutes != b[i].AttachedRoutes || !sameConds(a[i].Conditions, b[i].Conditions) ||
			!reflect.DeepEqual(append([]KindRef{}, a[i].SupportedKinds...), append([]KindRef{}, b[i].SupportedKinds...)) {
			return false
		}
	}
	return true
}

func (k *KubeSource) patchStatus(ctx context.Context, path string, status any) error {
	body, err := json.Marshal(map[string]any{"status": status})
	if err != nil {
		return err
	}
	_, err = k.do(ctx, http.MethodPatch, path+"/status", body, "application/merge-patch+json")
	return err
}

// WriteStatus implements StatusWriter. It patches only what differs from the
// objects seen by the latest Load, so a converged cluster sees no writes.
func (k *KubeSource) WriteStatus(ctx context.Context, doc *StatusDoc) error {
	if doc == nil || !k.isLeader() {
		return nil // followers serve traffic but never write
	}
	k.mu.Lock()
	classes, gwRaw, rtRaw, extra := k.classes, k.gwRaw, k.rtRaw, k.extra
	stale, addrs := k.stale, k.addrs
	k.mu.Unlock()
	var errs []error
	now := time.Now().UTC().Format(time.RFC3339)

	for name, raw := range classes {
		var o kobj
		json.Unmarshal(raw, &o)
		var st struct {
			Conditions []Condition `json:"conditions"`
		}
		json.Unmarshal(o.Status, &st)
		want := []Condition{{Type: "Accepted", Status: "True", Reason: "Accepted", Message: "controller " + ControllerName,
			ObservedGeneration: o.Metadata.Generation, LastTransitionTime: now}}
		if len(st.Conditions) > 0 && st.Conditions[0].Status == "True" {
			want[0].LastTransitionTime = st.Conditions[0].LastTransitionTime
		}
		if !sameConds(st.Conditions, want) {
			if err := k.patchStatus(ctx, apiGatewayV1+"/gatewayclasses/"+url.PathEscape(name), map[string]any{"conditions": want}); err != nil {
				errs = append(errs, err)
			}
		}
	}
	for key, raw := range gwRaw {
		want := doc.Gateways[key]
		if want == nil {
			continue
		}
		var o kobj
		json.Unmarshal(raw, &o)
		var st struct {
			Conditions           []Condition      `json:"conditions"`
			Listeners            []ListenerStatus `json:"listeners"`
			Addresses            []GatewayAddress `json:"addresses"`
			AttachedListenerSets *int             `json:"attachedListenerSets"`
		}
		json.Unmarshal(o.Status, &st)
		gwAddrs := addrs // static spec.addresses win over the Service's
		if len(want.Addresses) > 0 {
			gwAddrs = want.Addresses
		}
		withAddrs := len(gwAddrs) > 0 && !reflect.DeepEqual(st.Addresses, gwAddrs)
		attachedSets := want.AttachedListenerSets != nil && (st.AttachedListenerSets == nil || *st.AttachedListenerSets != *want.AttachedListenerSets)
		if sameConds(st.Conditions, want.Conditions) && sameListeners(st.Listeners, want.Listeners) && !withAddrs && !attachedSets {
			continue
		}
		path := apiGatewayV1 + "/namespaces/" + url.PathEscape(o.Metadata.Namespace) + "/gateways/" + url.PathEscape(o.Metadata.Name)
		body := map[string]any{"conditions": want.Conditions, "listeners": want.Listeners}
		if len(gwAddrs) > 0 {
			body["addresses"] = gwAddrs
		}
		if want.AttachedListenerSets != nil {
			body["attachedListenerSets"] = *want.AttachedListenerSets
		}
		if err := k.patchStatus(ctx, path, body); err != nil {
			errs = append(errs, err)
		}
	}
	for key, raw := range rtRaw {
		if err := k.writeRouteStatus(ctx, apiGatewayV1, "httproutes", raw, doc.Routes[key]); err != nil {
			errs = append(errs, err)
		}
	}
	for key, x := range extra {
		if err := k.writeRouteStatus(ctx, x.base, x.plural, x.raw, doc.Routes[key]); err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, k.writeGw15Status(ctx, doc, extra)...)
	for _, x := range stale { // detached routes: drop our entries, keep other controllers'
		if err := k.writeRouteStatus(ctx, x.base, x.plural, x.raw, &RouteStatus{}); err != nil {
			errs = append(errs, err)
		}
	}
	if err := k.reconcileServicePorts(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// writeRouteStatus patches one route's status.parents when it differs from
// what the latest Load saw.
func (k *KubeSource) writeRouteStatus(ctx context.Context, base, plural string, raw json.RawMessage, want *RouteStatus) error {
	if want == nil {
		return nil
	}
	var o kobj
	json.Unmarshal(raw, &o)
	var st struct {
		Parents []ParentStatus `json:"parents"`
	}
	json.Unmarshal(o.Status, &st)
	var others, mine []ParentStatus
	for _, p := range st.Parents {
		if p.ControllerName == ControllerName {
			mine = append(mine, p)
		} else {
			others = append(others, p)
		}
	}
	same := len(mine) == len(want.Parents)
	for i := 0; same && i < len(mine); i++ {
		same = reflect.DeepEqual(mine[i].ParentRef, want.Parents[i].ParentRef) && sameConds(mine[i].Conditions, want.Parents[i].Conditions)
	}
	if same {
		return nil
	}
	path := base + "/namespaces/" + url.PathEscape(o.Metadata.Namespace) + "/" + plural + "/" + url.PathEscape(o.Metadata.Name)
	// A merge patch replaces arrays wholesale, so keep other controllers' entries.
	return k.patchStatus(ctx, path, map[string]any{"parents": append(append([]ParentStatus{}, others...), want.Parents...)})
}
