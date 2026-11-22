package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"time"
)

// The Kubernetes source for the Gateway API 1.5 kinds: ListenerSets,
// TCPRoutes, UDPRoutes and BackendTLSPolicies, plus the ConfigMaps and
// Secrets those policies and Gateways reference.

// ourParent reports whether a parentRef names one of our Gateways, or a
// ListenerSet attached to one (mine holds "ns/name" for Gateways and
// "ListenerSet/ns/name" for their ListenerSets).
func ourParent(mine map[string]bool, p ParentRef, routeNS string) bool {
	if p.Group != "" && p.Group != APIGroup {
		return false
	}
	switch p.Kind {
	case "", "Gateway":
		return mine[parentNS(p, routeNS)+"/"+p.Name]
	case "ListenerSet":
		return mine["ListenerSet/"+parentNS(p, routeNS)+"/"+p.Name]
	}
	return false
}

// loadListenerSets reads the ListenerSets whose parent is one of our Gateways
// and marks them in mine so routes attached through them are ours too.
func (k *KubeSource) loadListenerSets(ctx context.Context, cfg *Config, mine map[string]bool, extra map[string]extraRaw) error {
	items, base, err := k.listOptional(ctx, APIGroup, []string{"v1"}, "listenersets")
	if err != nil {
		return err
	}
	objs, _ := decode(items)
	for i, o := range objs {
		var spec listenerSetSpec
		if err := json.Unmarshal(o.Spec, &spec); err != nil {
			k.warn("skipping ListenerSet %s/%s: %v", o.Metadata.Namespace, o.Metadata.Name, err)
			continue
		}
		if !ourParent(mine, spec.ParentRef, o.Metadata.Namespace) {
			continue
		}
		created, _ := time.Parse(time.RFC3339, o.Metadata.CreationTimestamp)
		ls := &ListenerSet{NS: o.Metadata.Namespace, Name: o.Metadata.Name, Generation: o.Metadata.Generation, Created: created, Parent: spec.ParentRef, Listeners: spec.Listeners}
		cfg.ListenerSets = append(cfg.ListenerSets, ls)
		mine["ListenerSet/"+ls.Key()] = true
		extra["ListenerSet/"+ls.Key()] = extraRaw{base: base, plural: "listenersets", raw: items[i]}
		for _, l := range spec.Listeners { // certificateRefs of the set's listeners
			if l.TLS != nil {
				for _, ref := range l.TLS.CertificateRefs {
					ns := ref.Namespace
					if ns == "" {
						ns = ls.NS
					}
					k.fetchSecret(ctx, cfg, ns, ref.Name)
				}
			}
		}
	}
	return nil
}

// loadL4Routes reads TCPRoutes and UDPRoutes that attach to us.
func (k *KubeSource) loadL4Routes(ctx context.Context, cfg *Config, mine map[string]bool, stale, extra map[string]extraRaw) error {
	for _, kind := range []struct{ plural, kindName string }{{"tcproutes", "TCPRoute"}, {"udproutes", "UDPRoute"}} {
		items, base, err := k.listOptional(ctx, APIGroup, []string{"v1", "v1alpha2"}, kind.plural)
		if err != nil {
			return err
		}
		objs, _ := decode(items)
		for i, o := range objs {
			var spec l4Spec
			if err := json.Unmarshal(o.Spec, &spec); err != nil {
				k.warn("skipping %s %s/%s: %v", kind.kindName, o.Metadata.Namespace, o.Metadata.Name, err)
				continue
			}
			var parents []ParentRef
			for _, p := range spec.ParentRefs {
				if ourParent(mine, p, o.Metadata.Namespace) {
					parents = append(parents, p)
				}
			}
			if len(parents) == 0 {
				noteStale(stale, base, kind.plural, kind.kindName, o, items[i])
				continue
			}
			created, _ := time.Parse(time.RFC3339, o.Metadata.CreationTimestamp)
			r := &L4Route{Kind: kind.kindName, NS: o.Metadata.Namespace, Name: o.Metadata.Name, Generation: o.Metadata.Generation, Created: created, Parents: parents, Rules: spec.Rules}
			if kind.kindName == "TCPRoute" {
				cfg.TCPRoutes = append(cfg.TCPRoutes, r)
			} else {
				cfg.UDPRoutes = append(cfg.UDPRoutes, r)
			}
			extra[r.stub().StatusKey()] = extraRaw{base: base, plural: kind.plural, raw: items[i]}
		}
	}
	return nil
}

// loadBackendTLS reads BackendTLSPolicies and the CA bundles and client
// certificates they and our Gateways reference.
func (k *KubeSource) loadBackendTLS(ctx context.Context, cfg *Config, extra map[string]extraRaw) error {
	if cfg.CACerts == nil {
		cfg.CACerts = map[string]CADef{}
	}
	items, base, err := k.listOptional(ctx, APIGroup, []string{"v1", "v1alpha3"}, "backendtlspolicies")
	if err != nil {
		return err
	}
	objs, _ := decode(items)
	for i, o := range objs {
		var spec backendTLSSpec
		if err := json.Unmarshal(o.Spec, &spec); err != nil {
			k.warn("skipping BackendTLSPolicy %s/%s: %v", o.Metadata.Namespace, o.Metadata.Name, err)
			continue
		}
		created, _ := time.Parse(time.RFC3339, o.Metadata.CreationTimestamp)
		p := &BackendTLSPolicy{NS: o.Metadata.Namespace, Name: o.Metadata.Name, Generation: o.Metadata.Generation, Created: created,
			Targets: spec.TargetRefs, Validation: spec.Validation, Options: spec.Options}
		cfg.BackendTLS = append(cfg.BackendTLS, p)
		extra["BackendTLSPolicy/"+p.Key()] = extraRaw{base: base, plural: "backendtlspolicies", raw: items[i]}
		for _, ref := range spec.Validation.CACertificateRefs {
			if ref.Group != "" && ref.Group != "core" {
				continue
			}
			key := p.NS + "/" + ref.Name
			if _, done := cfg.CACerts[key]; done {
				continue
			}
			switch ref.Kind {
			case "ConfigMap":
				if b, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(p.NS)+"/configmaps/"+url.PathEscape(ref.Name), nil, ""); err == nil {
					var cm kobj
					json.Unmarshal(b, &cm)
					if pem := cm.Data["ca.crt"]; pem != "" {
						cfg.CACerts[key] = CADef{PEM: pem}
					}
				} else {
					k.warn("configmap %s: %v", key, err)
				}
			case "Secret":
				if b, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(p.NS)+"/secrets/"+url.PathEscape(ref.Name), nil, ""); err == nil {
					var sec kobj
					json.Unmarshal(b, &sec)
					if pem, err := base64.StdEncoding.DecodeString(sec.Data["ca.crt"]); err == nil && len(pem) > 0 {
						cfg.CACerts[key] = CADef{PEM: string(pem)}
					}
				} else {
					k.warn("secret %s: %v", key, err)
				}
			}
		}
	}
	for _, gw := range cfg.Gateways { // spec.tls.backend.clientCertificateRef
		if gw.BackendClientCert != nil {
			ns := gw.BackendClientCert.Namespace
			if ns == "" {
				ns = gw.NS
			}
			k.fetchSecret(ctx, cfg, ns, gw.BackendClientCert.Name)
		}
	}
	return nil
}

// fetchSecret reads a kubernetes.io/tls Secret into cfg.Secrets, once.
func (k *KubeSource) fetchSecret(ctx context.Context, cfg *Config, ns, name string) {
	skey := ns + "/" + name
	if _, done := cfg.Secrets[skey]; done {
		return
	}
	b, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(ns)+"/secrets/"+url.PathEscape(name), nil, "")
	if err != nil {
		k.warn("secret %s: %v", skey, err)
		return
	}
	var sec kobj
	json.Unmarshal(b, &sec)
	crt, _ := base64.StdEncoding.DecodeString(sec.Data["tls.crt"])
	key, _ := base64.StdEncoding.DecodeString(sec.Data["tls.key"])
	cfg.Secrets[skey] = SecretDef{Cert: string(crt), Key: string(key)}
}

// writeGw15Status writes the status of ListenerSets and BackendTLSPolicies.
func (k *KubeSource) writeGw15Status(ctx context.Context, doc *StatusDoc, extra map[string]extraRaw) []error {
	var errs []error
	for key, x := range extra {
		var o kobj
		json.Unmarshal(x.raw, &o)
		path := x.base + "/namespaces/" + url.PathEscape(o.Metadata.Namespace) + "/" + x.plural + "/" + url.PathEscape(o.Metadata.Name)
		switch x.plural {
		case "listenersets":
			want := doc.ListenerSets[o.Metadata.Namespace+"/"+o.Metadata.Name]
			if want == nil {
				continue
			}
			var st struct {
				Conditions []Condition      `json:"conditions"`
				Listeners  []ListenerStatus `json:"listeners"`
			}
			json.Unmarshal(o.Status, &st)
			if sameConds(st.Conditions, want.Conditions) && sameListeners(st.Listeners, want.Listeners) {
				continue
			}
			if err := k.patchStatus(ctx, path, map[string]any{"conditions": want.Conditions, "listeners": want.Listeners}); err != nil {
				errs = append(errs, err)
			}
		case "backendtlspolicies":
			want := doc.Policies[o.Metadata.Namespace+"/"+o.Metadata.Name]
			if want == nil {
				continue
			}
			var st struct {
				Ancestors []AncestorStatus `json:"ancestors"`
			}
			json.Unmarshal(o.Status, &st)
			var others, mine []AncestorStatus
			for _, a := range st.Ancestors {
				if a.ControllerName == ControllerName {
					mine = append(mine, a)
				} else {
					others = append(others, a)
				}
			}
			same := len(mine) == len(want.Ancestors)
			for i := 0; same && i < len(mine); i++ {
				same = reflect.DeepEqual(mine[i].AncestorRef, want.Ancestors[i].AncestorRef) && sameConds(mine[i].Conditions, want.Ancestors[i].Conditions)
			}
			if same {
				continue
			}
			// A merge patch replaces arrays wholesale, so keep other controllers' ancestors.
			if err := k.patchStatus(ctx, path, map[string]any{"ancestors": append(append([]AncestorStatus{}, others...), want.Ancestors...)}); err != nil {
				errs = append(errs, err)
			}
		}
		_ = key
	}
	return errs
}
