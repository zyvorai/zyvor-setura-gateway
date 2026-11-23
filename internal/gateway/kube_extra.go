package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// extraRaw is a GRPCRoute or TLSRoute as read from the API, kept for status writes.
type extraRaw struct {
	base, plural string
	raw          json.RawMessage
}

// listOptional lists a CRD collection under each candidate API version in
// turn. A missing CRD (404) or a denied list (403) simply yields no objects.
func (k *KubeSource) listOptional(ctx context.Context, group string, versions []string, plural string) (items []json.RawMessage, base string, err error) {
	for _, v := range versions {
		base = "/apis/" + group + "/" + v
		items, err = k.list(ctx, base+"/"+plural)
		var ae *apiError
		if err == nil {
			return items, base, nil
		}
		if !errors.As(err, &ae) || (ae.Status != http.StatusNotFound && ae.Status != http.StatusForbidden) {
			return nil, "", err
		}
		if ae.Status == http.StatusForbidden {
			k.warn("cannot list %s: %v", plural, err)
			return nil, "", nil
		}
	}
	return nil, "", nil
}

// loadExtraRoutes reads GRPCRoutes and TLSRoutes that attach to our Gateways.
func (k *KubeSource) loadExtraRoutes(ctx context.Context, cfg *Config, mine map[string]bool, stale map[string]extraRaw) (map[string]extraRaw, error) {
	extra := map[string]extraRaw{}
	ours := func(ns string, refs []ParentRef) []ParentRef {
		var out []ParentRef
		for _, p := range refs {
			if ourParent(mine, p, ns) {
				out = append(out, p)
			}
		}
		return out
	}

	items, base, err := k.listOptional(ctx, APIGroup, []string{"v1"}, "grpcroutes")
	if err != nil {
		return nil, err
	}
	objs, _ := decode(items)
	for i, o := range objs {
		var spec grpcRouteSpec
		if err := json.Unmarshal(o.Spec, &spec); err != nil {
			k.warn("skipping GRPCRoute %s/%s: %v", o.Metadata.Namespace, o.Metadata.Name, err)
			continue
		}
		parents := ours(o.Metadata.Namespace, spec.ParentRefs)
		if len(parents) == 0 {
			noteStale(stale, base, "grpcroutes", "grpcroute", o, items[i])
			continue
		}
		created, _ := time.Parse(time.RFC3339, o.Metadata.CreationTimestamp)
		r := &GRPCRoute{NS: o.Metadata.Namespace, Name: o.Metadata.Name, Generation: o.Metadata.Generation, Created: created,
			Parents: parents, Hostnames: spec.Hostnames, Rules: spec.Rules}
		k.shadowAnnotations("GRPCRoute", o.Metadata, len(spec.Rules), func() {
			annotateGRPC(r.Rules, o.Metadata.Annotations)
			annotateAuthGRPC(r.Rules, o.Metadata.Annotations)
		})
		cfg.GRPCRoutes = append(cfg.GRPCRoutes, r)
		extra[r.stub().StatusKey()] = extraRaw{base: base, plural: "grpcroutes", raw: items[i]}
	}

	items, base, err = k.listOptional(ctx, APIGroup, []string{"v1", "v1alpha3", "v1alpha2"}, "tlsroutes")
	if err != nil {
		return nil, err
	}
	objs, _ = decode(items)
	for i, o := range objs {
		var spec tlsRouteSpec
		if err := json.Unmarshal(o.Spec, &spec); err != nil {
			k.warn("skipping TLSRoute %s/%s: %v", o.Metadata.Namespace, o.Metadata.Name, err)
			continue
		}
		parents := ours(o.Metadata.Namespace, spec.ParentRefs)
		if len(parents) == 0 {
			noteStale(stale, base, "tlsroutes", "tlsroute", o, items[i])
			continue
		}
		created, _ := time.Parse(time.RFC3339, o.Metadata.CreationTimestamp)
		r := &TLSRoute{NS: o.Metadata.Namespace, Name: o.Metadata.Name, Generation: o.Metadata.Generation, Created: created,
			Parents: parents, Hostnames: spec.Hostnames, Rules: spec.Rules}
		cfg.TLSRoutes = append(cfg.TLSRoutes, r)
		extra[r.stub().StatusKey()] = extraRaw{base: base, plural: "tlsroutes", raw: items[i]}
	}
	return extra, nil
}
