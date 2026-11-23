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

// The Kubernetes side of Envoy Gateway compatibility (--envoy-compat): list
// the optional gateway.envoyproxy.io CRDs, hand them to ApplyEnvoyCompat and
// write the outcome back to the policies' status.ancestors.

const envoyBase = "/apis/" + EnvoyGroup + "/" + EnvoyVersion

// envoyWatchTargets are watched next to watchTargets with --envoy-compat; the
// CRDs are optional.
var envoyWatchTargets = func() []struct {
	paths    []string
	optional bool
} {
	var out []struct {
		paths    []string
		optional bool
	}
	for _, k := range EnvoyKinds {
		out = append(out, struct {
			paths    []string
			optional bool
		}{[]string{envoyBase + "/" + k.Plural}, true})
	}
	return out
}()

// envoyStatusItem is a listed policy and what became of it.
type envoyStatusItem struct {
	plural  string
	raw     json.RawMessage
	outcome *EnvoyOutcome
}

func (k *KubeSource) envoyObjects(ctx context.Context, kind, plural string) ([]*EnvoyObject, []json.RawMessage, error) {
	items, _, err := k.listOptional(ctx, EnvoyGroup, []string{EnvoyVersion}, plural)
	if err != nil {
		return nil, nil, err
	}
	objs, _ := decode(items)
	var out []*EnvoyObject
	var raws []json.RawMessage
	for i, o := range objs {
		var spec map[string]any
		if err := json.Unmarshal(o.Spec, &spec); err != nil {
			k.warn("skipping %s %s/%s: %v", kind, o.Metadata.Namespace, o.Metadata.Name, err)
			continue
		}
		created, _ := time.Parse(time.RFC3339, o.Metadata.CreationTimestamp)
		out = append(out, &EnvoyObject{Kind: kind, NS: o.Metadata.Namespace, Name: o.Metadata.Name, Generation: o.Metadata.Generation,
			Created: created, Labels: o.Metadata.Labels, Annotations: o.Metadata.Annotations, Spec: spec})
		raws = append(raws, items[i])
	}
	return out, raws, nil
}

// loadEnvoyCompat reads the Envoy Gateway objects and applies them to cfg. It
// returns a digest of everything that shaped the result, for the config hash.
func (k *KubeSource) loadEnvoyCompat(ctx context.Context, cfg *Config) (string, error) {
	if !k.EnvoyCompat {
		return "", nil
	}
	var in EnvoyInput
	var raws []json.RawMessage
	var plurals []string
	for _, ek := range EnvoyKinds {
		objs, rs, err := k.envoyObjects(ctx, ek.Kind, ek.Plural)
		if err != nil {
			return "", err
		}
		switch ek.Kind {
		case "HTTPRouteFilter":
			in.Filters = objs
		case "Backend":
			in.Backends = objs
		default:
			in.Policies = append(in.Policies, objs...)
			raws = append(raws, rs...)
			for range rs {
				plurals = append(plurals, ek.Plural)
			}
		}
	}
	if len(in.Policies)+len(in.Filters)+len(in.Backends) == 0 {
		k.mu.Lock()
		k.envoyStatus = nil
		k.mu.Unlock()
		return "", nil
	}
	in.Secret = func(ns, name string) (map[string]string, bool) {
		b, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(ns)+"/secrets/"+url.PathEscape(name), nil, "")
		if err != nil {
			k.warn("secret %s/%s: %v", ns, name, err)
			return nil, false
		}
		var sec kobj
		json.Unmarshal(b, &sec)
		data := map[string]string{}
		for key, v := range sec.Data {
			if dec, err := base64.StdEncoding.DecodeString(v); err == nil {
				data[key] = string(dec)
			}
		}
		return data, true
	}
	res := ApplyEnvoyCompat(cfg, in)
	for _, w := range res.Warn {
		k.warn("%s", w)
	}
	items := make([]envoyStatusItem, 0, len(res.Outcomes))
	for _, out := range res.Outcomes {
		for i, p := range in.Policies {
			if p == out.Object {
				items = append(items, envoyStatusItem{plural: plurals[i], raw: raws[i], outcome: out})
			}
		}
	}
	k.mu.Lock()
	k.envoyStatus = items
	k.mu.Unlock()
	return res.Digest, nil
}

// writeEnvoyStatus patches status.ancestors of every policy whose conditions
// differ from what the latest Load computed; other controllers' ancestors stay.
func (k *KubeSource) writeEnvoyStatus(ctx context.Context) []error {
	k.mu.Lock()
	items := k.envoyStatus
	k.mu.Unlock()
	var errs []error
	now := time.Now().UTC()
	for _, it := range items {
		var o kobj
		json.Unmarshal(it.raw, &o)
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
		refs := it.outcome.Ancestors
		if len(refs) == 0 {
			refs = it.outcome.fallbackRefs()
		}
		var want []AncestorStatus
		for _, ref := range refs {
			var prev []Condition
			for _, m := range mine {
				if reflect.DeepEqual(m.AncestorRef, ref) {
					prev = m.Conditions
				}
			}
			want = append(want, AncestorStatus{AncestorRef: ref, ControllerName: ControllerName, Conditions: it.outcome.Conditions(now, prev)})
		}
		same := len(mine) == len(want)
		for i := 0; same && i < len(mine); i++ {
			same = reflect.DeepEqual(mine[i].AncestorRef, want[i].AncestorRef) && sameConds(mine[i].Conditions, want[i].Conditions)
		}
		if same {
			continue
		}
		path := envoyBase + "/namespaces/" + url.PathEscape(o.Metadata.Namespace) + "/" + it.plural + "/" + url.PathEscape(o.Metadata.Name)
		if err := k.patchStatus(ctx, path, map[string]any{"ancestors": append(append([]AncestorStatus{}, others...), want...)}); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// fallbackRefs names the policy's own targets as ancestors when it reaches no
// Gateway, so a TargetNotFound still has somewhere to be reported.
func (o *EnvoyOutcome) fallbackRefs() []ParentRef {
	p := newEnvoyPolicy(o.Object)
	var out []ParentRef
	for _, t := range p.targets {
		out = append(out, ParentRef{Group: APIGroup, Kind: t.Kind, Name: t.Name, Namespace: o.Object.NS, SectionName: t.Section})
	}
	if len(out) == 0 {
		out = append(out, ParentRef{Group: APIGroup, Kind: "Gateway", Name: "unknown", Namespace: o.Object.NS})
	}
	return out
}
