package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// compiledAI is an AIPolicy resolved against a routing table: provider
// secrets read, base URLs parsed, regexes compiled, and one Backend that holds
// an Endpoint per provider so health, outlier ejection and carry-over across
// reloads are the machinery every other backend uses.
type compiledAI struct {
	p     *AIPolicy
	key   string // route key and rule number: "ns/name/1"
	b     *Backend
	provs []*aiProv

	identKind, identName string
	pii                  *compiledPII
	cache                *aiCacheCfg
	maxBody              int64
	defMax               int
	inject               bool
	failStatus           map[int]bool
	maxAttempts          int
}

type aiProv struct {
	AIProvider
	typ     string
	base    *url.URL
	weight  int
	ep      *Endpoint
	key     *aiSecret
	header  string
	scheme  string
	timeout time.Duration
}

type aiCacheCfg struct {
	ttl                     time.Duration
	maxEntries              int
	maxEntryBytes, maxBytes int64
	stream, perIdentity     bool
	ignore                  []string
}

// serves reports whether the provider takes requests for model.
func (p *aiProv) serves(model string) bool {
	if len(p.Models) == 0 {
		return true
	}
	return modelMatches(p.Models, model)
}

// modelMatches matches model against exact names and trailing-* prefixes.
func modelMatches(patterns []string, model string) bool {
	for _, m := range patterns {
		if m == model || m == "*" || (strings.HasSuffix(m, "*") && strings.HasPrefix(model, strings.TrimSuffix(m, "*"))) {
			return true
		}
	}
	return false
}

// credential returns the header name and value that authenticate to the provider.
func (p *aiProv) credential() (name, value string) {
	if p.key == nil {
		return "", ""
	}
	k := p.key.get()
	if p.scheme != "" {
		k = p.scheme + " " + k
	}
	return p.header, k
}

// scrub removes any provider secret from text that may reach a log or a client.
func (c *compiledAI) scrub(s string) string {
	for _, p := range c.provs {
		if p.key == nil {
			continue
		}
		if v := p.key.get(); len(v) >= 8 {
			s = strings.ReplaceAll(s, v, redacted)
		}
	}
	return s
}

func (t *Table) aiGranted(r *Route, ns, name string) bool {
	return t.Cfg.granted("HTTPRoute", r.NS, "", "Secret", ns, name)
}

// compileAI resolves the policy of rule idx (0-based) of route r.
func (t *Table) compileAI(r *Route, idx int, p *AIPolicy) (*compiledAI, error) {
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", AIKey, err)
	}
	c := &compiledAI{p: p, key: r.Key() + "/" + strconv.Itoa(idx+1), maxBody: p.MaxRequestBytes, defMax: p.DefaultMaxTokens,
		inject: p.InjectStreamUsage == nil || *p.InjectStreamUsage, maxAttempts: len(p.Providers)}
	if c.maxBody <= 0 {
		c.maxBody = aiDefaultMaxBody
	}
	c.identKind, c.identName, _ = parseAIIdentity(p.Identity)
	if p.PII != nil {
		var err error
		if c.pii, err = compilePII(p.PII); err != nil {
			return nil, fmt.Errorf("%s: %w", AIKey, err)
		}
	}
	if ca := p.Cache; ca != nil && ca.Enabled {
		cfg := &aiCacheCfg{ttl: aiDefaultCacheTTL, maxEntries: ca.MaxEntries, maxEntryBytes: ca.MaxEntryBytes, maxBytes: ca.MaxBytes,
			stream: ca.Stream, perIdentity: ca.Scope != "route", ignore: ca.IgnoreFields}
		if ca.TTL != "" {
			cfg.ttl, _ = time.ParseDuration(ca.TTL)
		}
		if cfg.maxEntries <= 0 {
			cfg.maxEntries = aiDefaultCacheCount
		}
		if cfg.maxEntryBytes <= 0 {
			cfg.maxEntryBytes = aiDefaultCacheEntry
		}
		if cfg.maxBytes <= 0 {
			cfg.maxBytes = aiDefaultCacheBytes
		}
		if len(cfg.ignore) == 0 {
			cfg.ignore = []string{"user"}
		}
		c.cache = cfg
	}
	if f := p.Failover; f != nil {
		if f.MaxAttempts > 0 {
			c.maxAttempts = f.MaxAttempts
		}
		if len(f.Statuses) > 0 {
			c.failStatus = map[int]bool{}
			for _, s := range f.Statuses {
				c.failStatus[s] = true
			}
		}
	}
	b := &Backend{Key: "ai/" + c.key, Name: "ai/" + c.key, hmu: new(sync.Mutex), noProbe: true}
	for _, pr := range p.Providers {
		base, _ := parseAIBase(pr.BaseURL)
		ap := &aiProv{AIProvider: pr, typ: pr.Type, base: base, weight: 1, timeout: aiDefaultTimeout}
		if ap.typ == "" {
			ap.typ = "openai"
		}
		if pr.Weight != nil {
			ap.weight = *pr.Weight
		}
		if pr.Timeout != "" {
			ap.timeout, _ = time.ParseDuration(pr.Timeout)
		}
		// Endpoint identity (state carry-over across reloads) is the URL; the
		// fragment keeps two providers on one host apart. It is never dialled.
		ap.ep = &Endpoint{URL: &url.URL{Scheme: base.Scheme, Host: base.Host, Fragment: pr.Name}}
		ap.ep.healthy.Store(true)
		b.Eps = append(b.Eps, ap.ep)
		ap.header, ap.scheme = pr.AuthHeader, pr.AuthScheme
		if ap.header == "" {
			if ap.typ == "anthropic" {
				ap.header = "x-api-key"
			} else {
				ap.header = "Authorization"
				if ap.scheme == "" {
					ap.scheme = "Bearer"
				}
			}
		}
		if pr.APIKey != nil {
			sec, err := resolveAISecret(pr.APIKey, r.NS, t.Cfg.AIKeys, func(ns, name string) bool { return t.aiGranted(r, ns, name) })
			if err != nil {
				return nil, fmt.Errorf("%s: provider %s: %w", AIKey, pr.Name, err)
			}
			ap.key = sec
		}
		c.provs = append(c.provs, ap)
	}
	t.Backends[b.Key] = b
	t.noteUse(b)
	c.b = b
	return c, nil
}

// describe is the credential source of a provider, never the credential.
func (p *aiProv) describeKey() string {
	if p.key == nil {
		return "none (the provider is called without a credential)"
	}
	return p.key.desc
}

// loadAIKeys reads the Secret keys the AI providers of the routes name, one
// Secret at a time so RBAC needs only "get". A Secret that cannot be read is
// left out: the route that needs it turns invalid with a clear message.
func (k *KubeSource) loadAIKeys(ctx context.Context, cfg *Config) {
	cfg.AIKeys = map[string]string{}
	fetched := map[string]map[string]string{}
	load := func(ownerNS string, ref *AISecretKeyRef, what string) {
		ns := ref.Namespace
		if ns == "" {
			ns = ownerNS
		}
		id := ns + "/" + ref.Name
		data, done := fetched[id]
		if !done {
			b, err := k.do(ctx, http.MethodGet, "/api/v1/namespaces/"+url.PathEscape(ns)+"/secrets/"+url.PathEscape(ref.Name), nil, "")
			if err != nil {
				k.warn("%s secret %s: %v", what, id, err)
			} else {
				var sec kobj
				if json.Unmarshal(b, &sec) == nil {
					data = sec.Data
				}
			}
			fetched[id] = data
		}
		if v, err := base64.StdEncoding.DecodeString(data[ref.Key]); err == nil && len(v) > 0 {
			cfg.AIKeys[id+"#"+ref.Key] = string(v)
		}
	}
	for _, r := range cfg.Routes {
		for i := range r.Rules {
			if p := r.Rules[i].AI; p.active() {
				for _, pr := range p.Providers {
					if pr.APIKey != nil && pr.APIKey.Secret != nil {
						load(r.NS, pr.APIKey.Secret, "AI provider")
					}
				}
			}
			// auth policy secrets (OIDC client secret and cookie keys, injected credentials)
			for _, ref := range authSecretRefs(r.Rules[i].Auth) {
				load(r.NS, ref, "auth policy")
			}
		}
	}
	for _, r := range cfg.GRPCRoutes {
		for i := range r.Rules {
			for _, ref := range authSecretRefs(r.Rules[i].Auth) {
				load(r.NS, ref, "auth policy")
			}
		}
	}
}
