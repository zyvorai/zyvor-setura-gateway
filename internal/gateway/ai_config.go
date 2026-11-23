package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AIKey is the extension field of a rule, and the route annotation
// (setura.zyvor.dev/ai, setura.zyvor.dev/ai.rule-N), that turn the rule into
// an AI gateway route. See docs/ai-gateway.md.
const AIKey = "setura.zyvor.dev/ai"

// Response and request headers of AI routes.
const (
	AICacheHeader    = "X-Setura-Cache"
	AIProviderHeader = "X-Setura-Provider"
)

// AIPolicy is the AI gateway policy of one rule. A rule with an AI policy does
// not use backendRefs: its upstreams are the providers.
type AIPolicy struct {
	// Enabled false switches the policy off (the rule then needs backendRefs).
	Enabled   *bool        `json:"enabled,omitempty"`
	Providers []AIProvider `json:"providers"`
	// Failover tunes retries on another provider.
	Failover *AIFailover `json:"failover,omitempty"`
	// Identity says who a request belongs to, for budgets, the cache scope and
	// the per-key counters: "apikey" (name of the API key that matched),
	// "subject" (the verified subject of any credential, the default),
	// "claim:NAME" (a JWT claim) or "header:NAME" (a request header, as
	// trustworthy as whoever sets it).
	Identity string    `json:"identity,omitempty"`
	Budget   *AIBudget `json:"budget,omitempty"`
	Cache    *AICache  `json:"cache,omitempty"`
	PII      *AIPII    `json:"pii,omitempty"`
	// AllowedModels restricts the models a client may ask for (trailing * is a prefix).
	AllowedModels []string `json:"allowedModels,omitempty"`
	// DefaultMaxTokens is assumed for the budget reservation when a request does
	// not set max_tokens (default 1024).
	DefaultMaxTokens int `json:"defaultMaxTokens,omitempty"`
	// MaxRequestBytes bounds a request body (default 4 MiB).
	MaxRequestBytes int64 `json:"maxRequestBytes,omitempty"`
	// InjectStreamUsage asks OpenAI-style providers for a final usage chunk of
	// streamed responses (stream_options.include_usage) and removes it again
	// when the client did not ask for it (default true).
	InjectStreamUsage *bool `json:"injectStreamUsage,omitempty"`
	// Prices overrides the gateway price table for this route (USD or any
	// currency, per million tokens).
	Prices map[string]AIPrice `json:"prices,omitempty"`

	annErr error
}

// AIProvider is one upstream LLM endpoint.
type AIProvider struct {
	Name string `json:"name"`
	// Type is the API shape: "openai" (OpenAI-compatible, the default) or "anthropic".
	Type string `json:"type,omitempty"`
	// BaseURL is the API root, for example https://api.openai.com/v1. With no
	// path, /v1 is used.
	BaseURL string `json:"baseURL"`
	// Weight shares load within one priority (default 1); Priority orders the
	// tiers, lowest first (default 0). A higher tier is used only when the
	// tiers before it have no provider that can take the request.
	Weight   *int `json:"weight,omitempty"`
	Priority int  `json:"priority,omitempty"`
	// APIKey is where the provider credential comes from. It is never part of
	// the route, never shown, and replaces whatever credential the client sent.
	APIKey *AISecretRef `json:"apiKey,omitempty"`
	// AuthHeader and AuthScheme place the credential (defaults: Authorization
	// with scheme Bearer for openai, x-api-key with no scheme for anthropic).
	AuthHeader string `json:"authHeader,omitempty"`
	AuthScheme string `json:"authScheme,omitempty"`
	// Models limits the models the provider serves (trailing * is a prefix); ModelMap renames them.
	Models   []string          `json:"models,omitempty"`
	ModelMap map[string]string `json:"modelMap,omitempty"`
	// Timeout bounds one attempt (default 120s; for a streamed response it ends at the response headers).
	Timeout string `json:"timeout,omitempty"`
	// Headers are extra static request headers (never credentials).
	Headers map[string]string `json:"headers,omitempty"`
}

// AISecretRef names exactly one source of a secret.
type AISecretRef struct {
	Env    string          `json:"env,omitempty"`
	File   string          `json:"file,omitempty"`
	Secret *AISecretKeyRef `json:"secret,omitempty"`
}

// AISecretKeyRef is a key of a Kubernetes Secret.
type AISecretKeyRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Key       string `json:"key"`
}

// AIFailover tunes provider failover.
type AIFailover struct {
	// MaxAttempts bounds the providers tried for one request (default: all).
	MaxAttempts int `json:"maxAttempts,omitempty"`
	// Statuses are the upstream statuses that fail over (default 429 and every 5xx).
	Statuses []int `json:"statuses,omitempty"`
}

// AIBudget limits tokens per identity.
type AIBudget struct {
	// Default applies to every identity without an override.
	Default AILimits `json:"default,omitempty"`
	// Overrides are per identity limits (the identity value is the key).
	Overrides map[string]AILimits `json:"overrides,omitempty"`
	// Route limits the whole route together, whoever calls.
	Route *AILimits `json:"route,omitempty"`
}

// AILimits are fixed-window limits; 0 means unlimited. Windows are the UTC
// minute, the UTC day and the UTC calendar month.
type AILimits struct {
	TokensPerMinute int64   `json:"tokensPerMinute,omitempty"`
	TokensPerDay    int64   `json:"tokensPerDay,omitempty"`
	MonthlyTokens   int64   `json:"monthlyTokens,omitempty"`
	MonthlyCost     float64 `json:"monthlyCost,omitempty"`
}

func (l AILimits) none() bool { return l == AILimits{} }

func (l AILimits) validate(where string) error {
	if l.TokensPerMinute < 0 || l.TokensPerDay < 0 || l.MonthlyTokens < 0 || l.MonthlyCost < 0 {
		return fmt.Errorf("%s: limits must not be negative", where)
	}
	return nil
}

// AICache is the exact-match prompt cache.
type AICache struct {
	// Enabled must be true: the cache is opt-in.
	Enabled bool `json:"enabled"`
	// TTL of an entry (default 5m); MaxEntries (default 1000); MaxEntryBytes
	// (default 256 KiB); MaxBytes is the total (default 64 MiB).
	TTL           string `json:"ttl,omitempty"`
	MaxEntries    int    `json:"maxEntries,omitempty"`
	MaxEntryBytes int64  `json:"maxEntryBytes,omitempty"`
	MaxBytes      int64  `json:"maxBytes,omitempty"`
	// Stream also caches streamed responses (replayed as one burst); default off.
	Stream bool `json:"stream,omitempty"`
	// Scope is "identity" (default: one client never sees another client's
	// cached answer) or "route" (shared by everyone who can reach the route).
	Scope string `json:"scope,omitempty"`
	// IgnoreFields are request fields left out of the key (default ["user"]).
	IgnoreFields []string `json:"ignoreFields,omitempty"`
}

// AIPII is prompt PII handling.
type AIPII struct {
	// Mode: "redact" (default) replaces matches, "block" refuses the request
	// with 400, "report" only counts matches in the metrics and the access log.
	Mode string `json:"mode,omitempty"`
	// Rules are built-in rule names: email, phone, card, ssn (default: all four).
	Rules  []string     `json:"rules,omitempty"`
	Custom []AIPIIRegex `json:"custom,omitempty"`
}

// AIPIIRegex is a custom rule.
type AIPIIRegex struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement,omitempty"`
}

// AIPrice is the price of a model per million tokens.
type AIPrice struct {
	Input  float64 `json:"input"`
	Output float64 `json:"output"`
}

// ParseAIBlock decodes an AI policy strictly (unknown fields are errors) and
// validates its structure. It does not read any secret, so it works on a
// machine that does not have the provider keys (setura lint).
func ParseAIBlock(raw []byte) (*AIPolicy, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p AIPolicy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", AIKey, err)
	}
	if _, err := dec.Token(); err == nil {
		return nil, fmt.Errorf("%s: trailing data after the JSON object", AIKey)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", AIKey, err)
	}
	return &p, nil
}

// AIRuleAnnotation targets rule n (1-based): setura.zyvor.dev/ai.rule-N.
func AIRuleAnnotation(n int) string { return AIKey + ".rule-" + strconv.Itoa(n) }

// annotateAI gives every rule without a policy of its own the policy of its
// annotation (the rule specific one wins). A value that cannot be decoded
// becomes a policy that fails compilation, so the route turns invalid instead
// of silently proxying nothing.
func annotateAI(rules []Rule, ann map[string]string) {
	if len(ann) == 0 {
		return
	}
	for i := range rules {
		if rules[i].AI != nil {
			continue
		}
		key := AIRuleAnnotation(i + 1)
		v, ok := ann[key]
		if !ok {
			key = AIKey
			v, ok = ann[key]
		}
		if !ok {
			continue
		}
		p, err := ParseAIBlock([]byte(v))
		if err != nil {
			p = &AIPolicy{annErr: fmt.Errorf("annotation %s: %w", key, err)}
		}
		rules[i].AI = p
	}
}

// OrphanAIAnnotations lists AI annotation keys that no rule uses.
func OrphanAIAnnotations(ann map[string]string, rules int) []string {
	return orphanAnnotations(AIKey, ann, rules)
}

func orphanAnnotations(base string, ann map[string]string, rules int) []string {
	var out []string
	for k := range ann {
		if k == base || !strings.HasPrefix(k, base) {
			continue
		}
		rest, ok := strings.CutPrefix(k, base+".rule-")
		n, err := strconv.Atoi(rest)
		if !ok || err != nil || n < 1 || n > rules {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// active reports whether the policy is in force.
func (p *AIPolicy) active() bool { return p != nil && (p.Enabled == nil || *p.Enabled) }

var aiNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

const (
	aiDefaultMaxTokens   = 1024
	aiDefaultMaxBody     = 4 << 20
	aiDefaultTimeout     = 120 * time.Second
	aiDefaultCacheTTL    = 5 * time.Minute
	aiDefaultCacheEntry  = 256 << 10
	aiDefaultCacheBytes  = 64 << 20
	aiDefaultCacheCount  = 1000
	aiMaxProviders       = 32
	aiMaxCustomPIIRules  = 32
	aiMaxPIIPatternBytes = 2048
)

// validate checks the structure without touching the environment.
func (p *AIPolicy) validate() error {
	if p.annErr != nil {
		return p.annErr
	}
	if !p.active() {
		return nil
	}
	if len(p.Providers) == 0 {
		return errors.New("providers: at least one provider is required")
	}
	if len(p.Providers) > aiMaxProviders {
		return fmt.Errorf("providers: at most %d", aiMaxProviders)
	}
	seen := map[string]bool{}
	for i, pr := range p.Providers {
		w := fmt.Sprintf("providers[%d]", i)
		if !aiNameRe.MatchString(pr.Name) {
			return fmt.Errorf("%s: name %q must be 1-63 characters of letters, digits, '.', '_' or '-'", w, pr.Name)
		}
		if seen[pr.Name] {
			return fmt.Errorf("%s: provider name %q is used twice", w, pr.Name)
		}
		seen[pr.Name] = true
		w = "provider " + pr.Name
		if err := pr.validate(w); err != nil {
			return err
		}
	}
	if f := p.Failover; f != nil {
		if f.MaxAttempts < 0 || f.MaxAttempts > aiMaxProviders {
			return fmt.Errorf("failover.maxAttempts: %d is outside 0-%d", f.MaxAttempts, aiMaxProviders)
		}
		for _, c := range f.Statuses {
			if c < 400 || c > 599 {
				return fmt.Errorf("failover.statuses: %d is outside 400-599", c)
			}
		}
	}
	if _, _, err := parseAIIdentity(p.Identity); err != nil {
		return err
	}
	if b := p.Budget; b != nil {
		if err := b.Default.validate("budget.default"); err != nil {
			return err
		}
		for k, l := range b.Overrides {
			if err := l.validate("budget.overrides[" + k + "]"); err != nil {
				return err
			}
		}
		if b.Route != nil {
			if err := b.Route.validate("budget.route"); err != nil {
				return err
			}
		}
	}
	if c := p.Cache; c != nil {
		if err := c.validate(); err != nil {
			return err
		}
	}
	if x := p.PII; x != nil {
		if _, err := compilePII(x); err != nil {
			return err
		}
	}
	if p.DefaultMaxTokens < 0 || p.MaxRequestBytes < 0 {
		return errors.New("defaultMaxTokens and maxRequestBytes must not be negative")
	}
	for k, v := range p.Prices {
		if k == "" || v.Input < 0 || v.Output < 0 {
			return fmt.Errorf("prices[%q]: want a model name and non-negative prices", k)
		}
	}
	return nil
}

func (pr AIProvider) validate(w string) error {
	switch pr.Type {
	case "", "openai", "anthropic":
	default:
		return fmt.Errorf("%s: type %q is not openai or anthropic", w, pr.Type)
	}
	if _, err := parseAIBase(pr.BaseURL); err != nil {
		return fmt.Errorf("%s: %w", w, err)
	}
	if pr.Weight != nil && *pr.Weight < 0 {
		return fmt.Errorf("%s: weight must not be negative", w)
	}
	if pr.Priority < 0 {
		return fmt.Errorf("%s: priority must not be negative", w)
	}
	if pr.Timeout != "" {
		if d, err := time.ParseDuration(pr.Timeout); err != nil || d <= 0 {
			return fmt.Errorf("%s: timeout %q is not a positive duration", w, pr.Timeout)
		}
	}
	if a := pr.APIKey; a != nil {
		n := 0
		if a.Env != "" {
			n++
		}
		if a.File != "" {
			n++
		}
		if s := a.Secret; s != nil {
			n++
			if s.Name == "" || s.Key == "" {
				return fmt.Errorf("%s: apiKey.secret needs name and key", w)
			}
		}
		if n != 1 {
			return fmt.Errorf("%s: apiKey needs exactly one of env, file or secret (a key written into the route would be visible to everyone who can read it)", w)
		}
	}
	for h := range pr.Headers {
		switch strings.ToLower(h) {
		case "authorization", "x-api-key", "api-key", "proxy-authorization", "cookie", "host", "content-length", "x-goog-api-key":
			return fmt.Errorf("%s: headers must not set %s: provider credentials come from apiKey", w, h)
		}
	}
	for _, m := range pr.Models {
		if m == "" {
			return fmt.Errorf("%s: empty model pattern", w)
		}
	}
	for from, to := range pr.ModelMap {
		if from == "" || to == "" {
			return fmt.Errorf("%s: modelMap needs non-empty names", w)
		}
	}
	return nil
}

func (c *AICache) validate() error {
	if c.TTL != "" {
		if d, err := time.ParseDuration(c.TTL); err != nil || d <= 0 {
			return fmt.Errorf("cache.ttl %q is not a positive duration", c.TTL)
		}
	}
	switch c.Scope {
	case "", "identity", "route":
	default:
		return fmt.Errorf("cache.scope %q is not identity or route", c.Scope)
	}
	if c.MaxEntries < 0 || c.MaxEntries > 1_000_000 || c.MaxEntryBytes < 0 || c.MaxBytes < 0 {
		return errors.New("cache sizes must not be negative (maxEntries at most 1000000)")
	}
	return nil
}

// parseAIBase checks a provider base URL and returns it with its path.
func parseAIBase(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("baseURL %q: want an http(s) URL", redactURL(raw))
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("baseURL must not carry credentials, a query or a fragment")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = "/v1"
	}
	return u, nil
}

// parseAIIdentity splits an identity selector into its kind and name.
func parseAIIdentity(s string) (kind, name string, err error) {
	switch {
	case s == "" || s == "subject":
		return "subject", "", nil
	case s == "apikey":
		return "apikey", "", nil
	case strings.HasPrefix(s, "claim:") && len(s) > len("claim:"):
		return "claim", s[len("claim:"):], nil
	case strings.HasPrefix(s, "header:") && len(s) > len("header:"):
		return "header", s[len("header:"):], nil
	}
	return "", "", fmt.Errorf("identity %q: want apikey, subject, claim:NAME or header:NAME", s)
}

// ---- secrets ---------------------------------------------------------

// aiSecret is a resolved secret source. get never logs and never errors out
// after the first successful read: a file that cannot be re-read keeps its
// last value (a rotation in progress must not take the route down).
type aiSecret struct {
	desc string // "env NAME", "file PATH" or "secret NS/NAME#KEY": safe to show
	get  func() string
}

var aiSecretRecheck = 5 * time.Second

func resolveAISecret(ref *AISecretRef, routeNS string, keys map[string]string, granted func(ns, name string) bool) (*aiSecret, error) {
	switch {
	case ref.Env != "":
		v := strings.TrimSpace(os.Getenv(ref.Env))
		if v == "" {
			return nil, fmt.Errorf("environment variable %s is empty or not set", ref.Env)
		}
		return &aiSecret{desc: "env " + ref.Env, get: func() string { return v }}, nil
	case ref.File != "":
		read := func() (string, os.FileInfo, error) {
			b, err := os.ReadFile(ref.File)
			if err != nil {
				return "", nil, err
			}
			fi, _ := os.Stat(ref.File)
			return strings.TrimSpace(string(b)), fi, nil
		}
		v, fi, err := read()
		if err != nil {
			return nil, fmt.Errorf("secret file %s: %v", ref.File, errors.Unwrap(err))
		}
		if v == "" {
			return nil, fmt.Errorf("secret file %s is empty", ref.File)
		}
		var mu sync.Mutex
		checked := time.Now()
		return &aiSecret{desc: "file " + ref.File, get: func() string {
			mu.Lock()
			defer mu.Unlock()
			if time.Since(checked) < aiSecretRecheck {
				return v
			}
			checked = time.Now()
			if st, err := os.Stat(ref.File); err == nil && (fi == nil || !st.ModTime().Equal(fi.ModTime()) || st.Size() != fi.Size()) {
				if nv, nfi, err := read(); err == nil && nv != "" {
					v, fi = nv, nfi
				}
			}
			return v
		}}, nil
	case ref.Secret != nil:
		ns := ref.Secret.Namespace
		if ns == "" {
			ns = routeNS
		}
		if !granted(ns, ref.Secret.Name) {
			return nil, fmt.Errorf("Secret %s/%s needs a ReferenceGrant", ns, ref.Secret.Name)
		}
		id := ns + "/" + ref.Secret.Name + "#" + ref.Secret.Key
		v := strings.TrimSpace(keys[id])
		if v == "" {
			return nil, fmt.Errorf("Secret %s is not available (the Kubernetes source reads it; a snapshot file needs env or file)", id)
		}
		return &aiSecret{desc: "secret " + id, get: func() string { return v }}, nil
	}
	return nil, errors.New("no secret source")
}
