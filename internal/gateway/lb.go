package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Load balancing: how a request picks one endpoint of a backend.
//
// A load-balancer block is a rule field (setura.zyvor.dev/load-balancer), the
// route annotation of that name (KEY or KEY.rule-N), a backend field
// ("loadBalancer") and the gateway wide default (--load-balancer). The most
// specific one wins as a whole; blocks are not merged field by field.
const (
	LoadBalancerKey = "setura.zyvor.dev/load-balancer"

	AlgoRoundRobin     = "roundRobin"
	AlgoLeastRequest   = "leastRequest"
	AlgoRandom         = "random"
	AlgoConsistentHash = "consistentHash"

	defaultRingSize   = 1024
	maxRingSize       = 8 << 20
	defaultMaglevSize = 65537
	maxMaglevSize     = 5000011
	defaultLBPercent  = 70
)

// LBConfig is the JSON form of a load-balancer block.
type LBConfig struct {
	// Algorithm is roundRobin (default), leastRequest, random or consistentHash.
	Algorithm string `json:"algorithm,omitempty"`
	// Choices is how many endpoints leastRequest samples (default 2: power of two choices).
	Choices        int          `json:"choices,omitempty"`
	ConsistentHash *LBHash      `json:"consistentHash,omitempty"`
	SlowStart      *LBSlowStart `json:"slowStart,omitempty"`
	Locality       *LBLocality  `json:"locality,omitempty"`
	Priority       *LBPriority  `json:"priority,omitempty"`
	// PanicThreshold is the healthy percentage of all endpoints under which
	// health is ignored and every endpoint takes traffic (0 = never).
	PanicThreshold int `json:"panicThreshold,omitempty"`
}

// LBHash configures consistentHash.
type LBHash struct {
	Type string `json:"type,omitempty"` // ring (default) or maglev
	On   string `json:"on"`             // header, cookie, sourceIP or query
	Name string `json:"name,omitempty"` // header, cookie or query parameter name
	// TTL and Path apply to the cookie the gateway sets when the request has none.
	TTL         string `json:"ttl,omitempty"`
	Path        string `json:"path,omitempty"`
	MinRingSize int    `json:"minRingSize,omitempty"` // ring: minimum points on the ring (default 1024)
	TableSize   int    `json:"tableSize,omitempty"`   // maglev: lookup table size, a prime (default 65537)
}

// LBSlowStart ramps the weight of a new endpoint up over Window.
type LBSlowStart struct {
	Window           string  `json:"window"`
	Aggression       float64 `json:"aggression,omitempty"`       // 1 = linear (default); above 1 ramps faster
	MinWeightPercent int     `json:"minWeightPercent,omitempty"` // weight floor while ramping (default 10)
}

// LBLocality prefers endpoints in the gateway's own zone.
type LBLocality struct {
	PreferLocalZone bool `json:"preferLocalZone"`
	// LocalZone overrides --zone for this block.
	LocalZone string `json:"localZone,omitempty"`
	// MinHealthyPercent is the healthy share the local zone must keep to serve
	// alone; below it traffic spills to every zone (default 70).
	MinHealthyPercent int `json:"minHealthyPercent,omitempty"`
}

// LBPriority is priority failover: priority 0 serves until its healthy share
// drops under HealthyPercent, then priority 1 joins, and so on.
type LBPriority struct {
	HealthyPercent int `json:"healthyPercent,omitempty"` // default 70
}

// CLB is a compiled load-balancer block.
type CLB struct {
	Algo    string
	Choices int
	Hash    *CHash
	// Slow start: zero Window turns it off.
	SlowWindow time.Duration
	SlowAggr   float64
	SlowMin    float64 // 0-1

	PreferLocal bool
	LocalZone   string
	LocalMin    int
	PrioMin     int
	Panic       int

	Raw *LBConfig
}

// CHash is the compiled hash policy.
type CHash struct {
	Maglev  bool
	On      string // header, cookie, sourceIP, query
	Name    string
	TTL     time.Duration
	Path    string
	MinRing int
	Table   int
}

func canonName(s string) string {
	return strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// UnmarshalJSON reads an object (unknown fields are errors) or a bare string,
// which is shorthand for {"algorithm": ...}.
func (c *LBConfig) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		*c = LBConfig{}
		return json.Unmarshal(raw, &c.Algorithm)
	}
	type alias LBConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var a alias
	if err := dec.Decode(&a); err != nil {
		return err
	}
	*c = LBConfig(a)
	return nil
}

// ParseLBBlock decodes and validates a load-balancer block. A bare JSON
// string is shorthand for {"algorithm": ...}.
func ParseLBBlock(raw []byte) (*LBConfig, error) {
	var c LBConfig
	if err := strictDecode(LoadBalancerKey, bytes.TrimSpace(raw), &c); err != nil {
		return nil, err
	}
	if _, err := c.Compile(); err != nil {
		return nil, fmt.Errorf("%s: %w", LoadBalancerKey, err)
	}
	return &c, nil
}

// ParseLBFlag reads the --load-balancer flag: an algorithm name or a JSON block.
func ParseLBFlag(s string) (*LBConfig, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if s[0] != '{' && s[0] != '"' {
		s = strconv.Quote(s)
	}
	return ParseLBBlock([]byte(s))
}

func validPct(name string, v, lo int) error {
	if v < lo || v > 100 {
		return fmt.Errorf("%s %d is outside %d-100", name, v, lo)
	}
	return nil
}

func isPrime(n int) bool {
	if n < 2 {
		return false
	}
	for i := 2; i*i <= n; i++ {
		if n%i == 0 {
			return false
		}
	}
	return true
}

// Compile validates the block and resolves defaults.
func (c *LBConfig) Compile() (*CLB, error) {
	out := &CLB{Raw: c, Choices: 2, LocalMin: defaultLBPercent, PrioMin: defaultLBPercent, SlowAggr: 1, SlowMin: 0.1}
	switch canonName(c.Algorithm) {
	case "", "roundrobin":
		out.Algo = AlgoRoundRobin
	case "leastrequest", "leastconn":
		out.Algo = AlgoLeastRequest
	case "random":
		out.Algo = AlgoRandom
	case "consistenthash", "ringhash", "maglev":
		out.Algo = AlgoConsistentHash
	default:
		return nil, fmt.Errorf("algorithm %q: want roundRobin, leastRequest, random or consistentHash", c.Algorithm)
	}
	if c.Choices != 0 {
		if out.Algo != AlgoLeastRequest {
			return nil, fmt.Errorf("choices only applies to leastRequest")
		}
		if c.Choices < 1 || c.Choices > 16 {
			return nil, fmt.Errorf("choices %d is outside 1-16", c.Choices)
		}
		out.Choices = c.Choices
	}
	if h := c.ConsistentHash; h != nil {
		if out.Algo != AlgoConsistentHash {
			return nil, fmt.Errorf("consistentHash is set but the algorithm is %s", out.Algo)
		}
		ch := &CHash{Path: "/", MinRing: defaultRingSize, Table: defaultMaglevSize}
		switch canonName(h.Type) {
		case "", "ring", "ringhash":
		case "maglev":
			ch.Maglev = true
		default:
			return nil, fmt.Errorf("consistentHash.type %q: want ring or maglev", h.Type)
		}
		switch canonName(h.On) {
		case "header":
			ch.On = "header"
			if !validHeaderName(h.Name) {
				return nil, fmt.Errorf("consistentHash.name %q is not a header name", h.Name)
			}
			ch.Name = strings.ToLower(h.Name)
		case "cookie":
			ch.On = "cookie"
			if h.Name == "" || strings.ContainsAny(h.Name, " \t;=,\"") {
				return nil, fmt.Errorf("consistentHash.name %q is not a cookie name", h.Name)
			}
			ch.Name = h.Name
		case "query", "queryparam", "queryparameter":
			ch.On = "query"
			if h.Name == "" {
				return nil, fmt.Errorf("consistentHash.name is required to hash on a query parameter")
			}
			ch.Name = h.Name
		case "sourceip", "clientip":
			ch.On = "sourceIP"
			if h.Name != "" {
				return nil, fmt.Errorf("consistentHash.name does not apply to sourceIP")
			}
		case "":
			return nil, fmt.Errorf("consistentHash.on is required: header, cookie, sourceIP or query")
		default:
			return nil, fmt.Errorf("consistentHash.on %q: want header, cookie, sourceIP or query", h.On)
		}
		if h.TTL != "" || h.Path != "" {
			if ch.On != "cookie" {
				return nil, fmt.Errorf("consistentHash.ttl and path only apply to a cookie")
			}
			d, err := parseDur(h.TTL)
			if err != nil || d < 0 {
				return nil, fmt.Errorf("consistentHash.ttl %q is not a duration", h.TTL)
			}
			ch.TTL = d
			if h.Path != "" {
				if !strings.HasPrefix(h.Path, "/") {
					return nil, fmt.Errorf("consistentHash.path %q must start with /", h.Path)
				}
				ch.Path = h.Path
			}
		}
		if h.MinRingSize != 0 {
			if ch.Maglev {
				return nil, fmt.Errorf("consistentHash.minRingSize does not apply to maglev (use tableSize)")
			}
			if h.MinRingSize < 1 || h.MinRingSize > maxRingSize {
				return nil, fmt.Errorf("consistentHash.minRingSize %d is outside 1-%d", h.MinRingSize, maxRingSize)
			}
			ch.MinRing = h.MinRingSize
		}
		if h.TableSize != 0 {
			if !ch.Maglev {
				return nil, fmt.Errorf("consistentHash.tableSize only applies to maglev (use minRingSize)")
			}
			if h.TableSize > maxMaglevSize || !isPrime(h.TableSize) {
				return nil, fmt.Errorf("consistentHash.tableSize %d must be a prime up to %d", h.TableSize, maxMaglevSize)
			}
			ch.Table = h.TableSize
		}
		out.Hash = ch
	} else if out.Algo == AlgoConsistentHash {
		return nil, fmt.Errorf("consistentHash needs a consistentHash block saying what to hash (on: header, cookie, sourceIP or query)")
	}
	if s := c.SlowStart; s != nil {
		if out.Algo == AlgoConsistentHash {
			return nil, fmt.Errorf("slowStart does not apply to consistentHash")
		}
		d, err := parseDur(s.Window)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("slowStart.window %q is not a positive duration", s.Window)
		}
		out.SlowWindow = d
		if s.Aggression != 0 {
			if s.Aggression < 0.1 || s.Aggression > 10 {
				return nil, fmt.Errorf("slowStart.aggression %v is outside 0.1-10", s.Aggression)
			}
			out.SlowAggr = s.Aggression
		}
		if s.MinWeightPercent != 0 {
			if err := validPct("slowStart.minWeightPercent", s.MinWeightPercent, 1); err != nil {
				return nil, err
			}
			out.SlowMin = float64(s.MinWeightPercent) / 100
		}
	}
	if l := c.Locality; l != nil {
		out.PreferLocal, out.LocalZone = l.PreferLocalZone, l.LocalZone
		if l.MinHealthyPercent != 0 {
			if err := validPct("locality.minHealthyPercent", l.MinHealthyPercent, 1); err != nil {
				return nil, err
			}
			out.LocalMin = l.MinHealthyPercent
		}
	}
	if p := c.Priority; p != nil && p.HealthyPercent != 0 {
		if err := validPct("priority.healthyPercent", p.HealthyPercent, 1); err != nil {
			return nil, err
		}
		out.PrioMin = p.HealthyPercent
	}
	if c.PanicThreshold != 0 {
		if err := validPct("panicThreshold", c.PanicThreshold, 1); err != nil {
			return nil, err
		}
		out.Panic = c.PanicThreshold
	}
	return out, nil
}

// annotateLB copies load-balancer annotations (KEY or KEY.rule-N) onto the
// rules that have no field of their own.
func annotateLB(rules []Rule, ann map[string]string) {
	if len(ann) == 0 {
		return
	}
	for i := range rules {
		r := &rules[i]
		key := RuleExtAnnotation(LoadBalancerKey, i+1)
		v, ok := ann[key]
		if !ok {
			key = LoadBalancerKey
			v, ok = ann[key]
		}
		if !ok || r.LoadBalancer != nil {
			continue
		}
		b, err := ParseLBBlock([]byte(v))
		if err != nil {
			if r.extErr == nil {
				r.extErr = fmt.Errorf("annotation %s: %w", key, err)
			}
			continue
		}
		r.LoadBalancer = b
	}
}

// ---- endpoint helpers ----

// W is the endpoint's configured weight (default 1).
func (e *Endpoint) W() int {
	if e.weight <= 0 {
		return 1
	}
	return e.weight
}

// since is when the endpoint last became a candidate for slow start: added to a
// running table, brought back by an active check, or released from ejection.
func (e *Endpoint) since() time.Time {
	t := e.added
	if r := e.recovered.Load(); r != 0 {
		if rt := time.Unix(0, r); rt.After(t) {
			t = rt
		}
	}
	if e.st.until.After(t) {
		t = e.st.until
	}
	return t
}

// slowFactor is the share of its weight an endpoint gets at now (1 when not ramping).
func (e *Endpoint) slowFactor(c *CLB, now time.Time) float64 {
	if c.SlowWindow <= 0 {
		return 1
	}
	since := e.since()
	if since.IsZero() {
		return 1
	}
	age := now.Sub(since)
	if age >= c.SlowWindow {
		return 1
	}
	if age < 0 {
		return c.SlowMin
	}
	f := math.Pow(float64(age)/float64(c.SlowWindow), 1/c.SlowAggr)
	if f < c.SlowMin {
		f = c.SlowMin
	}
	return f
}

// ---- per request context ----

// lbReq carries what the picker needs from the request. A nil *lbReq picks with
// the backend's own configuration and no request key.
type lbReq struct {
	rule *CLB // the rule's block, nil when it has none
	def  *CLB // gateway wide default
	zone string
	rnd  func(int) int
	r    *http.Request
	ip   string
	tls  bool

	keyed  bool
	key    uint64
	desc   string // what was hashed, never the value of a cookie or header
	keyOK  bool
	cookie *http.Cookie // to set on the response
}

func (rq *lbReq) rand(n int) int {
	if rq != nil && rq.rnd != nil {
		return rq.rnd(n)
	}
	return randIntn(n)
}

func hash64(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return mix64(h.Sum64())
}

func mix64(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

// hashKey derives the request's hash. ok is false when the request has no value
// to hash on (a missing header or query parameter).
func (rq *lbReq) hashKey(h *CHash) (key uint64, desc string, ok bool) {
	if rq == nil || rq.r == nil {
		return 0, "no request", false
	}
	if rq.keyed {
		return rq.key, rq.desc, rq.keyOK
	}
	rq.keyed = true
	var v string
	switch h.On {
	case "header":
		v = rq.r.Header.Get(h.Name)
		rq.desc = "header " + h.Name
	case "query":
		v = rq.r.URL.Query().Get(h.Name)
		rq.desc = "query parameter " + h.Name
	case "sourceIP":
		v = rq.ip
		rq.desc = "source IP"
	case "cookie":
		rq.desc = "cookie " + h.Name
		if c, err := rq.r.Cookie(h.Name); err == nil && c.Value != "" {
			v = c.Value
		} else {
			v = fmt.Sprintf("%08x%08x", rq.rand(1<<31), rq.rand(1<<31))
			rq.cookie = &http.Cookie{Name: h.Name, Value: v, Path: h.Path, HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: rq.tls}
			if h.TTL > 0 {
				rq.cookie.MaxAge = int(h.TTL / time.Second)
			}
			rq.desc += " (absent: set by the gateway)"
		}
	}
	if v == "" {
		rq.keyOK = false
		return 0, rq.desc + " (absent)", false
	}
	rq.key, rq.keyOK = hash64(v), true
	return rq.key, rq.desc, true
}

// ---- the pick ----

// lbWhy says how an endpoint was chosen, in numbers; String renders it.
type lbWhy struct {
	Algo    string
	Cands   int  // endpoints the algorithm chose among
	Tiers   int  // priority tiers in play
	Local   bool // only the local zone was used
	Spill   bool // the local zone was too unhealthy and every zone served
	Panic   bool
	AllDown bool // every endpoint is down or ejected, so any is tried
	Retry   bool // endpoints already tried were avoided
	NoKey   bool // consistentHash found nothing to hash and chose at random
	Hash    string
	Sampled int
	Load    int64 // in-flight requests of the chosen endpoint (leastRequest)
	Other   int64 // in-flight requests of the runner up
	Solo    bool  // a single candidate
	Ring    string
}

func (w lbWhy) String() string {
	var p []string
	switch {
	case w.AllDown:
		p = append(p, "every endpoint is unhealthy or ejected, so one is tried anyway")
	case w.Panic:
		p = append(p, "panic mode: too few endpoints are healthy, so health is ignored")
	}
	if w.Tiers > 1 {
		p = append(p, fmt.Sprintf("priority 0 is under its healthy threshold, so %d tiers serve together", w.Tiers))
	}
	if w.Local {
		p = append(p, "the local zone is healthy enough to serve alone")
	} else if w.Spill {
		p = append(p, "the local zone is under its healthy threshold, so every zone serves")
	}
	switch {
	case w.Solo:
		p = append(p, "only one endpoint can take traffic")
	case w.Algo == AlgoConsistentHash && w.NoKey:
		p = append(p, fmt.Sprintf("%s was not in the request, so an endpoint was picked at random", w.Hash))
	case w.Algo == AlgoConsistentHash:
		p = append(p, fmt.Sprintf("%s hash of the %s selected it", w.Ring, w.Hash))
	case w.Algo == AlgoLeastRequest:
		p = append(p, fmt.Sprintf("least request: sampled %d of %d endpoints, it had the fewest in-flight requests (%d, runner up %d)", w.Sampled, w.Cands, w.Load, w.Other))
	case w.Algo == AlgoRandom:
		p = append(p, fmt.Sprintf("random by weight among %d endpoints", w.Cands))
	default:
		p = append(p, fmt.Sprintf("weighted round robin over %d endpoints", w.Cands))
	}
	if w.Retry {
		p = append(p, "endpoints already tried were avoided")
	}
	return strings.Join(p, "; ")
}

// lbRecord is the last pick of a backend, shown in /status.
type lbRecord struct {
	ep  *Endpoint
	why lbWhy
	at  time.Time
}

// cfg returns the block that applies: rule, backend, then the gateway default.
func (b *Backend) cfg(rq *lbReq) *CLB {
	if rq != nil && rq.rule != nil {
		return rq.rule
	}
	if b.LB != nil {
		return b.LB
	}
	if rq != nil && rq.def != nil {
		return rq.def
	}
	return defaultLB
}

var defaultLB = &CLB{Algo: AlgoRoundRobin, Choices: 2, LocalMin: defaultLBPercent, PrioMin: defaultLBPercent, SlowAggr: 1, SlowMin: 0.1}

// weightOf is the effective weight of e.
func weightOf(e *Endpoint, c *CLB, now time.Time) float64 {
	w := float64(e.W())
	if c.Algo != AlgoConsistentHash {
		w *= e.slowFactor(c, now)
	}
	return w
}

// candidates narrows the up endpoints by priority tier and zone. Caller holds hmu.
func (b *Backend) candidates(c *CLB, ups []*Endpoint, zone string, why *lbWhy) []*Endpoint {
	cand := ups
	if len(b.prios) > 1 {
		accTotal, accUp, tiers := 0, 0, 0
		for i, p := range b.prios {
			accTotal += b.prioCount[p]
			for _, e := range ups {
				if e.Priority == p {
					accUp++
				}
			}
			tiers = i + 1
			if i == len(b.prios)-1 || (accUp > 0 && accUp*100 >= c.PrioMin*accTotal) {
				break
			}
		}
		why.Tiers = tiers
		maxP := b.prios[tiers-1]
		sel := make([]*Endpoint, 0, len(ups))
		for _, e := range ups {
			if e.Priority <= maxP {
				sel = append(sel, e)
			}
		}
		cand = sel
	}
	if c.PreferLocal && zone != "" && b.hasZone {
		total, local := 0, make([]*Endpoint, 0, len(cand))
		for _, e := range b.Eps {
			if e.Zone == zone && (len(b.prios) <= 1 || e.Priority <= b.prios[max(why.Tiers, 1)-1]) {
				total++
			}
		}
		for _, e := range cand {
			if e.Zone == zone {
				local = append(local, e)
			}
		}
		switch {
		case total > 0 && len(local) > 0 && len(local)*100 >= c.LocalMin*total:
			cand, why.Local = local, true
		case total > 0:
			why.Spill = true
		}
	}
	return cand
}

// pickLB chooses an endpoint of b. dry reports the choice a deterministic
// algorithm would make without changing any state (explain, status).
func (b *Backend) pickLB(now time.Time, skip map[*Endpoint]bool, rq *lbReq, dry bool) (*Endpoint, lbWhy) {
	n := len(b.Eps)
	if n == 0 {
		return nil, lbWhy{}
	}
	c := b.cfg(rq)
	why := lbWhy{Algo: c.Algo}
	b.hmu.Lock()
	defer b.hmu.Unlock()
	if !dry {
		b.rr.Add(1)
	}
	ups := make([]*Endpoint, 0, n)
	for _, e := range b.Eps {
		if b.up(e, now) {
			ups = append(ups, e)
		}
	}
	cand := ups
	switch {
	case c.Panic > 0 && len(ups)*100 < c.Panic*n:
		cand, why.Panic = b.Eps, true
	case len(ups) == 0:
		cand, why.AllDown = b.Eps, true
	default:
		zone := c.LocalZone
		if zone == "" && rq != nil {
			zone = rq.zone
		}
		cand = b.candidates(c, ups, zone, &why)
	}
	if len(skip) > 0 {
		rest := make([]*Endpoint, 0, len(cand))
		for _, e := range cand {
			if !skip[e] {
				rest = append(rest, e)
			}
		}
		if len(rest) > 0 && len(rest) < len(cand) {
			cand, why.Retry = rest, true
		}
	}
	why.Cands = len(cand)
	var ep *Endpoint
	switch {
	case len(cand) == 1:
		ep, why.Solo = cand[0], true
	case c.Algo == AlgoConsistentHash:
		ep = b.hashPick(c, cand, rq, &why)
	case dry:
		return nil, why
	case c.Algo == AlgoRandom:
		ep = pickRandom(c, cand, rq, now)
	case c.Algo == AlgoLeastRequest:
		ep = pickLeast(c, cand, rq, now, &why)
	default:
		ep = pickSWRR(c, cand, now)
	}
	if ep != nil && !dry {
		b.last.Store(&lbRecord{ep: ep, why: why, at: now})
	}
	return ep, why
}

func pickRandom(c *CLB, cand []*Endpoint, rq *lbReq, now time.Time) *Endpoint {
	ws := make([]float64, len(cand))
	total := 0.0
	for i, e := range cand {
		ws[i] = weightOf(e, c, now)
		total += ws[i]
	}
	x := float64(rq.rand(1<<20)) / float64(1<<20) * total
	for i, e := range cand {
		if x < ws[i] {
			return e
		}
		x -= ws[i]
	}
	return cand[len(cand)-1]
}

// pickLeast is power-of-N-choices: sample c.Choices distinct endpoints and take
// the one with the lowest in-flight count per unit of weight.
func pickLeast(c *CLB, cand []*Endpoint, rq *lbReq, now time.Time, why *lbWhy) *Endpoint {
	k := min(c.Choices, len(cand))
	idx := make([]int, len(cand))
	for i := range idx {
		idx[i] = i
	}
	var best *Endpoint
	bestLoad, bestScore, other := int64(0), 0.0, int64(-1)
	for i := 0; i < k; i++ {
		j := i + rq.rand(len(idx)-i)
		idx[i], idx[j] = idx[j], idx[i]
		e := cand[idx[i]]
		load := e.inflight.Load()
		score := float64(load+1) / weightOf(e, c, now)
		if best == nil || score < bestScore {
			if best != nil {
				other = bestLoad
			}
			best, bestLoad, bestScore = e, load, score
		} else if other < 0 || load < other {
			other = load
		}
	}
	why.Sampled, why.Load, why.Other = k, bestLoad, other
	if other < 0 {
		why.Other = bestLoad
	}
	return best
}

// pickSWRR is smooth weighted round robin: exact proportions, no bursts.
func pickSWRR(c *CLB, cand []*Endpoint, now time.Time) *Endpoint {
	total := 0.0
	var best *Endpoint
	for _, e := range cand {
		w := weightOf(e, c, now)
		e.cur += w
		total += w
		if best == nil || e.cur > best.cur {
			best = e
		}
	}
	best.cur -= total
	return best
}

// hashPick maps the request's key onto the ring or Maglev table and takes the
// first endpoint at or after that point that is a candidate.
func (b *Backend) hashPick(c *CLB, cand []*Endpoint, rq *lbReq, why *lbWhy) *Endpoint {
	h := c.Hash
	why.Ring = "ring"
	if h.Maglev {
		why.Ring = "Maglev"
	}
	key, desc, ok := rq.hashKey(h)
	why.Hash = desc
	if !ok {
		why.NoKey = true
		return cand[rq.rand(len(cand))]
	}
	in := make(map[*Endpoint]bool, len(cand))
	for _, e := range cand {
		in[e] = true
	}
	if h.Maglev {
		t := b.maglevFor(h.Table)
		for i := 0; i < len(t.entry); i++ {
			if e := b.Eps[t.entry[(int(key%uint64(len(t.entry)))+i)%len(t.entry)]]; in[e] {
				return e
			}
		}
		return cand[0]
	}
	r := b.ringFor(h.MinRing)
	start := sort.Search(len(r.pts), func(i int) bool { return r.pts[i].h >= key })
	for i := 0; i < len(r.pts); i++ {
		if e := b.Eps[r.pts[(start+i)%len(r.pts)].idx]; in[e] {
			return e
		}
	}
	return cand[0]
}

type ringPt struct {
	h   uint64
	idx int32
}

type lbRing struct{ pts []ringPt }

type lbMaglev struct{ entry []int32 }

// lbTables caches the rings and Maglev tables of one backend. They depend only
// on the (immutable) endpoint list and weights.
type lbTables struct {
	mu     sync.Mutex
	rings  map[int]*lbRing
	maglev map[int]*lbMaglev
}

func (b *Backend) epKey(i int) string { return b.Eps[i].URL.Host }

// ringReferenceEndpoints is the endpoint count minRingSize is spread over to get
// the points of one weight unit. The points of an endpoint depend only on its
// own weight, never on how many other endpoints exist, so adding or removing an
// endpoint moves only the keys that endpoint gains or loses.
const (
	ringReferenceEndpoints   = 64
	ringMaxPointsPerEndpoint = 1 << 15
)

// ringPointsPerWeight is the ring points of one weight unit for a minRingSize.
func ringPointsPerWeight(minSize int) int {
	return max(1, (minSize+ringReferenceEndpoints-1)/ringReferenceEndpoints)
}

func (b *Backend) ringFor(minSize int) *lbRing {
	b.tabs.mu.Lock()
	defer b.tabs.mu.Unlock()
	if r := b.tabs.rings[minSize]; r != nil {
		return r
	}
	r := &lbRing{}
	perWeight := ringPointsPerWeight(minSize)
	for i, e := range b.Eps {
		pts := min(e.W()*perWeight, ringMaxPointsPerEndpoint)
		for j := 0; j < pts; j++ {
			r.pts = append(r.pts, ringPt{hash64(b.epKey(i) + "#" + strconv.Itoa(j)), int32(i)})
		}
	}
	sort.Slice(r.pts, func(i, j int) bool {
		if r.pts[i].h != r.pts[j].h {
			return r.pts[i].h < r.pts[j].h
		}
		return r.pts[i].idx < r.pts[j].idx
	})
	if b.tabs.rings == nil {
		b.tabs.rings = map[int]*lbRing{}
	}
	b.tabs.rings[minSize] = r
	return r
}

func (b *Backend) maglevFor(m int) *lbMaglev {
	b.tabs.mu.Lock()
	defer b.tabs.mu.Unlock()
	if t := b.tabs.maglev[m]; t != nil {
		return t
	}
	n := len(b.Eps)
	maxW := 0
	for _, e := range b.Eps {
		maxW = max(maxW, e.W())
	}
	offset, skip, next, filled := make([]uint64, n), make([]uint64, n), make([]uint64, n), make([]int, n)
	for i := range b.Eps {
		offset[i] = hash64(b.epKey(i)+"/offset") % uint64(m)
		skip[i] = hash64(b.epKey(i)+"/skip")%uint64(m-1) + 1
	}
	t := &lbMaglev{entry: make([]int32, m)}
	for i := range t.entry {
		t.entry[i] = -1
	}
	placed := 0
	for round := 1; placed < m; round++ {
		for i, e := range b.Eps {
			for filled[i] < round*e.W()/maxW && placed < m {
				c := (offset[i] + next[i]*skip[i]) % uint64(m)
				for t.entry[c] >= 0 {
					next[i]++
					c = (offset[i] + next[i]*skip[i]) % uint64(m)
				}
				t.entry[c] = int32(i)
				next[i]++
				filled[i]++
				placed++
			}
		}
	}
	if b.tabs.maglev == nil {
		b.tabs.maglev = map[int]*lbMaglev{}
	}
	b.tabs.maglev[m] = t
	return t
}

// ---- wiring ----

// lbFor builds the picking context of a request: the rule's block and what the
// hash needs from the request.
func (s *Server) lbFor(rule *CRule, r *http.Request, tlsPort bool) *lbReq {
	rq := &lbReq{def: s.lbDefault, zone: s.opts.Zone, rnd: s.intn, r: r, tls: tlsPort}
	if rule != nil {
		rq.rule = rule.LB
	}
	if r != nil {
		rq.ip = s.trusted.clientIP(r)
	}
	return rq
}

// choose picks the next endpoint with the backend's own algorithm and no request.
func (b *Backend) choose(now time.Time, skip map[*Endpoint]bool) *Endpoint {
	ep, _ := b.pickLB(now, skip, nil, false)
	return ep
}

// chooseFor is choose for a request.
func (b *Backend) chooseFor(now time.Time, skip map[*Endpoint]bool, rq *lbReq) *Endpoint {
	ep, _ := b.pickLB(now, skip, rq, false)
	return ep
}

// pick returns an endpoint for fire-and-forget users (mirrors).
func (b *Backend) pick() *Endpoint { return b.choose(time.Now(), nil) }

// inflightBody counts an endpoint's in-flight request down when the response body is done.
type inflightBody struct {
	rc interface {
		Read([]byte) (int, error)
		Close() error
	}
	ep   *Endpoint
	done atomic.Bool
}

func (b *inflightBody) Read(p []byte) (int, error) { return b.rc.Read(p) }
func (b *inflightBody) Close() error {
	err := b.rc.Close()
	if b.done.CompareAndSwap(false, true) {
		b.ep.inflight.Add(-1)
	}
	return err
}
