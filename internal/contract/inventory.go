package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// InventorySchema identifies the inventory file format.
const InventorySchema = "setura.contract-inventory/v1"

// DefaultMaxEndpoints bounds the endpoints one learner keeps.
const DefaultMaxEndpoints = 5000

// Bounds of the per-endpoint sets and maps. Past a bound new keys count under "other".
const (
	maxNames   = 32 // query parameter and header names
	maxKeys    = 16 // routes, backends, content types
	maxStatus  = 32
	maxNameLen = 64
	otherKey   = "other"
)

var (
	latencyBounds = []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000}
	byteBounds    = []float64{0, 128, 512, 1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20, 64 << 20}
)

// Dist is a fixed-bucket distribution. Percentiles are the upper bound of the
// bucket that holds the rank, so they overstate by up to one bucket; the
// last bucket reports Max.
type Dist struct {
	N    int64   `json:"n"`
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P99  float64 `json:"p99"`
	Max  float64 `json:"max"`
	Hist []int64 `json:"hist,omitempty"`
}

func (d *Dist) add(bounds []float64, v float64) {
	if v < 0 {
		return
	}
	if d.Hist == nil {
		d.Hist = make([]int64, len(bounds)+1)
	}
	i := sort.SearchFloat64s(bounds, v)
	d.Hist[i]++
	d.N++
	if v > d.Max {
		d.Max = v
	}
}

func (d *Dist) merge(o *Dist, bounds []float64) {
	if len(o.Hist) != len(bounds)+1 {
		return
	}
	if d.Hist == nil {
		d.Hist = make([]int64, len(bounds)+1)
	}
	for i, c := range o.Hist {
		d.Hist[i] += c
	}
	d.N += o.N
	if o.Max > d.Max {
		d.Max = o.Max
	}
}

func (d *Dist) quantile(bounds []float64, q float64) float64 {
	if d.N == 0 || len(d.Hist) != len(bounds)+1 {
		return 0
	}
	rank := int64(q*float64(d.N) + 0.9999999)
	if rank < 1 {
		rank = 1
	}
	var cum int64
	for i, c := range d.Hist {
		cum += c
		if cum >= rank {
			if i >= len(bounds) || bounds[i] > d.Max {
				return d.Max
			}
			return bounds[i]
		}
	}
	return d.Max
}

func (d *Dist) finalize(bounds []float64) {
	if len(d.Hist) != len(bounds)+1 {
		*d = Dist{}
		return
	}
	d.N = 0
	for _, c := range d.Hist {
		d.N += c
	}
	d.P50, d.P90, d.P99 = d.quantile(bounds, .5), d.quantile(bounds, .9), d.quantile(bounds, .99)
}

// AuthCount counts requests by whether the serving rule carried an auth filter.
type AuthCount struct {
	Protected int64 `json:"protected"`
	Open      int64 `json:"open"`
}

// Endpoint is everything observed about one method and path template.
type Endpoint struct {
	Method        string           `json:"method"`
	Path          string           `json:"path"`
	Count         int64            `json:"count"`
	FirstSeen     time.Time        `json:"first_seen"`
	LastSeen      time.Time        `json:"last_seen"`
	Routes        map[string]int64 `json:"routes,omitempty"`
	Backends      map[string]int64 `json:"backends,omitempty"`
	Status        map[string]int64 `json:"status,omitempty"`
	RequestTypes  map[string]int64 `json:"request_content_types,omitempty"`
	ResponseTypes map[string]int64 `json:"response_content_types,omitempty"`
	Query         []string         `json:"query_params,omitempty"`
	Headers       []string         `json:"headers,omitempty"`
	Auth          AuthCount        `json:"auth"`
	Latency       Dist             `json:"latency_ms"`
	RequestBytes  Dist             `json:"request_bytes"`
	ResponseBytes Dist             `json:"response_bytes"`
}

// Key is "METHOD /template".
func (e *Endpoint) Key() string { return e.Method + " " + e.Path }

func (e *Endpoint) finalize() {
	e.Latency.finalize(latencyBounds)
	e.RequestBytes.finalize(byteBounds)
	e.ResponseBytes.finalize(byteBounds)
	sort.Strings(e.Query)
	sort.Strings(e.Headers)
}

// Doc is the inventory document, in memory and on disk.
type Doc struct {
	Schema          string      `json:"schema"`
	Saved           time.Time   `json:"saved"`
	First           time.Time   `json:"first_seen"`
	Last            time.Time   `json:"last_seen"`
	Requests        int64       `json:"requests"`
	MaxEndpoints    int         `json:"max_endpoints"`
	DroppedRequests int64       `json:"dropped_requests,omitempty"` // requests whose new endpoint did not fit
	Endpoints       []*Endpoint `json:"endpoints"`
	Source          string      `json:"source,omitempty"` // gateway or the access log it came from
}

// Finalize recomputes the derived percentiles and puts the endpoints in order.
func (d *Doc) Finalize() {
	for _, e := range d.Endpoints {
		e.finalize()
	}
	sort.Slice(d.Endpoints, func(i, j int) bool {
		a, b := d.Endpoints[i], d.Endpoints[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Method < b.Method
	})
}

// ParseDoc decodes and validates an inventory file.
func ParseDoc(b []byte) (*Doc, error) {
	var d Doc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("not an inventory document: %w", err)
	}
	if d.Schema != InventorySchema {
		return nil, fmt.Errorf("unsupported inventory schema %q (want %s)", d.Schema, InventorySchema)
	}
	for _, e := range d.Endpoints {
		if e == nil || e.Method == "" || !strings.HasPrefix(e.Path, "/") {
			return nil, errors.New("inventory has an endpoint without a method or path")
		}
	}
	d.Finalize()
	return &d, nil
}

// ReadDoc reads an inventory file.
func ReadDoc(path string) (*Doc, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	d, err := ParseDoc(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return d, nil
}

// Obs is one observed request. It carries names and sizes only: no body, no
// header value and no query value.
type Obs struct {
	Method      string
	Path        string // the request path, not yet a template
	QueryNames  []string
	HeaderNames []string
	Status      int
	Route       string
	Backend     string
	ReqType     string // media type of the request body, "" when none
	RespType    string
	ReqBytes    int64 // negative when unknown
	RespBytes   int64
	Latency     time.Duration // negative when unknown
	Protected   bool          // the rule that served it carries an auth filter
	At          time.Time
}

// Learner accumulates an inventory in bounded memory. The zero value is not
// usable; call NewLearner. All methods are safe for concurrent use.
type Learner struct {
	enabled atomic.Bool
	mu      sync.Mutex
	max     int
	eps     map[string]*Endpoint
	fan     map[string]map[string]struct{}
	first   time.Time
	last    time.Time
	reqs    int64
	dropped int64
	dirty   bool
	source  string
}

// NewLearner returns a disabled learner that keeps at most max endpoints
// (0 means DefaultMaxEndpoints).
func NewLearner(max int) *Learner {
	if max <= 0 {
		max = DefaultMaxEndpoints
	}
	return &Learner{max: max, eps: map[string]*Endpoint{}, fan: map[string]map[string]struct{}{}}
}

// Enable turns recording on or off. The accumulated state is kept either way.
func (l *Learner) Enable(on bool) { l.enabled.Store(on) }

// Enabled reports whether Record keeps observations.
func (l *Learner) Enabled() bool { return l.enabled.Load() }

// SetSource names where the observations come from.
func (l *Learner) SetSource(s string) { l.mu.Lock(); l.source = s; l.mu.Unlock() }

// Stats reports sizes for status pages and metrics.
func (l *Learner) Stats() (endpoints int, requests, dropped int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.eps), l.reqs, l.dropped
}

func (l *Learner) guard(parent, seg string) bool {
	set := l.fan[parent]
	if _, ok := set[seg]; ok {
		return true
	}
	if len(set) >= maxFanout {
		return false
	}
	if set == nil {
		if len(l.fan) >= 2*l.max {
			return true // untracked parent: the endpoint cap still bounds memory
		}
		set = map[string]struct{}{}
		l.fan[parent] = set
	}
	set[seg] = struct{}{}
	return true
}

func bump(m *map[string]int64, key string, cap int) {
	if *m == nil {
		*m = map[string]int64{}
	}
	if _, ok := (*m)[key]; !ok && len(*m) >= cap {
		key = otherKey
	}
	(*m)[key]++
}

func addName(set *[]string, n string) {
	if n == "" || len(*set) >= maxNames {
		return
	}
	if len(n) > maxNameLen {
		n = n[:maxNameLen]
	}
	for _, s := range *set {
		if s == n {
			return
		}
	}
	*set = append(*set, n)
}

func normType(ct string) string {
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if len(ct) > 100 || strings.ContainsAny(ct, " \t\"") {
		return ""
	}
	return ct
}

// Record adds one observation. It is a no-op while the learner is disabled.
func (l *Learner) Record(o Obs) {
	if !l.enabled.Load() {
		return
	}
	l.record(o)
}

func (l *Learner) record(o Obs) {
	if o.At.IsZero() {
		o.At = time.Now()
	}
	method := strings.ToUpper(o.Method)
	if method == "" || len(method) > 16 {
		method = "OTHER"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs++
	if l.first.IsZero() || o.At.Before(l.first) {
		l.first = o.At
	}
	if o.At.After(l.last) {
		l.last = o.At
	}
	tpl := buildTemplate(o.Path, l.guard)
	key := method + " " + tpl
	e := l.eps[key]
	if e == nil {
		if len(l.eps) >= l.max {
			l.dropped++
			return
		}
		e = &Endpoint{Method: method, Path: tpl, FirstSeen: o.At}
		l.eps[key] = e
	}
	l.dirty = true
	e.Count++
	if o.At.Before(e.FirstSeen) {
		e.FirstSeen = o.At
	}
	if o.At.After(e.LastSeen) {
		e.LastSeen = o.At
	}
	if o.Route != "" {
		bump(&e.Routes, o.Route, maxKeys)
	}
	if o.Backend != "" {
		bump(&e.Backends, o.Backend, maxKeys)
	}
	if o.Status > 0 {
		bump(&e.Status, fmt.Sprint(o.Status), maxStatus)
	}
	if t := normType(o.ReqType); t != "" {
		bump(&e.RequestTypes, t, maxKeys)
	}
	if t := normType(o.RespType); t != "" {
		bump(&e.ResponseTypes, t, maxKeys)
	}
	for _, n := range o.QueryNames {
		addName(&e.Query, n)
	}
	for _, n := range o.HeaderNames {
		addName(&e.Headers, strings.ToLower(n))
	}
	if o.Protected {
		e.Auth.Protected++
	} else {
		e.Auth.Open++
	}
	if o.Latency >= 0 {
		e.Latency.add(latencyBounds, float64(o.Latency)/float64(time.Millisecond))
	}
	if o.ReqBytes >= 0 {
		e.RequestBytes.add(byteBounds, float64(o.ReqBytes))
	}
	if o.RespBytes >= 0 {
		e.ResponseBytes.add(byteBounds, float64(o.RespBytes))
	}
}

func cloneMap(m map[string]int64) map[string]int64 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneEndpoint(e *Endpoint) *Endpoint {
	c := *e
	c.Routes, c.Backends, c.Status = cloneMap(e.Routes), cloneMap(e.Backends), cloneMap(e.Status)
	c.RequestTypes, c.ResponseTypes = cloneMap(e.RequestTypes), cloneMap(e.ResponseTypes)
	c.Query, c.Headers = append([]string(nil), e.Query...), append([]string(nil), e.Headers...)
	c.Latency.Hist = append([]int64(nil), e.Latency.Hist...)
	c.RequestBytes.Hist = append([]int64(nil), e.RequestBytes.Hist...)
	c.ResponseBytes.Hist = append([]int64(nil), e.ResponseBytes.Hist...)
	return &c
}

// Snapshot returns a deep copy of the inventory.
func (l *Learner) Snapshot() *Doc {
	l.mu.Lock()
	defer l.mu.Unlock()
	d := &Doc{Schema: InventorySchema, Saved: time.Now().UTC(), First: l.first, Last: l.last, Requests: l.reqs,
		MaxEndpoints: l.max, DroppedRequests: l.dropped, Source: l.source, Endpoints: make([]*Endpoint, 0, len(l.eps))}
	for _, e := range l.eps {
		d.Endpoints = append(d.Endpoints, cloneEndpoint(e))
	}
	d.Finalize()
	return d
}

// Merge adds a stored inventory to the learner's state (used to resume from a
// file and to combine several logs). Endpoints beyond the cap are dropped.
func (l *Learner) Merge(d *Doc) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs += d.Requests
	l.dropped += d.DroppedRequests
	if !d.First.IsZero() && (l.first.IsZero() || d.First.Before(l.first)) {
		l.first = d.First
	}
	if d.Last.After(l.last) {
		l.last = d.Last
	}
	for _, in := range d.Endpoints {
		key := in.Key()
		e := l.eps[key]
		if e == nil {
			if len(l.eps) >= l.max {
				l.dropped += in.Count
				continue
			}
			e = &Endpoint{Method: in.Method, Path: in.Path, FirstSeen: in.FirstSeen}
			l.eps[key] = e
			l.noteFan(in.Path)
		}
		e.Count += in.Count
		if !in.FirstSeen.IsZero() && (e.FirstSeen.IsZero() || in.FirstSeen.Before(e.FirstSeen)) {
			e.FirstSeen = in.FirstSeen
		}
		if in.LastSeen.After(e.LastSeen) {
			e.LastSeen = in.LastSeen
		}
		mergeMap(&e.Routes, in.Routes, maxKeys)
		mergeMap(&e.Backends, in.Backends, maxKeys)
		mergeMap(&e.Status, in.Status, maxStatus)
		mergeMap(&e.RequestTypes, in.RequestTypes, maxKeys)
		mergeMap(&e.ResponseTypes, in.ResponseTypes, maxKeys)
		for _, n := range in.Query {
			addName(&e.Query, n)
		}
		for _, n := range in.Headers {
			addName(&e.Headers, n)
		}
		e.Auth.Protected += in.Auth.Protected
		e.Auth.Open += in.Auth.Open
		e.Latency.merge(&in.Latency, latencyBounds)
		e.RequestBytes.merge(&in.RequestBytes, byteBounds)
		e.ResponseBytes.merge(&in.ResponseBytes, byteBounds)
	}
	l.dirty = true
}

func mergeMap(dst *map[string]int64, src map[string]int64, cap int) {
	for _, k := range sortedKeys(src) {
		if *dst == nil {
			*dst = map[string]int64{}
		}
		key := k
		if _, ok := (*dst)[k]; !ok && len(*dst) >= cap {
			key = otherKey
		}
		(*dst)[key] += src[k]
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// noteFan re-learns the literal children of a loaded template so the fan-out
// rule keeps working after a restart.
func (l *Learner) noteFan(tpl string) {
	segs := SplitPath(tpl)
	parent := ""
	for _, s := range segs {
		if s != VarSegment && s != "**" {
			set := l.fan[parent]
			if set == nil && len(l.fan) < 2*l.max {
				set = map[string]struct{}{}
				l.fan[parent] = set
			}
			if set != nil && len(set) < maxFanout {
				set[s] = struct{}{}
			}
		}
		parent += "/" + s
	}
}

// Dirty reports whether state changed since the last MarkSaved.
func (l *Learner) Dirty() bool { l.mu.Lock(); defer l.mu.Unlock(); return l.dirty }

// SaveFile writes the inventory atomically (temp file, then rename) with
// mode 0600 and clears the dirty flag.
func (l *Learner) SaveFile(path string) error {
	l.mu.Lock()
	l.dirty = false
	l.mu.Unlock()
	if err := WriteDoc(path, l.Snapshot()); err != nil {
		l.mu.Lock()
		l.dirty = true
		l.mu.Unlock()
		return err
	}
	return nil
}

// WriteDoc writes an inventory document atomically.
func WriteDoc(path string, d *Doc) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".setura-inventory-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// LoadFile merges a stored inventory into the learner. A missing file is not
// an error. It reports how many endpoints were read.
func (l *Learner) LoadFile(path string) (int, error) {
	d, err := ReadDoc(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	l.Merge(d)
	l.mu.Lock()
	l.dirty = false
	l.mu.Unlock()
	return len(d.Endpoints), nil
}
