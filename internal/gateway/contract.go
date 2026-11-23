package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zyvorai/zyvor-setura-gateway/internal/contract"
)

// ContractKey is the route annotation (and the rule field) that sets the
// enforcement mode of a route: off, monitor or block. It overrides
// --contract-enforce. See docs/contract.md.
const ContractKey = "setura.zyvor.dev/contract"

// Contract enforcement modes.
const (
	ContractOff     = "off"
	ContractMonitor = "monitor"
	ContractBlock   = "block"
)

const defaultContractInterval = 5 * time.Second

// ValidContractMode reports whether m is "", off, monitor or block.
func ValidContractMode(m string) bool {
	switch m {
	case "", ContractOff, ContractMonitor, ContractBlock:
		return true
	}
	return false
}

// annotateContract gives each rule without its own mode the route annotation
// setura.zyvor.dev/contract.rule-N, else setura.zyvor.dev/contract.
func annotateContract(rules []Rule, ann map[string]string) {
	for i := range rules {
		if rules[i].Contract != "" {
			continue
		}
		if v, ok := ann[fmt.Sprintf("%s.rule-%d", ContractKey, i+1)]; ok {
			rules[i].Contract = strings.TrimSpace(v)
		} else if v, ok := ann[ContractKey]; ok {
			rules[i].Contract = strings.TrimSpace(v)
		}
	}
}

// contractState is the learner and the enforcement spec of one server.
type contractState struct {
	learn     *contract.Learner
	learnFile string
	specFile  string
	mode      string // default enforcement mode from --contract-enforce
	spec      atomic.Pointer[contract.Spec]
	specStamp string // size and mtime of the loaded spec file
	specErr   atomic.Value

	mu      sync.Mutex
	unknown map[[3]string]int64 // route, reason, mode

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func (s *Server) initContract() {
	o := &s.opts
	c := &contractState{learn: contract.NewLearner(o.LearnMax), learnFile: o.LearnFile, specFile: o.ContractSpec, mode: o.ContractEnforce,
		unknown: map[[3]string]int64{}, stop: make(chan struct{}), done: make(chan struct{})}
	s.contract = c
	c.learn.SetSource("gateway")
	if c.learnFile != "" {
		n, err := c.learn.LoadFile(c.learnFile)
		switch {
		case err != nil:
			s.diag("learn: starting empty: %v", err)
		case n > 0:
			s.diag("learn: resumed %d endpoints from %s", n, c.learnFile)
		}
		c.learn.Enable(true)
	}
	if c.specFile != "" {
		s.reloadSpec(true)
	}
	iv := o.ContractInterval
	if iv <= 0 {
		iv = defaultContractInterval
	}
	go func() {
		defer close(c.done)
		tk := time.NewTicker(iv)
		defer tk.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-tk.C:
				s.contractTick()
			}
		}
	}()
}

func statStamp(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d/%d", st.Size(), st.ModTime().UnixNano())
}

// reloadSpec (re)reads the spec file when it changed. A file that no longer
// parses keeps the previous spec in force.
func (s *Server) reloadSpec(force bool) {
	c := s.contract
	if c.specFile == "" {
		return
	}
	stamp := statStamp(c.specFile)
	if !force && stamp == c.specStamp {
		return
	}
	c.specStamp = stamp
	sp, err := contract.LoadSpecFile(c.specFile)
	if err != nil {
		c.specErr.Store(err.Error())
		s.diag("contract: keeping the previous spec: %v", err)
		return
	}
	c.specErr.Store("")
	c.spec.Store(sp)
	s.diag("contract: loaded %s (%d operations)", c.specFile, len(sp.Ops))
}

// contractTick saves the inventory when it changed and reloads a changed spec.
func (s *Server) contractTick() {
	c := s.contract
	if c.learnFile != "" && c.learn.Dirty() {
		if err := c.learn.SaveFile(c.learnFile); err != nil {
			s.diag("learn: write %s: %v", c.learnFile, err)
		}
	}
	s.reloadSpec(false)
}

func (s *Server) closeContract() {
	c := s.contract
	if c == nil {
		return
	}
	c.once.Do(func() { close(c.stop) })
	<-c.done
	if c.learnFile != "" && c.learn.Dirty() {
		if err := c.learn.SaveFile(c.learnFile); err != nil {
			s.diag("learn: write %s: %v", c.learnFile, err)
		}
	}
}

// noisyHeaders are request headers that say nothing about an API's contract.
var noisyHeaders = map[string]bool{"host": true, "user-agent": true, "accept-encoding": true, "accept-language": true, "connection": true,
	"content-length": true, "content-type": true, "transfer-encoding": true, "te": true, "via": true, "origin": true, "referer": true,
	"cache-control": true, "accept": true, "pragma": true, "dnt": true, "expect": true, "traceparent": true, "tracestate": true, "x-request-id": true,
	"if-none-match": true, "if-modified-since": true, "upgrade-insecure-requests": true, "upgrade": true}

func learnableHeader(k string) bool {
	k = strings.ToLower(k)
	return !noisyHeaders[k] && !strings.HasPrefix(k, "sec-") && !strings.HasPrefix(k, "x-forwarded-") && !strings.HasPrefix(k, "x-setura-") && !strings.HasPrefix(k, "x-b3-")
}

// queryNames lists the parameter names of a raw query string, never values.
func queryNames(raw string) []string {
	var out []string
	for raw != "" && len(out) < 64 {
		var kv string
		kv, raw, _ = strings.Cut(raw, "&")
		k, _, _ := strings.Cut(kv, "=")
		if u, err := unescapeQuery(k); err == nil {
			k = u
		}
		if k != "" {
			out = append(out, k)
		}
	}
	return out
}

func unescapeQuery(s string) (string, error) { return url.QueryUnescape(s) }

// requestHeaderNames lists the learnable request header names. It runs before
// auth filters, which remove the credential headers they consume.
func requestHeaderNames(r *http.Request) []string {
	var out []string
	for k := range r.Header {
		if learnableHeader(k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// learnRequest feeds one finished request to the learner: method, path,
// parameter and header names, status, content types, sizes and latency.
func (s *Server) learnRequest(rec *recorder, r *http.Request, st *reqState, status int, d time.Duration) {
	o := contract.Obs{Method: r.Method, Path: r.URL.Path, QueryNames: queryNames(r.URL.RawQuery), Status: status, Route: st.route, Backend: st.backend,
		ReqType: r.Header.Get("Content-Type"), RespType: rec.Header().Get("Content-Type"), ReqBytes: -1, RespBytes: rec.bytesOut(),
		Latency: d, Protected: st.authed}
	if st.in != nil {
		o.ReqBytes = st.in.n.Load()
	}
	o.HeaderNames = st.hdrNames
	s.contract.learn.Record(o)
}

// ruleAuthed reports whether the rule runs an auth filter: an enabled
// setura.zyvor.dev/auth policy or an ExternalAuth filter.
func ruleAuthed(cr *CRule) bool {
	if a := cr.Rule.Auth; a != nil && a.c != nil && a.c.enabled {
		return true
	}
	return hasExternalAuth(cr.Rule.Filters)
}

// contractMode is the effective enforcement mode of a rule.
func (s *Server) contractMode(rule *Rule) string {
	if rule != nil && rule.Contract != "" {
		return rule.Contract
	}
	return s.contract.mode
}

// contractGate checks the request against the loaded spec. It returns true
// when it answered the request (block mode). In monitor mode it only counts
// and notes the violation for the access log.
func (s *Server) contractGate(w http.ResponseWriter, r *http.Request, st *reqState, rule *Rule) bool {
	mode := s.contractMode(rule)
	if mode == "" || mode == ContractOff {
		return false
	}
	sp := s.contract.spec.Load()
	if sp == nil {
		return false
	}
	v := sp.Check(r.Method, r.URL.Path)
	if v.OK {
		return false
	}
	c := s.contract
	c.mu.Lock()
	c.unknown[[3]string{st.route, v.Reason, mode}]++
	c.mu.Unlock()
	st.contract, st.contractMode = v.Reason, mode
	if mode != ContractBlock {
		return false
	}
	st.contractBlocked = true
	st.errMsg = "contract: " + v.Reason
	if v.Reason == "unknown_method" {
		w.Header().Set("Allow", strings.Join(v.Allow, ", "))
		plain(w, http.StatusMethodNotAllowed, "method not allowed by the API contract")
		return true
	}
	plain(w, http.StatusNotFound, "endpoint is not in the API contract")
	return true
}

func (s *Server) writeContractMetrics(w io.Writer) {
	c := s.contract
	head := func(name, typ, help string) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	head("setura_gateway_contract_unknown_total", "counter", "Requests whose method and path are not in the loaded OpenAPI document, per route, reason (unknown_endpoint, unknown_method) and mode (monitor, block).")
	c.mu.Lock()
	keys := make([][3]string, 0, len(c.unknown))
	for k := range c.unknown {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		for n := 0; n < 3; n++ {
			if keys[i][n] != keys[j][n] {
				return keys[i][n] < keys[j][n]
			}
		}
		return false
	})
	for _, k := range keys {
		fmt.Fprintf(w, "setura_gateway_contract_unknown_total{route=\"%s\",reason=\"%s\",mode=\"%s\"} %d\n", promLabel(k[0]), k[1], k[2], c.unknown[k])
	}
	c.mu.Unlock()
	ops := 0
	if sp := c.spec.Load(); sp != nil {
		ops = len(sp.Ops)
	}
	head("setura_gateway_contract_spec_operations", "gauge", "Operations in the loaded OpenAPI document (0 when none is loaded).")
	fmt.Fprintf(w, "setura_gateway_contract_spec_operations %d\n", ops)
	eps, reqs, dropped := c.learn.Stats()
	head("setura_gateway_learn_endpoints", "gauge", "Distinct method and path templates in the learned inventory.")
	fmt.Fprintf(w, "setura_gateway_learn_endpoints %d\n", eps)
	head("setura_gateway_learn_requests_total", "counter", "Requests recorded by the endpoint learner.")
	fmt.Fprintf(w, "setura_gateway_learn_requests_total %d\n", reqs)
	head("setura_gateway_learn_dropped_total", "counter", "Requests not recorded because the inventory was full.")
	fmt.Fprintf(w, "setura_gateway_learn_dropped_total %d\n", dropped)
}

// ContractStatus is the /contract/status document.
type ContractStatus struct {
	Learning    LearnStatus   `json:"learning"`
	Enforcement EnforceStatus `json:"enforcement"`
}

// LearnStatus describes the endpoint learner.
type LearnStatus struct {
	Enabled         bool   `json:"enabled"`
	File            string `json:"file,omitempty"`
	Endpoints       int    `json:"endpoints"`
	Requests        int64  `json:"requests"`
	DroppedRequests int64  `json:"dropped_requests"`
	MaxEndpoints    int    `json:"max_endpoints"`
}

// EnforceStatus describes contract enforcement.
type EnforceStatus struct {
	Spec       string           `json:"spec,omitempty"`
	Operations int              `json:"operations"`
	Mode       string           `json:"mode,omitempty"`
	Error      string           `json:"error,omitempty"`
	Unknown    map[string]int64 `json:"unknown,omitempty"` // route/reason/mode -> requests
}

// ContractStatus reports learning and enforcement state.
func (s *Server) ContractStatus() ContractStatus {
	c := s.contract
	eps, reqs, dropped := c.learn.Stats()
	st := ContractStatus{Learning: LearnStatus{Enabled: c.learn.Enabled(), File: c.learnFile, Endpoints: eps, Requests: reqs,
		DroppedRequests: dropped, MaxEndpoints: s.opts.LearnMax}}
	if st.Learning.MaxEndpoints <= 0 {
		st.Learning.MaxEndpoints = contract.DefaultMaxEndpoints
	}
	st.Enforcement = EnforceStatus{Spec: c.specFile, Mode: c.mode}
	if sp := c.spec.Load(); sp != nil {
		st.Enforcement.Operations = len(sp.Ops)
	}
	if e, _ := c.specErr.Load().(string); e != "" {
		st.Enforcement.Error = e
	}
	c.mu.Lock()
	if len(c.unknown) > 0 {
		st.Enforcement.Unknown = map[string]int64{}
		for k, v := range c.unknown {
			st.Enforcement.Unknown[k[0]+"/"+k[1]+"/"+k[2]] = v
		}
	}
	c.mu.Unlock()
	return st
}

// Inventory returns the learned inventory.
func (s *Server) Inventory() *contract.Doc { return s.contract.learn.Snapshot() }

// SetLearning turns the endpoint learner on or off at runtime.
func (s *Server) SetLearning(on bool) { s.contract.learn.Enable(on) }

func (s *Server) handleContractLearn(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var on bool
		if v := r.URL.Query().Get("enabled"); v != "" {
			switch v {
			case "true", "1", "on":
				on = true
			case "false", "0", "off":
			default:
				plain(w, http.StatusBadRequest, "enabled wants true or false")
				return
			}
		} else {
			var body struct {
				Enabled *bool `json:"enabled"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || body.Enabled == nil {
				plain(w, http.StatusBadRequest, `give ?enabled=true|false or a JSON body {"enabled":true}`)
				return
			}
			on = *body.Enabled
		}
		s.SetLearning(on)
	} else if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		plain(w, http.StatusMethodNotAllowed, "use GET or POST")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(s.ContractStatus().Learning)
}

// uiInventory serves the dashboard's API inventory page.
func (s *Server) uiInventory() any {
	return map[string]any{"status": s.ContractStatus(), "inventory": s.Inventory()}
}
