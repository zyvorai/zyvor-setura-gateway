package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const aiMaxResponse = 32 << 20

// aiReq is what one AI request knows about itself: what it asked for, who it
// is, what it was charged and what it used. The access log and the counters
// are filled from it when the request ends.
type aiReq struct {
	c        *compiledAI
	shape    string
	model    string
	provider string
	ident    string
	stream   bool
	injected bool // the gateway added stream_options.include_usage

	raw     []byte         // request body as it goes upstream (after PII redaction and injection)
	body    map[string]any // decoded form of raw, for model renames
	estIn   int64
	maxOut  int64
	rsv     []*aiReservation
	u       aiUsage // usage to account (real, or estimated when the provider reported none)
	outcome string  // ok, upstream_error, cache_hit, budget_denied, pii_blocked or rejected
	cache   string  // "", HIT or MISS
	piiRes  piiResult
	piiAct  string
	done    bool
	cost    float64
	tried   []aiTry
}

type aiTry struct {
	Provider string `json:"provider"`
	Status   int    `json:"status,omitempty"`
	Reason   string `json:"reason"`
}

func (a *aiReq) keyLabel() string {
	if a.ident == "" {
		return "anonymous"
	}
	return a.ident
}

// aiIdentity resolves who the request belongs to from the verified credential
// (or, for header identities, from the request).
func aiIdentity(c *compiledAI, r *http.Request, st *reqState) string {
	var v string
	switch c.identKind {
	case "header":
		v = strings.TrimSpace(r.Header.Get(c.identName))
	case "apikey":
		if st.authRes != nil && st.authRes.Method == "apikey" {
			v = st.authRes.Subject
		}
	case "claim":
		if st.authRes != nil && st.authRes.claims != nil {
			if cv, ok := claimAt(st.authRes.claims, c.identName); ok {
				v = claimHeaderValue(cv)
			}
		}
	default:
		if st.authRes != nil {
			v = st.authRes.Subject
		}
	}
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

// aiError writes an error in the shape the client's SDK parses: OpenAI's
// {"error":{...}} or Anthropic's {"type":"error","error":{...}}.
func (a *aiReq) writeError(w http.ResponseWriter, status int, typ, code, msg string, extra map[string]any, retryAfter int) {
	e := map[string]any{"message": msg, "type": typ, "code": code}
	for k, v := range extra {
		e[k] = v
	}
	doc := map[string]any{"error": e}
	if a.shape == shapeMessages {
		doc["type"] = "error"
	} else {
		e["param"] = nil
	}
	w.Header().Set("Content-Type", "application/json")
	if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(doc)
}

// marshalBody encodes a request body without HTML escaping.
func marshalBody(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// serveAI answers a request on an AI rule: policy checks, then the providers.
func (s *Server) serveAI(w http.ResponseWriter, r *http.Request, st *reqState, rule *CRule) {
	c := rule.AI
	a := &aiReq{c: c, outcome: "rejected"}
	st.ai = a
	defer s.aiFinish(st, a)
	fail := func(status int, typ, code, msg string, extra map[string]any, outcome string, retry int) {
		a.outcome = outcome
		st.errMsg = c.scrub(code + ": " + msg)
		shapeResponse(w.Header(), r, rule.Rule.Filters)
		a.writeError(w, status, typ, code, msg, extra, retry)
	}

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "invalid_request_error", "method_not_allowed", "AI routes take POST requests", nil, "rejected", 0)
		return
	}
	a.shape, _ = aiShape(r.URL.Path)
	if a.shape == "" {
		fail(http.StatusNotFound, "invalid_request_error", "unsupported_path", "this AI route serves /chat/completions, /completions, /embeddings and /messages", nil, "rejected", 0)
		return
	}
	_, rel := aiShape(r.URL.Path)

	if rule.Timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), rule.Timeout)
		defer cancel()
		r = r.WithContext(ctx)
	}

	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, c.maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(http.StatusRequestEntityTooLarge, "invalid_request_error", "request_too_large", fmt.Sprintf("the request body exceeds %d bytes", c.maxBody), nil, "rejected", 0)
		} else {
			fail(http.StatusBadRequest, "invalid_request_error", "unreadable_body", "cannot read the request body", nil, "rejected", 0)
		}
		return
	}
	var body map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&body) != nil || body == nil {
		fail(http.StatusBadRequest, "invalid_request_error", "invalid_json", "the request body is not a JSON object", nil, "rejected", 0)
		return
	}
	a.model, _ = body["model"].(string)
	if a.model == "" {
		fail(http.StatusBadRequest, "invalid_request_error", "model_required", "the request needs a model", nil, "rejected", 0)
		return
	}
	if len(c.p.AllowedModels) > 0 && !modelMatches(c.p.AllowedModels, a.model) {
		fail(http.StatusForbidden, "invalid_request_error", "model_not_allowed", fmt.Sprintf("model %q is not allowed on this route", a.model), nil, "rejected", 0)
		return
	}
	a.stream, _ = body["stream"].(bool)

	a.ident = aiIdentity(c, r, st)
	if c.p.Budget != nil && a.ident == "" {
		fail(http.StatusUnauthorized, "authentication_error", "identity_required",
			"this route enforces token budgets per identity and the request carries none ("+identityHint(c)+")", nil, "rejected", 0)
		return
	}

	// PII runs before the cache and the providers: neither ever sees the original text.
	a.raw = raw
	if c.pii != nil {
		res, changed := c.pii.apply(body)
		if n := res.total(); n > 0 {
			a.piiRes, a.piiAct = res, map[string]string{PIIRedact: "redacted", PIIBlock: "blocked", PIIReport: "reported"}[c.pii.mode]
			s.aiCount(c.key, func(sr *aiRouteStat) {
				for rule, k := range res {
					sr.pii[[2]string{rule, a.piiAct}] += int64(k)
				}
			})
			if c.pii.mode == PIIBlock {
				fail(http.StatusBadRequest, "invalid_request_error", "pii_detected",
					"the request was blocked because the prompt contains personal data ("+res.summary()+")", map[string]any{"findings": map[string]int(res)}, "pii_blocked", 0)
				return
			}
		}
		if changed {
			a.raw = marshalBody(body)
		}
	}
	a.body = body

	if (a.shape == shapeChat || a.shape == shapeCompletion) && a.stream && c.inject {
		so, _ := body["stream_options"].(map[string]any)
		if so == nil {
			so = map[string]any{}
		}
		if v, _ := so["include_usage"].(bool); !v {
			so["include_usage"], body["stream_options"], a.injected = true, so, true
			a.raw = marshalBody(body)
		}
	}

	// Cache lookup: a hit is answered without a provider and without spending budget.
	var cache *aiCache
	var ckey string
	if c.cache != nil && (!a.stream || c.cache.stream) {
		cache = s.aiCacheFor(c)
		ckey = aiCacheKey(c, a.shape, a.ident, bodyForKey(body, a))
		if e := cache.get(ckey, s.aiNow()); e != nil {
			s.aiServeHit(w, r, st, rule, a, e)
			return
		}
		a.cache = "MISS"
		s.aiCount(c.key, func(sr *aiRouteStat) { sr.cacheMiss++ })
	}

	// Budget: reserve prompt estimate plus the completion allowance, settle with the real usage.
	a.estIn = estimateTokens(body)
	a.maxOut = maxTokensOf(body, a.shape, c.defMax)
	if c.p.Budget != nil {
		var cost float64
		if p, ok := s.aiPrice(c, a.model); ok {
			cost = p.cost(a.estIn, a.maxOut)
		}
		rsv, denied := s.aiReserve(c, a.ident, a.estIn+a.maxOut, cost, s.aiNow())
		if denied != nil {
			s.aiCount(c.key, func(sr *aiRouteStat) { sr.denied[denied.Limit]++ })
			msg := fmt.Sprintf("token budget exceeded: %s limit %s is %s with %s in use, and this request may need %s (prompt about %d plus up to %d completion tokens); retry in %d seconds",
				denied.Scope, denied.Limit, trimFloat(denied.Max), trimFloat(denied.Used), trimFloat(denied.Requested), a.estIn, a.maxOut, denied.RetryAfter)
			fail(http.StatusTooManyRequests, "rate_limit_error", "token_budget_exceeded", msg, map[string]any{"budget": denied}, "budget_denied", denied.RetryAfter)
			return
		}
		a.rsv = rsv
	}

	order := s.aiOrder(c, a.shape, a.model, s.res.now())
	if len(order) == 0 {
		fail(http.StatusNotFound, "invalid_request_error", "no_provider", fmt.Sprintf("no provider on this route serves %q on the %s API", a.model, a.shape), nil, "rejected", 0)
		return
	}
	limit := min(len(order), c.maxAttempts)
	rt := s.backendTransport(c.b)
	for i, p := range order[:limit] {
		if r.Context().Err() != nil {
			a.outcome, st.errMsg = "rejected", "client closed the request"
			return
		}
		more := i+1 < limit
		out, err := s.aiRequest(r, st, rule, a, p, rel)
		if err != nil {
			fail(http.StatusInternalServerError, "api_error", "request_build_failed", err.Error(), nil, "upstream_error", 0)
			return
		}
		actx, cancel := context.WithCancel(r.Context())
		timer := time.AfterFunc(p.timeout, cancel)
		rctx, tr := st.up.begin(actx)
		health := c.b.state(p.ep, s.res.now())
		resp, err := rt.RoundTrip(out.WithContext(rctx))
		st.up.end(tr, p.ep, health, resp, err)
		st.noteUpstream()
		st.backend = "ai:" + p.Name
		clientGone := r.Context().Err() != nil
		timedOut := err != nil && !clientGone && actx.Err() != nil
		bad := err != nil || c.failsOver(resp.StatusCode)
		if !clientGone {
			s.res.observe(c.b, p.ep, bad, s.res.now())
		}
		try := aiTry{Provider: p.Name}
		switch {
		case err != nil:
			try.Reason = c.scrub(err.Error())
			if timedOut {
				try.Reason = fmt.Sprintf("no response within %s", p.timeout)
			}
		case bad:
			try.Status, try.Reason = resp.StatusCode, "upstream answered "+strconv.Itoa(resp.StatusCode)
		}
		if bad {
			a.tried = append(a.tried, try)
		}
		if clientGone {
			timer.Stop()
			cancel()
			if resp != nil {
				resp.Body.Close()
			}
			a.outcome, st.errMsg = "rejected", "client closed the request"
			return
		}
		if bad && more {
			s.aiCount(c.key, func(sr *aiRouteStat) {
				sr.attempts[[2]string{p.Name, "failover"}]++
				sr.failovers[[2]string{p.Name, order[i+1].Name}]++
			})
			timer.Stop()
			cancel()
			if resp != nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				resp.Body.Close()
			}
			continue
		}
		if err != nil {
			s.aiCount(c.key, func(sr *aiRouteStat) { sr.attempts[[2]string{p.Name, "error"}]++ })
			timer.Stop()
			cancel()
			code, status := "upstream_unavailable", http.StatusBadGateway
			if timedOut || errors.Is(err, context.DeadlineExceeded) {
				code, status = "upstream_timeout", http.StatusGatewayTimeout
			}
			a.outcome = "upstream_error"
			fail(status, "api_error", code, "no provider could serve the request", map[string]any{"attempts": a.tried}, "upstream_error", 0)
			return
		}
		res := "ok"
		if bad {
			res = "error"
		}
		s.aiCount(c.key, func(sr *aiRouteStat) { sr.attempts[[2]string{p.Name, res}]++ })
		a.provider = p.Name
		s.aiRelay(w, r, st, rule, a, p, resp, timer, cancel, cache, ckey)
		return
	}
}

func identityHint(c *compiledAI) string {
	switch c.identKind {
	case "header":
		return "header " + c.identName + " is missing or empty"
	case "claim":
		return "JWT claim " + c.identName + " is missing"
	case "apikey":
		return "no API key matched"
	}
	return "no verified subject"
}

func trimFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// bodyForKey is the body the cache key is made from: what the client asked for
// after PII redaction, without the stream_options the gateway added.
func bodyForKey(body map[string]any, a *aiReq) map[string]any {
	if !a.injected {
		return body
	}
	cp := make(map[string]any, len(body))
	for k, v := range body {
		if k != "stream_options" {
			cp[k] = v
		}
	}
	return cp
}

// failsOver reports whether an upstream status moves the request to the next provider.
func (c *compiledAI) failsOver(status int) bool {
	if c.failStatus != nil {
		return c.failStatus[status]
	}
	return status == http.StatusTooManyRequests || status >= 500
}

// aiOrder lists the providers to try for a request, best first: providers
// that can take traffic before ejected ones, tiers by priority, and within a
// tier a weighted random order (weight 0 providers last: standbys).
func (s *Server) aiOrder(c *compiledAI, shape, model string, now time.Time) []*aiProv {
	typ := shapeProviderType(shape)
	var up, down []*aiProv
	c.b.hmu.Lock()
	for _, p := range c.provs {
		if p.typ != typ || !p.serves(model) {
			continue
		}
		if c.b.up(p.ep, now) {
			up = append(up, p)
		} else {
			down = append(down, p)
		}
	}
	c.b.hmu.Unlock()
	return append(s.aiTiers(up), s.aiTiers(down)...)
}

func (s *Server) aiTiers(ps []*aiProv) []*aiProv {
	var out []*aiProv
	for len(ps) > 0 {
		lo := ps[0].Priority
		for _, p := range ps {
			lo = min(lo, p.Priority)
		}
		var tier, rest []*aiProv
		for _, p := range ps {
			if p.Priority == lo {
				tier = append(tier, p)
			} else {
				rest = append(rest, p)
			}
		}
		for len(tier) > 0 {
			total := 0
			for _, p := range tier {
				total += p.weight
			}
			pick := 0
			if total > 0 {
				n := s.intn(total)
				for i, p := range tier {
					if n < p.weight {
						pick = i
						break
					}
					n -= p.weight
				}
			} // all remaining weights are 0: keep configured order
			out = append(out, tier[pick])
			tier = append(tier[:pick:pick], tier[pick+1:]...)
		}
		ps = rest
	}
	return out
}

// upstream request headers the gateway forwards from the client.
var aiForwardHeaders = []string{"Accept", "User-Agent", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta", "Idempotency-Key"}

// aiRequest builds the request for one provider. Whatever credential the
// client sent is gone: only the headers above are forwarded, and the provider
// credential is set last, so it is re-signed on every attempt.
func (s *Server) aiRequest(r *http.Request, st *reqState, rule *CRule, a *aiReq, p *aiProv, rel string) (*http.Request, error) {
	u := *p.base
	u.Path = strings.TrimRight(u.Path, "/") + rel
	u.RawQuery = r.URL.RawQuery
	body := a.raw
	if to, ok := p.ModelMap[a.model]; ok {
		cp := make(map[string]any, len(a.body))
		for k, v := range a.body {
			cp[k] = v
		}
		cp["model"] = to
		body = marshalBody(cp)
	}
	out, err := http.NewRequestWithContext(r.Context(), http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for _, h := range aiForwardHeaders {
		if v := r.Header.Values(h); len(v) > 0 {
			out.Header[http.CanonicalHeaderKey(h)] = append([]string(nil), v...)
		}
	}
	out.Header.Set("Content-Type", "application/json")
	if p.typ == "anthropic" && out.Header.Get("Anthropic-Version") == "" {
		out.Header.Set("Anthropic-Version", "2023-06-01")
	}
	for _, f := range rule.Rule.Filters {
		if f.Type == "RequestHeaderModifier" && f.RequestHeaderModifier != nil {
			applyHeaderMod(out.Header, f.RequestHeaderModifier)
		}
	}
	for k, v := range p.Headers {
		out.Header.Set(k, v)
	}
	injectTrace(out, st)
	if name, val := p.credential(); name != "" {
		out.Header.Set(name, val)
	}
	return out, nil
}

// respHeaderSkip are upstream response headers the gateway does not relay.
var respHeaderSkip = map[string]bool{"Content-Length": true, "Content-Encoding": true, "Set-Cookie": true, "Connection": true,
	"Keep-Alive": true, "Transfer-Encoding": true, "Trailer": true, "Upgrade": true, "Proxy-Authenticate": true}

func aiCopyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if respHeaderSkip[k] || strings.HasPrefix(k, "X-Setura-") {
			continue
		}
		dst[k] = append([]string(nil), vs...)
	}
}

// aiRelay sends the provider's response to the client and takes its usage.
func (s *Server) aiRelay(w http.ResponseWriter, r *http.Request, st *reqState, rule *CRule, a *aiReq, p *aiProv, resp *http.Response,
	timer *time.Timer, cancel context.CancelFunc, cache *aiCache, ckey string) {
	c := a.c
	defer cancel()
	defer timer.Stop()
	defer resp.Body.Close()
	h := w.Header()
	aiCopyHeaders(h, resp.Header)
	h.Set(AIProviderHeader, p.Name)
	h.Set(BackendHeader, p.Name)
	h.Del(RequestIDHeader)
	h.Set(RequestIDHeader, st.reqID)
	if a.cache != "" {
		h.Set(AICacheHeader, a.cache)
	}
	shapeResponse(h, r, rule.Rule.Filters)
	ok := resp.StatusCode < 400
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		timer.Stop() // a stream may run as long as it likes; the timeout bounded the headers
		s.aiStream(w, r, st, a, p, resp, cache, ckey)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, aiMaxResponse+1))
	if err != nil || len(body) > aiMaxResponse {
		a.outcome = "upstream_error"
		st.errMsg = "reading the provider response failed"
		h.Del("Content-Type")
		a.writeError(w, http.StatusBadGateway, "api_error", "upstream_response_failed", "the provider response could not be read in full", map[string]any{"attempts": a.tried}, 0)
		return
	}
	if !ok {
		body = []byte(c.scrub(string(body))) // an error body that quotes the key must not reach the client
		a.outcome = "upstream_error"
		st.errMsg = c.scrub("provider " + p.Name + " answered " + strconv.Itoa(resp.StatusCode))
	} else {
		a.outcome = "ok"
		u := usageFromJSON(body)
		if !u.Have {
			u = aiUsage{In: a.estIn, Out: min(a.maxOut, int64(len(body))/4), Model: u.Model, Estimated: true}
		}
		a.u = u
		if cache != nil && a.cache == "MISS" && resp.StatusCode == http.StatusOK && json.Valid(body) {
			ev := s.aiCachePut(c, cache, &aiCacheEntry{key: ckey, status: resp.StatusCode, ctype: ct, body: body, usage: a.u, provider: p.Name})
			_ = ev
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (s *Server) aiCachePut(c *compiledAI, cache *aiCache, e *aiCacheEntry) int {
	ev := cache.put(e, s.aiNow())
	if ev > 0 {
		s.aiCount(c.key, func(sr *aiRouteStat) { sr.cacheEvct += int64(ev) })
	}
	return ev
}

// aiStream relays a server-sent event stream event by event, flushing each,
// and follows the usage the provider reports on the way.
func (s *Server) aiStream(w http.ResponseWriter, r *http.Request, st *reqState, a *aiReq, p *aiProv, resp *http.Response, cache *aiCache, ckey string) {
	c := a.c
	if a.cache == "" || cache == nil {
		w.Header().Del(AICacheHeader)
	}
	w.WriteHeader(resp.StatusCode)
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
	flush()
	var keep *bytes.Buffer
	if cache != nil && a.cache == "MISS" && resp.StatusCode == http.StatusOK {
		keep = &bytes.Buffer{}
	}
	var sse sseUsage
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var ev [][]byte
	var data []byte
	clientErr := false
	emit := func() bool {
		if len(ev) == 0 {
			return true
		}
		drop := sse.event(data) && a.injected
		if !drop {
			for _, l := range ev {
				if _, err := w.Write(l); err != nil {
					return false
				}
				w.Write([]byte("\n"))
				if keep != nil {
					if int64(keep.Len()) > c.cache.maxEntryBytes {
						keep = nil
					} else {
						keep.Write(l)
						keep.WriteByte('\n')
					}
				}
			}
			w.Write([]byte("\n"))
			if keep != nil {
				keep.WriteByte('\n')
			}
			flush()
		}
		ev, data = ev[:0], data[:0]
		return true
	}
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			if !emit() {
				clientErr = true
				break
			}
			continue
		}
		ev = append(ev, append([]byte(nil), line...))
		if d, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(d, []byte(" "))...)
		}
	}
	scanErr := sc.Err()
	if !clientErr {
		emit()
	}
	u := sse.u
	if ok := resp.StatusCode < 400; ok {
		a.outcome = "ok"
		if !u.Have {
			u.In, u.Out, u.Estimated = a.estIn, min(a.maxOut, sse.chars/4), true
		}
		a.u = u
		if clientErr || scanErr != nil {
			st.errMsg = "stream ended early"
		}
		if keep != nil && !clientErr && scanErr == nil {
			s.aiCachePut(c, cache, &aiCacheEntry{key: ckey, status: resp.StatusCode, ctype: resp.Header.Get("Content-Type"), body: keep.Bytes(), usage: a.u, provider: p.Name, stream: true})
		}
	} else {
		a.outcome = "upstream_error"
	}
}

// aiServeHit answers from the cache.
func (s *Server) aiServeHit(w http.ResponseWriter, r *http.Request, st *reqState, rule *CRule, a *aiReq, e *aiCacheEntry) {
	a.outcome, a.cache, a.provider = "cache_hit", "HIT", e.provider
	s.aiCount(a.c.key, func(sr *aiRouteStat) { sr.cacheHit++ })
	h := w.Header()
	if e.ctype != "" {
		h.Set("Content-Type", e.ctype)
	}
	h.Set(AICacheHeader, "HIT")
	h.Set(AIProviderHeader, e.provider)
	h.Set(BackendHeader, e.provider)
	h.Set(RequestIDHeader, st.reqID)
	shapeResponse(h, r, rule.Rule.Filters)
	st.backend = "ai:" + e.provider
	w.WriteHeader(e.status)
	w.Write(e.body)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

// aiFinish runs once when the request ends: it settles the budget with the
// real usage and records the counters and the figures the access log shows.
func (s *Server) aiFinish(st *reqState, a *aiReq) {
	if a.done {
		return
	}
	a.done = true
	c := a.c
	u := a.u
	model := a.model
	if u.Model != "" {
		model = u.Model
	}
	var cost float64
	if p, ok := s.aiPrice(c, model); ok {
		cost = p.cost(u.In, u.Out)
	}
	a.cost = cost
	s.aiSettle(a.rsv, u.total(), cost)
	a.u.Model = model
	prov := a.provider
	if prov == "" {
		prov = "none"
	}
	s.aiCount(c.key, func(sr *aiRouteStat) {
		ml := sr.modelLabel(model)
		sr.reqs[[3]string{prov, ml, a.outcome}]++
		if a.outcome == "ok" {
			tk := sr.tokens[[2]string{prov, ml}]
			if tk == nil {
				tk = &aiTok{}
				sr.tokens[[2]string{prov, ml}] = tk
			}
			tk.in, tk.out, tk.cost, tk.reqs = tk.in+u.In, tk.out+u.Out, tk.cost+cost, tk.reqs+1
		}
		kt := sr.keyEntry(a.keyLabel(), s.ai.opts.MaxKeyLabels)
		kt.reqs++
		if a.outcome == "ok" {
			kt.in, kt.out, kt.cost = kt.in+u.In, kt.out+u.Out, kt.cost+cost
		}
	})
}

// fill puts the AI figures of a finished request on its log line. Nil safe.
func (a *aiReq) fill(l *logLine) {
	if a == nil {
		return
	}
	l.AIKey, l.Provider, l.Model = a.keyLabel(), a.provider, a.u.Model
	if l.Model == "" {
		l.Model = a.model
	}
	l.TokensIn, l.TokensOut, l.TokensEstimated = a.u.In, a.u.Out, a.u.Estimated && a.outcome == "ok"
	l.CostEstimate = a.cost
	if a.cache != "" {
		hit := a.cache == "HIT"
		l.CacheHit = &hit
	}
	l.PIIFindings, l.PIIAction = a.piiRes.total(), a.piiAct
}
