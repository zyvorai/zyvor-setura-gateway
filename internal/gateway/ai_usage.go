package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// API shapes an AI route understands.
const (
	shapeChat       = "chat"       // OpenAI /chat/completions
	shapeCompletion = "completion" // OpenAI /completions
	shapeEmbedding  = "embeddings" // OpenAI /embeddings
	shapeMessages   = "messages"   // Anthropic /messages
)

// aiShape identifies the API from the request path suffix, so a route may
// match any prefix ("/llm/v1/chat/completions"). rel is the path below the
// provider's base URL.
func aiShape(path string) (shape, rel string) {
	p := strings.TrimRight(path, "/")
	switch {
	case strings.HasSuffix(p, "/chat/completions"):
		return shapeChat, "/chat/completions"
	case strings.HasSuffix(p, "/embeddings"):
		return shapeEmbedding, "/embeddings"
	case strings.HasSuffix(p, "/completions"):
		return shapeCompletion, "/completions"
	case strings.HasSuffix(p, "/messages"):
		return shapeMessages, "/messages"
	}
	return "", ""
}

// providerType is the provider API family a shape needs.
func shapeProviderType(shape string) string {
	if shape == shapeMessages {
		return "anthropic"
	}
	return "openai"
}

// aiUsage is the token usage of one exchange.
type aiUsage struct {
	In, Out   int64
	Model     string
	Have      bool // the upstream reported usage
	Estimated bool // In and Out are the gateway's own estimate
}

func (u aiUsage) total() int64 { return u.In + u.Out }

// usageFromJSON reads the usage of a non-streamed OpenAI or Anthropic response.
func usageFromJSON(raw []byte) aiUsage {
	var doc struct {
		Model string          `json:"model"`
		Usage json.RawMessage `json:"usage"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return aiUsage{}
	}
	u := aiUsage{Model: doc.Model}
	u.mergeUsage(doc.Usage)
	return u
}

// mergeUsage folds a usage object into u. OpenAI: prompt_tokens and
// completion_tokens. Anthropic: input_tokens, output_tokens and the cache
// token counts, which are input too. Values only ever grow, so the cumulative
// counters of a stream may be merged repeatedly.
func (u *aiUsage) mergeUsage(raw json.RawMessage) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	var loose map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&loose) != nil {
		return
	}
	m := map[string]json.Number{}
	for k, v := range loose {
		if n, ok := v.(json.Number); ok {
			m[k] = n
		}
	}
	num := func(k string) int64 {
		n, err := m[k].Int64()
		if err != nil || n < 0 {
			return 0
		}
		return n
	}
	in, out, total := num("prompt_tokens"), num("completion_tokens"), num("total_tokens")
	if a := num("input_tokens") + num("cache_creation_input_tokens") + num("cache_read_input_tokens"); a > in {
		in = a
	}
	if a := num("output_tokens"); a > out {
		out = a
	}
	if out == 0 && total > in {
		out = total - in // a total only
	}
	if in == 0 && out == 0 && total == 0 {
		return
	}
	if in > u.In {
		u.In = in
	}
	if out > u.Out {
		u.Out = out
	}
	u.Have = true
}

// sseUsage follows a streamed response event by event and collects its usage
// and model: OpenAI's final chunk (stream_options.include_usage) and
// Anthropic's message_start and message_delta events.
type sseUsage struct {
	u       aiUsage
	chars   int64 // bytes of generated text seen, for the estimate when no usage arrives
	dropped int
}

// event is one SSE event's data payload. It returns true for the OpenAI usage
// only chunk (empty choices), which a gateway that injected include_usage
// removes from what the client sees.
func (s *sseUsage) event(data []byte) (usageOnly bool) {
	if len(data) == 0 || bytes.Equal(data, []byte("[DONE]")) {
		return false
	}
	hasUsage := bytes.Contains(data, []byte(`"usage"`))
	hasModel := s.u.Model == "" && bytes.Contains(data, []byte(`"model"`))
	hasText := bytes.Contains(data, []byte(`"content"`)) || bytes.Contains(data, []byte(`"text"`))
	if !hasUsage && !hasModel && !hasText {
		return false
	}
	var d struct {
		Model   string          `json:"model"`
		Usage   json.RawMessage `json:"usage"`
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
			Text string `json:"text"`
		} `json:"choices"`
		Type    string `json:"type"` // anthropic
		Message *struct {
			Model string          `json:"model"`
			Usage json.RawMessage `json:"usage"`
		} `json:"message"`
		Delta *struct {
			Text string `json:"text"`
		} `json:"delta"`
	}
	if json.Unmarshal(data, &d) != nil {
		return false
	}
	if s.u.Model == "" {
		s.u.Model = d.Model
	}
	for _, c := range d.Choices {
		s.chars += int64(len(c.Delta.Content) + len(c.Text))
	}
	if d.Delta != nil {
		s.chars += int64(len(d.Delta.Text))
	}
	if d.Message != nil {
		if s.u.Model == "" {
			s.u.Model = d.Message.Model
		}
		s.u.mergeUsage(d.Message.Usage)
	}
	s.u.mergeUsage(d.Usage)
	return hasUsage && len(d.Usage) > 0 && string(d.Usage) != "null" && d.Choices != nil && len(d.Choices) == 0
}

// ---- prompt estimate -------------------------------------------------

// estimateTokens is the gateway's approximation of a prompt: about one token
// per four characters of text plus a small per-message overhead. It is only
// used to refuse a request that cannot fit a budget and to reserve budget
// until the provider reports the real usage.
func estimateTokens(body map[string]any) int64 {
	var chars, msgs int64
	var walk func(v any, key string)
	walk = func(v any, key string) {
		switch t := v.(type) {
		case string:
			if !piiSkipKeys[key] {
				chars += int64(utf8.RuneCountInString(t))
			}
		case []any:
			for _, e := range t {
				walk(e, key)
			}
		case map[string]any:
			for k, e := range t {
				walk(e, k)
			}
		}
	}
	for _, k := range piiScanKeys {
		if v, ok := body[k]; ok {
			walk(v, "")
		}
	}
	if m, ok := body["messages"].([]any); ok {
		msgs = int64(len(m))
	}
	return (chars+3)/4 + 4*msgs
}

// maxTokensOf is the completion allowance a request asks for.
func maxTokensOf(body map[string]any, shape string, def int) int64 {
	if shape == shapeEmbedding {
		return 0
	}
	for _, k := range []string{"max_completion_tokens", "max_tokens"} {
		switch n := body[k].(type) {
		case json.Number:
			if v, err := n.Int64(); err == nil && v > 0 {
				return v
			}
		case float64:
			if n > 0 {
				return int64(n)
			}
		}
	}
	if def <= 0 {
		def = aiDefaultMaxTokens
	}
	return int64(def)
}

// ---- prices ----------------------------------------------------------

// AIPrices is the price table: per million tokens, in Currency.
type AIPrices struct {
	Currency string             `json:"currency,omitempty"`
	Models   map[string]AIPrice `json:"models"`
}

// lookup finds the price of a model: the exact name, then the longest table
// entry that is a prefix of it ("gpt-4o" prices "gpt-4o-2024-08-06"), then "*".
func lookupPrice(models map[string]AIPrice, model string) (AIPrice, bool) {
	if p, ok := models[model]; ok {
		return p, true
	}
	best, bl := AIPrice{}, 0
	for k, p := range models {
		if k != "*" && strings.HasPrefix(model, k) && len(k) > bl {
			best, bl = p, len(k)
		}
	}
	if bl > 0 {
		return best, true
	}
	p, ok := models["*"]
	return p, ok
}

func (p AIPrice) cost(in, out int64) float64 {
	return (float64(in)*p.Input + float64(out)*p.Output) / 1e6
}

// ParseAIPrices reads a price table file's content.
func ParseAIPrices(raw []byte) (*AIPrices, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p AIPrices
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	for k, v := range p.Models {
		if k == "" || v.Input < 0 || v.Output < 0 {
			return nil, &json.UnmarshalTypeError{Value: "price for " + k}
		}
	}
	return &p, nil
}

// priceBook is the server wide table, reloaded when its file changes.
type priceBook struct {
	mu    sync.RWMutex
	path  string
	mtime time.Time
	size  int64
	t     *AIPrices
}

func (b *priceBook) get() *AIPrices {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.t
}

// reload re-reads the file when it changed (or on first use). It keeps the old
// table on a bad file and returns the error.
func (b *priceBook) reload(force bool) error {
	if b.path == "" {
		return nil
	}
	fi, err := os.Stat(b.path)
	if err != nil {
		return err
	}
	b.mu.RLock()
	same := !force && fi.ModTime().Equal(b.mtime) && fi.Size() == b.size
	b.mu.RUnlock()
	if same {
		return nil
	}
	raw, err := os.ReadFile(b.path)
	if err != nil {
		return err
	}
	t, err := ParseAIPrices(raw)
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.t, b.mtime, b.size = t, fi.ModTime(), fi.Size()
	b.mu.Unlock()
	return nil
}
