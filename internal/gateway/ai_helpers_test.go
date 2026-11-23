package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLLM is a fake LLM provider speaking OpenAI or Anthropic style JSON and
// SSE. It is deterministic: usage is derived from the request, and a handler
// that must hang waits on the request context, never on a sleep.
type fakeLLM struct {
	*httptest.Server
	name string
	typ  string // openai or anthropic
	mu   sync.Mutex
	reqs []llmReq
	n    atomic.Int64
	// status decides the response status of the n-th request (1-based); 0 means 200.
	status func(n int) int
	// hang makes the request block until the gateway gives up on it.
	hang func(n int) bool
	// noUsage leaves the usage out of responses.
	noUsage bool
	prompt  int // prompt tokens reported (default 11)
	compl   int // completion tokens reported (default 7)
}

type llmReq struct {
	Path   string
	Header http.Header
	Body   map[string]any
	Raw    string
}

func (f *fakeLLM) seen() []llmReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]llmReq(nil), f.reqs...)
}

func (f *fakeLLM) count() int { return int(f.n.Load()) }

func newLLM(t *testing.T, name, typ string) *fakeLLM {
	t.Helper()
	f := &fakeLLM{name: name, typ: typ, prompt: 11, compl: 7}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.reqs = append(f.reqs, llmReq{Path: r.URL.Path, Header: r.Header.Clone(), Body: body, Raw: string(raw)})
		f.mu.Unlock()
		n := int(f.n.Add(1))
		if f.hang != nil && f.hang(n) {
			<-r.Context().Done()
			return
		}
		if f.status != nil {
			if st := f.status(n); st != 0 {
				w.Header().Set("Content-Type", "application/json")
				if st == 429 {
					w.Header().Set("Retry-After", "7")
				}
				w.WriteHeader(st)
				fmt.Fprintf(w, `{"error":{"message":"%s says %d, key was %s","type":"upstream"}}`, name, st, r.Header.Get("Authorization"))
				return
			}
		}
		model, _ := body["model"].(string)
		stream, _ := body["stream"].(bool)
		so, _ := body["stream_options"].(map[string]any)
		incl, _ := so["include_usage"].(bool)
		switch {
		case typ == "anthropic" && stream:
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":%q,\"usage\":{\"input_tokens\":%d,\"output_tokens\":1}}}\n\n", model, f.prompt)
			fl.Flush()
			fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n")
			fl.Flush()
			fmt.Fprintf(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{},\"usage\":{\"output_tokens\":%d}}\n\n", f.compl)
			fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		case typ == "anthropic":
			w.Header().Set("Content-Type", "application/json")
			u := ""
			if !f.noUsage {
				u = fmt.Sprintf(`,"usage":{"input_tokens":%d,"output_tokens":%d,"cache_read_input_tokens":3}`, f.prompt, f.compl)
			}
			fmt.Fprintf(w, `{"id":"msg_1","type":"message","model":%q,"content":[{"type":"text","text":"hi from %s"}]%s}`, model, name, u)
		case stream:
			w.Header().Set("Content-Type", "text/event-stream")
			fl := w.(http.Flusher)
			fmt.Fprintf(w, "data: {\"id\":\"c1\",\"model\":%q,\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n", model)
			fl.Flush()
			fmt.Fprintf(w, "data: {\"id\":\"c1\",\"model\":%q,\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}]}\n\n", model)
			fl.Flush()
			if incl && !f.noUsage {
				fmt.Fprintf(w, "data: {\"id\":\"c1\",\"model\":%q,\"choices\":[],\"usage\":{\"prompt_tokens\":%d,\"completion_tokens\":%d,\"total_tokens\":%d}}\n\n", model, f.prompt, f.compl, f.prompt+f.compl)
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
		case strings.HasSuffix(r.URL.Path, "/embeddings"):
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"object":"list","model":%q,"data":[{"embedding":[0.1,0.2]}],"usage":{"prompt_tokens":%d,"total_tokens":%d}}`, model, f.prompt, f.prompt)
		default:
			w.Header().Set("Content-Type", "application/json")
			u := ""
			if !f.noUsage {
				u = fmt.Sprintf(`,"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}`, f.prompt, f.compl, f.prompt+f.compl)
			}
			fmt.Fprintf(w, `{"id":"c1","model":%q,"choices":[{"message":{"role":"assistant","content":"hi from %s"}}]%s}`, model, name, u)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

const aiKeyT = "setura.zyvor.dev/ai"

// aiProviders makes provider entries pointing at the fakes, keys from env.
func llmProv(t *testing.T, f *fakeLLM, extra m) m {
	t.Helper()
	env := "SETURA_TEST_KEY_" + strings.ToUpper(strings.ReplaceAll(f.name, "-", "_"))
	t.Setenv(env, "sk-"+f.name+"-SECRET-0123456789")
	p := m{"name": f.name, "type": f.typ, "baseURL": f.URL + "/v1", "apiKey": m{"env": env}}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// aiServer serves one AI rule at a.test with the policy; mod adjusts Options.
func aiServer(t *testing.T, policy m, mod func(*Options)) (*Server, *syncBuf) {
	t.Helper()
	log := &syncBuf{}
	r := m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/"}}}, aiKeyT: policy}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", r)}, nil), func(o *Options) {
		o.AccessLog = log
		o.AuthClock = func() time.Time { return t0 }
		if mod != nil {
			mod(o)
		}
	})
	return s, log
}

func postJSON(t *testing.T, s *Server, path string, body any, hdr ...string) reply {
	t.Helper()
	var raw string
	switch b := body.(type) {
	case string:
		raw = b
	default:
		bb, _ := json.Marshal(b)
		raw = string(bb)
	}
	return req(t, client(s.Addr(8080), nil), "http", "POST", "a.test", path, raw, hdr...)
}

func chat(model string, msgs ...string) m {
	var ms []any
	for _, c := range msgs {
		ms = append(ms, m{"role": "user", "content": c})
	}
	return m{"model": model, "messages": ms}
}

// logLines returns the access log records after the log is flushed.
func aiLogLines(t *testing.T, s *Server, buf *syncBuf) []map[string]any {
	t.Helper()
	s.FlushAccessLog()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("bad log line %q: %v", ln, err)
		}
		out = append(out, rec)
	}
	return out
}

func lastLine(t *testing.T, s *Server, buf *syncBuf) map[string]any {
	t.Helper()
	ls := aiLogLines(t, s, buf)
	if len(ls) == 0 {
		t.Fatal("no access log line")
	}
	return ls[len(ls)-1]
}

func num(rec map[string]any, k string) float64 { v, _ := rec[k].(float64); return v }

func metricsText(s *Server) string {
	var b strings.Builder
	s.WriteMetrics(&b)
	return b.String()
}
