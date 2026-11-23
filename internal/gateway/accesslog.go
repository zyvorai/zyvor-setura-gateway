package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const defaultAccessLogBuffer = 4096

// logLine is one access log line and one /connections history record.
// Fields that are unknown for a request are omitted.
type logLine struct {
	ID                int64        `json:"id,omitempty"` // history sequence number, not part of log lines
	Time              string       `json:"time"`
	Listener          string       `json:"listener,omitempty"`
	ListenerPort      int          `json:"listener_port,omitempty"`
	Host              string       `json:"host"`
	Method            string       `json:"method"`
	Path              string       `json:"path"`
	Status            int          `json:"status"`
	Bytes             int64        `json:"bytes"`
	Millis            float64      `json:"duration_ms"`
	Route             string       `json:"route,omitempty"`
	Rule              *int         `json:"rule,omitempty"`
	Match             *int         `json:"match,omitempty"`
	Backend           string       `json:"backend,omitempty"`
	BackendWeight     int          `json:"backend_weight,omitempty"`
	Remote            string       `json:"remote"`
	ClientIP          string       `json:"client_ip,omitempty"`
	ClientPort        int          `json:"client_port,omitempty"`
	Protocol          string       `json:"protocol,omitempty"`
	HTTPVersion       string       `json:"http_version,omitempty"`
	TLSVersion        string       `json:"tls_version,omitempty"`
	TLSCipher         string       `json:"tls_cipher,omitempty"`
	TLSSNI            string       `json:"tls_sni,omitempty"`
	TLSALPN           string       `json:"tls_alpn,omitempty"`
	TLSClientCert     string       `json:"tls_client_cert_subject,omitempty"`
	UserAgent         string       `json:"user_agent,omitempty"`
	XFF               string       `json:"x_forwarded_for,omitempty"` // as received, never trusted
	GRPCService       string       `json:"grpc_service,omitempty"`
	GRPCMethod        string       `json:"grpc_method,omitempty"`
	GRPCStatus        *int         `json:"grpc_status,omitempty"`
	RateLimited       bool         `json:"rate_limited,omitempty"`
	RequestBytes      int64        `json:"request_bytes,omitempty"`
	ResponseBytes     int64        `json:"response_bytes,omitempty"`
	UpstreamAddr      string       `json:"upstream_addr,omitempty"`
	UpstreamProto     string       `json:"upstream_protocol,omitempty"`
	UpstreamTLS       *bool        `json:"upstream_tls,omitempty"`
	UpstreamReused    *bool        `json:"upstream_reused,omitempty"`
	UpstreamConnectMS float64      `json:"upstream_connect_ms,omitempty"`
	UpstreamTTFBMS    float64      `json:"upstream_ttfb_ms,omitempty"`
	UpstreamStatus    int          `json:"upstream_status,omitempty"`
	UpstreamHealth    string       `json:"upstream_health,omitempty"`
	Retries           int          `json:"retries,omitempty"`
	Attempts          []attemptRec `json:"attempts,omitempty"`
	AuthProtected     bool         `json:"auth_protected,omitempty"` // the serving rule carries an auth filter
	Contract          string       `json:"contract,omitempty"`       // unknown_endpoint or unknown_method
	ContractMode      string       `json:"contract_mode,omitempty"`  // monitor or block
	RequestID         string       `json:"request_id,omitempty"`
	TraceID           string       `json:"trace_id,omitempty"`
	SpanID            string       `json:"span_id,omitempty"`
	Error             string       `json:"error,omitempty"`

	// AI routes (ai_serve.go). Counts and names only: never prompts, answers or credentials.
	AIKey           string  `json:"ai_key,omitempty"`
	Provider        string  `json:"provider,omitempty"`
	Model           string  `json:"model,omitempty"`
	TokensIn        int64   `json:"tokens_in,omitempty"`
	TokensOut       int64   `json:"tokens_out,omitempty"`
	TokensEstimated bool    `json:"tokens_estimated,omitempty"`
	CacheHit        *bool   `json:"cache_hit,omitempty"`
	CostEstimate    float64 `json:"cost_estimate,omitempty"`
	PIIFindings     int     `json:"pii_findings,omitempty"`
	PIIAction       string  `json:"pii_action,omitempty"`
}

func (l *logLine) text() []byte {
	b := make([]byte, 0, 512)
	kv := func(k, v string) {
		if v == "" {
			return
		}
		b = append(b, k...)
		b = append(b, '=')
		b = strconv.AppendQuote(b, v)
		b = append(b, ' ')
	}
	ki := func(k string, v int64) {
		if v == 0 {
			return
		}
		b = append(b, k...)
		b = append(b, '=')
		b = strconv.AppendInt(b, v, 10)
		b = append(b, ' ')
	}
	kf := func(k string, v float64) {
		if v == 0 {
			return
		}
		b = append(b, k...)
		b = append(b, '=')
		b = strconv.AppendFloat(b, v, 'f', 3, 64)
		b = append(b, ' ')
	}
	kb := func(k string, v *bool) {
		if v == nil {
			return
		}
		b = append(b, k...)
		b = append(b, '=')
		b = strconv.AppendBool(b, *v)
		b = append(b, ' ')
	}
	kv("time", l.Time)
	kv("listener", l.Listener)
	ki("listener_port", int64(l.ListenerPort))
	kv("host", l.Host)
	kv("method", l.Method)
	kv("path", l.Path)
	b = append(b, "status="+strconv.Itoa(l.Status)+" bytes="+strconv.FormatInt(l.Bytes, 10)+" duration_ms="+strconv.FormatFloat(l.Millis, 'f', 3, 64)+" "...)
	kv("route", l.Route)
	if l.Rule != nil {
		b = append(b, "rule="+strconv.Itoa(*l.Rule)+" "...)
	}
	if l.Match != nil {
		b = append(b, "match="+strconv.Itoa(*l.Match)+" "...)
	}
	kv("backend", l.Backend)
	ki("backend_weight", int64(l.BackendWeight))
	kv("remote", l.Remote)
	kv("client_ip", l.ClientIP)
	ki("client_port", int64(l.ClientPort))
	kv("protocol", l.Protocol)
	kv("http_version", l.HTTPVersion)
	kv("tls_version", l.TLSVersion)
	kv("tls_cipher", l.TLSCipher)
	kv("tls_sni", l.TLSSNI)
	kv("tls_alpn", l.TLSALPN)
	kv("tls_client_cert_subject", l.TLSClientCert)
	kv("user_agent", l.UserAgent)
	kv("x_forwarded_for", l.XFF)
	kv("grpc_service", l.GRPCService)
	kv("grpc_method", l.GRPCMethod)
	if l.GRPCStatus != nil {
		b = append(b, "grpc_status="+strconv.Itoa(*l.GRPCStatus)+" "...)
	}
	if l.RateLimited {
		b = append(b, "rate_limited=true "...)
	}
	ki("request_bytes", l.RequestBytes)
	ki("response_bytes", l.ResponseBytes)
	kv("upstream_addr", l.UpstreamAddr)
	kv("upstream_protocol", l.UpstreamProto)
	kb("upstream_tls", l.UpstreamTLS)
	kb("upstream_reused", l.UpstreamReused)
	kf("upstream_connect_ms", l.UpstreamConnectMS)
	kf("upstream_ttfb_ms", l.UpstreamTTFBMS)
	ki("upstream_status", int64(l.UpstreamStatus))
	kv("upstream_health", l.UpstreamHealth)
	ki("retries", int64(l.Retries))
	if len(l.Attempts) > 0 {
		var sb []byte
		for i, a := range l.Attempts {
			if i > 0 {
				sb = append(sb, ',')
			}
			sb = append(sb, a.Addr...)
			sb = append(sb, ':')
			sb = strconv.AppendInt(sb, int64(a.Status), 10)
		}
		kv("attempts", string(sb))
	}
	if l.AuthProtected {
		b = append(b, "auth_protected=true "...)
	}
	kv("contract", l.Contract)
	kv("contract_mode", l.ContractMode)
	kv("ai_key", l.AIKey)
	kv("provider", l.Provider)
	kv("model", l.Model)
	ki("tokens_in", l.TokensIn)
	ki("tokens_out", l.TokensOut)
	if l.TokensEstimated {
		b = append(b, "tokens_estimated=true "...)
	}
	kb("cache_hit", l.CacheHit)
	kf("cost_estimate", l.CostEstimate)
	ki("pii_findings", int64(l.PIIFindings))
	kv("pii_action", l.PIIAction)
	kv("request_id", l.RequestID)
	kv("trace_id", l.TraceID)
	kv("span_id", l.SpanID)
	kv("error", l.Error)
	b[len(b)-1] = '\n'
	return b
}

// accessLogger formats on the request path but writes on its own goroutine.
// When the buffer is full the line is dropped and counted, never waited for.
type accessLogger struct {
	w       io.Writer
	text    bool
	ch      chan []byte
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
	dropped atomic.Int64
	written atomic.Int64
	pending atomic.Int64 // queued or being written
}

func newAccessLogger(w io.Writer, format string, buf int) *accessLogger {
	if buf <= 0 {
		buf = defaultAccessLogBuffer
	}
	a := &accessLogger{w: w, text: format == "text", ch: make(chan []byte, buf), done: make(chan struct{}), stopped: make(chan struct{})}
	go a.run()
	return a
}

func (a *accessLogger) write(b []byte) {
	if _, err := a.w.Write(b); err == nil {
		a.written.Add(1)
	}
	a.pending.Add(-1)
}

func (a *accessLogger) run() {
	defer close(a.stopped)
	for {
		select {
		case b := <-a.ch:
			a.write(b)
		case <-a.done:
			for {
				select {
				case b := <-a.ch:
					a.write(b)
				default:
					return
				}
			}
		}
	}
}

func (a *accessLogger) log(l *logLine) {
	var b []byte
	if a.text {
		b = l.text()
	} else {
		b, _ = json.Marshal(l)
		b = append(b, '\n')
	}
	a.pending.Add(1)
	select {
	case a.ch <- b:
	default:
		a.pending.Add(-1)
		a.dropped.Add(1)
	}
}

// close drains what is buffered and stops the writer goroutine.
func (a *accessLogger) close() {
	a.once.Do(func() { close(a.done) })
	<-a.stopped
}

// FlushAccessLog waits (up to a few seconds) until every queued line has
// been handed to the writer. Intended for tests and shutdown paths.
func (s *Server) FlushAccessLog() {
	// A handler queues its log line after the response is written, so a caller
	// that just read a response must also wait for requests still in the handler.
	for deadline := time.Now().Add(time.Second); s.inflight.Load() > 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if a := s.obs.access; a != nil {
		for deadline := time.Now().Add(5 * time.Second); a.pending.Load() > 0 && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
	}
}

// observe records one finished request: access log line, history record and span.
func (s *Server) observe(rec *recorder, r *http.Request, st *reqState, start, end time.Time, status int) {
	if s.obs.access != nil || s.conns != nil || len(s.obs.sinks) > 0 {
		l := s.buildLine(rec, r, st, start, end, status)
		if s.obs.access != nil || len(s.obs.sinks) > 0 {
			if !s.obs.logSkipped(r.URL.Path, status) {
				for _, k := range s.obs.sinks {
					k.offer(l) // copies the line; the history assigns its ID next
				}
				if a := s.obs.access; a != nil {
					a.log(l) // marshals before returning, so the history can take the record next
				}
			}
		}
		s.conns.push(l)
	}
	if x := s.obs.otlp; x != nil {
		name := r.Method
		if st.route != "" {
			name += " " + st.route
		}
		x.add(span{trace: st.trace, name: name, start: start, end: end, method: r.Method, path: r.URL.Path,
			host: r.Host, status: status, route: st.route, backend: st.backend, reqID: st.reqID, err: st.errMsg})
	}
}
