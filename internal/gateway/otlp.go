package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	otlpQueue    = 2048
	otlpBatch    = 128
	otlpInterval = 2 * time.Second

	defaultOTLPRetries = 4                      // retries after the first attempt
	defaultOTLPBackoff = 250 * time.Millisecond // first wait, doubling
	maxOTLPBackoff     = 10 * time.Second
)

// OTLPOptions tunes span export; zero values give the defaults.
type OTLPOptions struct {
	Queue   int           // spans buffered before new ones are dropped (default 2048)
	Retries int           // retries of a failed batch (default 4; negative disables retrying)
	Backoff time.Duration // first retry wait, doubling up to 10s with jitter (default 250ms)
	// Protocol is "http" (OTLP/HTTP JSON, default) or "grpc" (OTLP/gRPC, protobuf).
	Protocol string
}

type span struct {
	trace        traceInfo
	name         string
	start, end   time.Time
	method, path string
	host         string
	status       int
	route        string
	backend      string
	reqID, err   string
}

// otlpExporter batches spans and POSTs OTLP/HTTP JSON. It is best effort:
// a full queue or a failing collector drops spans and counts them.
type otlpExporter struct {
	url      string
	client   *http.Client
	interval time.Duration
	ch       chan span
	done     chan struct{}
	stopped  chan struct{}
	once     sync.Once
	exported atomic.Int64
	dropped  atomic.Int64
	failures atomic.Int64
	retries  atomic.Int64
	opts     OTLPOptions
	grpc     bool
}

// otlpGRPCURL is the Export URL of an OTLP/gRPC endpoint: a bare host:port
// means plaintext HTTP/2 (h2c), https:// means TLS.
func otlpGRPCURL(endpoint, path string) string {
	if !strings.Contains(endpoint, "://") {
		endpoint = "http://" + endpoint
	}
	return strings.TrimRight(endpoint, "/") + path
}

func otlpURL(endpoint string) string {
	if !strings.Contains(endpoint, "://") {
		endpoint = "http://" + endpoint
	}
	if i := strings.Index(endpoint, "://"); !strings.Contains(endpoint[i+3:], "/") {
		endpoint += "/v1/traces"
	}
	return endpoint
}

func newOTLP(endpoint string, interval time.Duration) *otlpExporter {
	return newOTLPOpts(endpoint, interval, OTLPOptions{})
}

func newOTLPOpts(endpoint string, interval time.Duration, o OTLPOptions) *otlpExporter {
	if interval <= 0 {
		interval = otlpInterval
	}
	if o.Queue <= 0 {
		o.Queue = otlpQueue
	}
	if o.Retries == 0 {
		o.Retries = defaultOTLPRetries
	}
	if o.Backoff <= 0 {
		o.Backoff = defaultOTLPBackoff
	}
	x := &otlpExporter{url: otlpURL(endpoint), client: &http.Client{Timeout: 5 * time.Second}, interval: interval, opts: o,
		ch: make(chan span, o.Queue), done: make(chan struct{}), stopped: make(chan struct{})}
	if o.Protocol == "grpc" {
		x.grpc, x.url = true, otlpGRPCURL(endpoint, otlpTracePath)
		x.client = grpcClient(x.url, 5*time.Second)
	}
	go x.run()
	return x
}

func (x *otlpExporter) add(sp span) {
	if sp.trace.Flags != "" && len(sp.trace.Flags) == 2 {
		// honour the sampled flag: unsampled traces are not exported
		if f, err := strconv.ParseUint(sp.trace.Flags, 16, 8); err == nil && f&1 == 0 {
			return
		}
	}
	select {
	case x.ch <- sp:
	default:
		x.dropped.Add(1)
	}
}

func (x *otlpExporter) run() {
	defer close(x.stopped)
	tk := time.NewTicker(x.interval)
	defer tk.Stop()
	var batch []span
	flush := func() {
		if len(batch) > 0 {
			x.send(batch)
			batch = nil
		}
	}
	for {
		select {
		case sp := <-x.ch:
			batch = append(batch, sp)
			if len(batch) >= otlpBatch {
				flush()
			}
		case <-tk.C:
			flush()
		case <-x.done:
			for {
				select {
				case sp := <-x.ch:
					batch = append(batch, sp)
				default:
					flush()
					return
				}
			}
		}
	}
}

// send exports one batch. A failed attempt (network error, 429, 502, 503,
// 504) is retried with exponential backoff and jitter, honouring Retry-After;
// other 4xx answers drop the batch at once, as retrying cannot help. While a
// batch is being retried new spans wait in the bounded queue and are dropped
// (and counted) when it is full. Shutdown stops retrying.
func (x *otlpExporter) send(batch []span) {
	payload := encodeOTLP(batch)
	if x.grpc {
		payload = encodeOTLPProto(batch)
	}
	wait := x.opts.Backoff
	for attempt := 0; ; attempt++ {
		retryAfter, retryable := x.try(payload)
		if retryAfter < 0 {
			x.exported.Add(int64(len(batch)))
			return
		}
		x.failures.Add(1)
		if !retryable || x.opts.Retries < 0 || attempt >= x.opts.Retries || x.closing() {
			x.dropped.Add(int64(len(batch)))
			return
		}
		d := wait
		if retryAfter > 0 {
			d = retryAfter
		}
		d += time.Duration(randIntn(int(d/4) + 1)) // up to 25% jitter
		if d > maxOTLPBackoff {
			d = maxOTLPBackoff
		}
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-x.done:
			t.Stop()
			x.dropped.Add(int64(len(batch)))
			return
		}
		x.retries.Add(1)
		if wait *= 2; wait > maxOTLPBackoff {
			wait = maxOTLPBackoff
		}
	}
}

func (x *otlpExporter) closing() bool {
	select {
	case <-x.done:
		return true
	default:
		return false
	}
}

// try posts payload once. It returns a negative retryAfter on success;
// otherwise retryAfter is the collector's Retry-After (0 if none) and
// retryable says whether another attempt may help.
func (x *otlpExporter) try(payload []byte) (retryAfter time.Duration, retryable bool) {
	if x.grpc {
		return x.tryGRPC(payload)
	}
	req, err := http.NewRequest(http.MethodPost, x.url, bytes.NewReader(payload))
	if err != nil {
		return 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := x.client.Do(req)
	if err != nil {
		return 0, true
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	switch c := resp.StatusCode; {
	case c/100 == 2:
		return -1, false
	case c == 429 || c == 502 || c == 503 || c == 504:
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
			retryAfter = time.Duration(n) * time.Second
		}
		return retryAfter, true
	}
	return 0, false
}

func (x *otlpExporter) close() {
	x.once.Do(func() { close(x.done) })
	<-x.stopped
}

func jstr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func attrS(k, v string) string {
	return `{"key":` + jstr(k) + `,"value":{"stringValue":` + jstr(v) + `}}`
}

func attrI(k string, v int) string {
	return `{"key":` + jstr(k) + `,"value":{"intValue":"` + strconv.Itoa(v) + `"}}`
}

// encodeOTLP renders an ExportTraceServiceRequest in OTLP/JSON encoding
// (hex trace ids, int64 as strings).
func encodeOTLP(batch []span) []byte {
	var b strings.Builder
	b.WriteString(`{"resourceSpans":[{"resource":{"attributes":[` + attrS("service.name", "setura-gateway") + `]},` +
		`"scopeSpans":[{"scope":{"name":"setura/gateway"},"spans":[`)
	for i, sp := range batch {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"traceId":` + jstr(sp.trace.TraceID) + `,"spanId":` + jstr(sp.trace.SpanID))
		if sp.trace.ParentID != "" {
			b.WriteString(`,"parentSpanId":` + jstr(sp.trace.ParentID))
		}
		if sp.trace.State != "" {
			b.WriteString(`,"traceState":` + jstr(sp.trace.State))
		}
		b.WriteString(`,"name":` + jstr(sp.name) + `,"kind":2`)
		b.WriteString(`,"startTimeUnixNano":"` + strconv.FormatInt(sp.start.UnixNano(), 10) + `"`)
		b.WriteString(`,"endTimeUnixNano":"` + strconv.FormatInt(sp.end.UnixNano(), 10) + `"`)
		attrs := []string{attrS("http.request.method", sp.method), attrS("url.path", sp.path), attrS("server.address", sp.host),
			attrI("http.response.status_code", sp.status), attrS("setura.request_id", sp.reqID)}
		if sp.route != "" {
			attrs = append(attrs, attrS("setura.route", sp.route))
		}
		if sp.backend != "" {
			attrs = append(attrs, attrS("setura.backend", sp.backend))
		}
		b.WriteString(`,"attributes":[` + strings.Join(attrs, ",") + `]`)
		if sp.status >= 500 {
			b.WriteString(`,"status":{"code":2,"message":` + jstr(sp.err) + `}`)
		}
		b.WriteByte('}')
	}
	b.WriteString(`]}]}]}`)
	return []byte(b.String())
}
