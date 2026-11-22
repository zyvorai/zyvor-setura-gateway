package gateway

import (
	"bytes"
	"encoding/json"
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
)

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
	if interval <= 0 {
		interval = otlpInterval
	}
	x := &otlpExporter{url: otlpURL(endpoint), client: &http.Client{Timeout: 5 * time.Second}, interval: interval,
		ch: make(chan span, otlpQueue), done: make(chan struct{}), stopped: make(chan struct{})}
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

func (x *otlpExporter) send(batch []span) {
	req, err := http.NewRequest(http.MethodPost, x.url, bytes.NewReader(encodeOTLP(batch)))
	if err != nil {
		x.dropped.Add(int64(len(batch)))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := x.client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			x.exported.Add(int64(len(batch)))
			return
		}
	}
	x.failures.Add(1)
	x.dropped.Add(int64(len(batch)))
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
