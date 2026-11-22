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

type logLine struct {
	Time      string  `json:"time"`
	Listener  string  `json:"listener,omitempty"`
	Host      string  `json:"host"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Status    int     `json:"status"`
	Bytes     int64   `json:"bytes"`
	Millis    float64 `json:"duration_ms"`
	Route     string  `json:"route,omitempty"`
	Rule      *int    `json:"rule,omitempty"`
	Backend   string  `json:"backend,omitempty"`
	Remote    string  `json:"remote"`
	RequestID string  `json:"request_id,omitempty"`
	TraceID   string  `json:"trace_id,omitempty"`
	SpanID    string  `json:"span_id,omitempty"`
	Error     string  `json:"error,omitempty"`
}

func (l *logLine) text() []byte {
	b := make([]byte, 0, 256)
	kv := func(k, v string) {
		if v == "" {
			return
		}
		b = append(b, k...)
		b = append(b, '=')
		b = strconv.AppendQuote(b, v)
		b = append(b, ' ')
	}
	kv("time", l.Time)
	kv("listener", l.Listener)
	kv("host", l.Host)
	kv("method", l.Method)
	kv("path", l.Path)
	b = append(b, "status="+strconv.Itoa(l.Status)+" bytes="+strconv.FormatInt(l.Bytes, 10)+" duration_ms="+strconv.FormatFloat(l.Millis, 'f', 3, 64)+" "...)
	kv("route", l.Route)
	kv("backend", l.Backend)
	kv("remote", l.Remote)
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
	if a := s.obs.access; a != nil {
		for deadline := time.Now().Add(5 * time.Second); a.pending.Load() > 0 && time.Now().Before(deadline); {
			time.Sleep(time.Millisecond)
		}
	}
}

// observe records one finished request: access log line and span.
func (s *Server) observe(rec *recorder, r *http.Request, st *reqState, start time.Time, status int) {
	end := time.Now()
	if a := s.obs.access; a != nil {
		a.log(&logLine{Time: start.UTC().Format(time.RFC3339Nano), Listener: st.listener, Host: r.Host, Method: r.Method,
			Path: r.URL.RequestURI(), Status: status, Bytes: rec.bytes, Millis: float64(end.Sub(start).Microseconds()) / 1000,
			Route: st.route, Rule: st.rule, Backend: st.backend, Remote: r.RemoteAddr, RequestID: st.reqID,
			TraceID: st.trace.TraceID, SpanID: st.trace.SpanID, Error: st.errMsg})
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
