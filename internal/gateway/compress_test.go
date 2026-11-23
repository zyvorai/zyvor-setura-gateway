package gateway

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// rawClient never negotiates compression by itself and never decodes.
func rawClient(addr string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second,
		Transport: &http.Transport{DisableCompression: true, DisableKeepAlives: true,
			DialContext: func(ctx context.Context, n, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, n, addr)
			}}}
}

type rawReply struct {
	Status int
	Header http.Header
	Body   []byte
}

func rawDo(t *testing.T, s *Server, method, target string, hdr ...string) rawReply {
	t.Helper()
	rq, err := http.NewRequest(method, "http://a.test"+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		rq.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := rawClient(s.Addr(8080)).Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return rawReply{resp.StatusCode, resp.Header, b}
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip: %v (%d bytes)", err, len(b))
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func inflate(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not zlib deflate: %v", err)
	}
	out, _ := io.ReadAll(zr)
	return string(out)
}

// handlerUpstream serves h and returns the backends map for it.
func handlerUpstream(t *testing.T, h http.Handler) map[string]any {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return map[string]any{"a": strings.TrimPrefix(srv.URL, "http://")}
}

var bigText = strings.Repeat("the quick brown fox jumps over the lazy dog\n", 200) // ~8.8KB

func compressUpstream(t *testing.T) map[string]any {
	return handlerUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Etag", `"v1"`)
			w.Header().Set("Accept-Ranges", "bytes")
			io.WriteString(w, `{"v":"`+bigText[:4000]+`"}`)
		case "/small":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "tiny")
		case "/png":
			w.Header().Set("Content-Type", "image/png")
			io.WriteString(w, bigText)
		case "/encoded":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Encoding", "gzip")
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			zw.Write([]byte(bigText))
			zw.Close()
			w.Write(b.Bytes())
		case "/notransform":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Cache-Control", "public, no-transform")
			io.WriteString(w, bigText)
		case "/range":
			http.ServeContent(w, r, "t.txt", time.Time{}, strings.NewReader(bigText))
		case "/vary":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Vary", "Accept-Language")
			io.WriteString(w, bigText)
		case "/chunked":
			// no Content-Length, no content type: sniffed from the first bytes
			w.Write([]byte(bigText))
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, strings.Repeat("data: x\n\n", 300))
		default:
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, bigText)
		}
	}))
}

func compressServer(t *testing.T, ro func(r m), mod func(*Options)) *Server {
	be := compressUpstream(t)
	rl := rule("/", ref("a", 1))
	if ro != nil {
		ro(rl)
	}
	return startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rl)}, be), mod)
}

func withCompress(o *Options) { o.Shape.Compress.Enabled = true }

func TestCompressNegotiationGzipDeflate(t *testing.T) {
	s := compressServer(t, nil, withCompress)
	r := rawDo(t, s, "GET", "/json", "Accept-Encoding", "gzip")
	if r.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(r.Header.Get("Vary"), "Accept-Encoding") || r.Header.Get("Content-Length") != "" {
		t.Fatalf("gzip: %v", r.Header)
	}
	if got := gunzip(t, r.Body); !strings.HasPrefix(got, `{"v":"the quick`) || len(r.Body) >= len(got)/4 {
		t.Fatalf("gzip body %d bytes for %d", len(r.Body), len(got))
	}
	if r.Header.Get("Etag") != `W/"v1"` || r.Header.Get("Accept-Ranges") != "" {
		t.Errorf("a compressed representation has a weak ETag and no byte ranges: %v", r.Header)
	}
	r = rawDo(t, s, "GET", "/json", "Accept-Encoding", "deflate")
	if r.Header.Get("Content-Encoding") != "deflate" || !strings.HasPrefix(inflate(t, r.Body), `{"v":"the quick`) {
		t.Fatalf("deflate: %v", r.Header)
	}
	for _, c := range []struct{ ae, want string }{
		{"gzip, deflate", "gzip"},
		{"deflate, gzip;q=0.5", "deflate"},
		{"gzip;q=0, deflate", "deflate"},
		{"br, zstd", ""},
		{"identity", ""},
		{"*", "gzip"},
		{"gzip;q=0, *;q=0", ""},
		{"x-gzip", "gzip"},
		{"", ""},
	} {
		r := rawDo(t, s, "GET", "/json", "Accept-Encoding", c.ae)
		if got := r.Header.Get("Content-Encoding"); got != c.want {
			t.Errorf("Accept-Encoding %q: %q, want %q", c.ae, got, c.want)
		}
		if !strings.Contains(r.Header.Get("Vary"), "Accept-Encoding") {
			t.Errorf("Accept-Encoding %q: the answer depends on the header, Vary is %q", c.ae, r.Header.Get("Vary"))
		}
	}
}

func TestCompressFiltersAndSkips(t *testing.T) {
	s := compressServer(t, nil, withCompress)
	gz := []string{"Accept-Encoding", "gzip"}
	// below the minimum size (Content-Length is known): left alone, Vary still set for caches
	if r := rawDo(t, s, "GET", "/small", gz...); r.Header.Get("Content-Encoding") != "" || string(r.Body) != "tiny" || !strings.Contains(r.Header.Get("Vary"), "Accept-Encoding") {
		t.Errorf("small: %v %q", r.Header, r.Body)
	}
	// content type not on the list: untouched, and no Vary since the answer cannot differ
	if r := rawDo(t, s, "GET", "/png", gz...); r.Header.Get("Content-Encoding") != "" || r.Header.Get("Vary") != "" || string(r.Body) != bigText {
		t.Errorf("png: %v", r.Header)
	}
	// already encoded by the backend: never compressed twice
	r := rawDo(t, s, "GET", "/encoded", gz...)
	if vals := r.Header.Values("Content-Encoding"); len(vals) != 1 || vals[0] != "gzip" || gunzip(t, r.Body) != bigText {
		t.Errorf("encoded: %v", r.Header)
	}
	// no-transform
	if r := rawDo(t, s, "GET", "/notransform", gz...); r.Header.Get("Content-Encoding") != "" || string(r.Body) != bigText {
		t.Errorf("no-transform: %v", r.Header)
	}
	// an upstream Vary is kept and extended
	r = rawDo(t, s, "GET", "/vary", gz...)
	if v := strings.Join(r.Header.Values("Vary"), ","); !strings.Contains(v, "Accept-Language") || !strings.Contains(v, "Accept-Encoding") || r.Header.Get("Content-Encoding") != "gzip" {
		t.Errorf("vary: %v", r.Header)
	}
	// unknown length and no content type: sniffed as text and compressed
	r = rawDo(t, s, "GET", "/chunked", gz...)
	if r.Header.Get("Content-Encoding") != "gzip" || gunzip(t, r.Body) != bigText {
		t.Errorf("chunked: %v", r.Header)
	}
	// event streams are not compressed unless named
	if r := rawDo(t, s, "GET", "/sse", gz...); r.Header.Get("Content-Encoding") != "" {
		t.Errorf("sse: %v", r.Header)
	}
}

func TestCompressHeadAndRanges(t *testing.T) {
	s := compressServer(t, nil, withCompress)
	gz := []string{"Accept-Encoding", "gzip"}
	// HEAD carries the headers a GET would, and no body
	h := rawDo(t, s, "HEAD", "/json", gz...)
	if h.Status != 200 || h.Header.Get("Content-Encoding") != "gzip" || h.Header.Get("Content-Length") != "" || len(h.Body) != 0 || !strings.Contains(h.Header.Get("Vary"), "Accept-Encoding") {
		t.Errorf("HEAD: %d %v %q", h.Status, h.Header, h.Body)
	}
	// a ranged request wants identity bytes: no compression, partial content intact
	r := rawDo(t, s, "GET", "/range", append(gz, "Range", "bytes=0-9")...)
	if r.Status != 206 || r.Header.Get("Content-Encoding") != "" || string(r.Body) != bigText[:10] || r.Header.Get("Content-Range") == "" {
		t.Errorf("range: %d %v %q", r.Status, r.Header, r.Body)
	}
	// without a Range header the same resource compresses (and drops Accept-Ranges)
	r = rawDo(t, s, "GET", "/range", gz...)
	if r.Status != 200 || r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("Accept-Ranges") != "" || gunzip(t, r.Body) != bigText {
		t.Errorf("full: %d %v", r.Status, r.Header)
	}
}

func TestCompressStreamingFlush(t *testing.T) {
	first, release := make(chan struct{}), make(chan struct{})
	be := handlerUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.(http.Flusher).Flush()
		io.WriteString(w, `{"n":1}`+"\n")
		w.(http.Flusher).Flush()
		close(first)
		<-release
		io.WriteString(w, `{"n":2}`+"\n")
	}))
	rl := rule("/", ref("a", 1))
	rl["setura.zyvor.dev/compress"] = m{"types": l{"application/x-ndjson"}, "minSize": 1}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rl)}, be), withCompress)
	rq, _ := http.NewRequest("GET", "http://a.test/", nil)
	rq.Header.Set("Accept-Encoding", "gzip")
	resp, err := rawClient(s.Addr(8080)).Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("headers: %v", resp.Header)
	}
	<-first
	zr, err := gzip.NewReader(resp.Body) // would block until the second chunk if the flush did not reach the client
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(zr, buf); err != nil || string(buf) != `{"n":1}` {
		t.Fatalf("first chunk before the second was released: %q %v", buf, err)
	}
	close(release)
	rest, _ := io.ReadAll(zr)
	if string(rest) != "\n"+`{"n":2}`+"\n" {
		t.Errorf("rest %q", rest)
	}
}

func TestCompressScopesAndOverrides(t *testing.T) {
	// the gateway flag is off: only a rule that asks compresses
	s := compressServer(t, func(r m) {
		r["setura.zyvor.dev/compress"] = m{"enabled": true, "encodings": l{"deflate"}, "types": l{"text/plain"}, "minSize": "2KB", "level": 9}
	}, nil)
	r := rawDo(t, s, "GET", "/x", "Accept-Encoding", "gzip, deflate")
	if r.Header.Get("Content-Encoding") != "deflate" {
		t.Fatalf("rule block: %v", r.Header)
	}
	if r := rawDo(t, s, "GET", "/json", "Accept-Encoding", "gzip, deflate"); r.Header.Get("Content-Encoding") != "" { // application/json is not on this rule's list
		t.Errorf("types: %v", r.Header)
	}
	if r := rawDo(t, s, "GET", "/small", "Accept-Encoding", "deflate"); r.Header.Get("Content-Encoding") != "" {
		t.Errorf("minSize: %v", r.Header)
	}
	// a gateway wide --compress that one rule switches off
	off := compressServer(t, func(r m) { r["setura.zyvor.dev/compress"] = m{"enabled": false} }, withCompress)
	if r := rawDo(t, off, "GET", "/x", "Accept-Encoding", "gzip"); r.Header.Get("Content-Encoding") != "" || r.Header.Get("Vary") != "" {
		t.Errorf("rule off: %v", r.Header)
	}
	// a rule.N annotation addresses one rule of the route
	be := compressUpstream(t)
	rl := m{"matches": l{m{"path": m{"type": "PathPrefix", "value": "/json"}}}, "backendRefs": l{ref("a", 1)}}
	other := rule("/", ref("a", 1))
	routes := map[string]m{"r": annotated(route("a.test", rl, other), m{"setura.zyvor.dev/compress.rule-1": `{"enabled":true}`})}
	s2 := startServer(t, snap(httpGateway(""), routes, be), nil)
	if rawDo(t, s2, "GET", "/json", "Accept-Encoding", "gzip").Header.Get("Content-Encoding") != "gzip" || rawDo(t, s2, "GET", "/other", "Accept-Encoding", "gzip").Header.Get("Content-Encoding") != "" {
		t.Error("rule-1 annotation")
	}
	// listener level
	gw := httpGateway("")
	gw["listeners"].([]any)[0].(m)["setura.zyvor.dev/compress"] = m{"enabled": true}
	s3 := startServer(t, snap(gw, map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, compressUpstream(t)), nil)
	if rawDo(t, s3, "GET", "/x", "Accept-Encoding", "gzip").Header.Get("Content-Encoding") != "gzip" {
		t.Error("listener block")
	}
	// metrics: bounded labels, ratio visible
	out := obsMetricsOf(s3)
	for _, w := range []string{`setura_gateway_compress_responses_total{route="t/r",encoding="gzip"} 1`, `setura_gateway_compress_bytes_total{route="t/r",direction="in"} ` + strconv.Itoa(len(bigText))} {
		if !strings.Contains(out, w) {
			t.Errorf("metrics lack %s\n%s", w, out)
		}
	}
}

func TestCompressBlockValidation(t *testing.T) {
	for name, blk := range map[string]string{
		"brotli": `{"encodings":["br"]}`,
		"zstd":   `{"encodings":["zstd"]}`,
		"level":  `{"level":12}`,
		"type":   `{"types":["json"]}`,
		"size":   `{"minSize":"abc"}`,
		"field":  `{"nope":true}`,
	} {
		if _, err := ParseCompressBlock([]byte(blk)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseCompressBlock([]byte(`{"encodings":["gzip"],"types":["text/*","*/*+json"],"minSize":512,"level":3}`)); err != nil {
		t.Error(err)
	}
}

// TestCompressWriterBuffersUntilMinimum covers a response with no Content-Length
// that ends before the minimum: it goes out unchanged.
func TestCompressWriterBuffersUntilMinimum(t *testing.T) {
	pol := resolveCompress(&CompressConfig{Enabled: ptr(true)})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	run := func(parts ...string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		cw := newCompressWriter(rec, req, pol, "t/r", &shapeStats{})
		cw.Header().Set("Content-Type", "text/plain")
		cw.WriteHeader(200)
		for _, p := range parts {
			cw.Write([]byte(p))
		}
		cw.Close()
		return rec
	}
	if rec := run("short", " body"); rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != "short body" {
		t.Errorf("short: %v %q", rec.Header(), rec.Body.String())
	}
	rec := run(bigText[:600], bigText[600:1500])
	if rec.Header().Get("Content-Encoding") != "gzip" || gunzip(t, rec.Body.Bytes()) != bigText[:1500] {
		t.Errorf("long: %v", rec.Header())
	}
	// nothing written: the response is not touched
	if rec := run(); rec.Header().Get("Content-Encoding") != "" || rec.Body.Len() != 0 {
		t.Errorf("empty: %v", rec.Header())
	}
}

func ptr[T any](v T) *T { return &v }
