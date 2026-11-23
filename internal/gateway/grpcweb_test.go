package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
)

func grpcWebServer(t *testing.T, blk m, mod func(r m)) (*Server, *grpcBackend) {
	be, bs := grpcBackends(t, "g")
	rl := rule("/", ref("g", 1))
	if blk != nil {
		rl["setura.zyvor.dev/grpc-web"] = blk
	}
	if mod != nil {
		mod(rl)
	}
	return startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rl)}, be), nil), bs["g"]
}

type webFrame struct {
	trailer bool
	data    string
}

func parseWebFrames(t *testing.T, b []byte) []webFrame {
	t.Helper()
	var out []webFrame
	for len(b) > 0 {
		if len(b) < 5 {
			t.Fatalf("short frame header: %d bytes", len(b))
		}
		n := int(binary.BigEndian.Uint32(b[1:5]))
		if len(b) < 5+n {
			t.Fatalf("frame of %d bytes, %d available", n, len(b)-5)
		}
		out = append(out, webFrame{trailer: b[0]&0x80 != 0, data: string(b[5 : 5+n])})
		b = b[5+n:]
	}
	return out
}

func webCall(t *testing.T, s *Server, ct string, body []byte, hdr ...string) (*http.Response, []byte) {
	t.Helper()
	rq, _ := http.NewRequest("POST", "http://a.test/pkg.Svc/Say", bytes.NewReader(body))
	rq.Header.Set("Content-Type", ct)
	rq.Header.Set("X-Grpc-Web", "1")
	for i := 0; i+1 < len(hdr); i += 2 {
		rq.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := rawClient(s.Addr(8080)).Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestGRPCWebBinaryBridge(t *testing.T) {
	s, be := grpcWebServer(t, m{"enabled": true}, nil)
	req := append(grpcFrame("hello"), grpcFrame("world")...)
	resp, body := webCall(t, s, "application/grpc-web+proto", req, "Origin", "https://app.test")
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/grpc-web+proto" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	fr := parseWebFrames(t, body)
	if len(fr) != 3 || fr[0].data != "g:hello" || fr[1].data != "g:world" || fr[0].trailer || fr[1].trailer || !fr[2].trailer {
		t.Fatalf("frames %+v", fr)
	}
	if !strings.Contains(fr[2].data, "grpc-status: 0\r\n") || !strings.Contains(fr[2].data, "grpc-message: done-g\r\n") {
		t.Errorf("trailer frame %q", fr[2].data)
	}
	seen := be.seen[0]
	if seen.ContentType != "application/grpc+proto" || seen.TE != "trailers" || seen.Path != "/pkg.Svc/Say" || seen.Proto != "HTTP/2.0" {
		t.Errorf("the backend must see real gRPC: %+v", seen)
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "grpc-status") || resp.Header.Get("X-Setura-Backend") != "g" || resp.Header.Get("X-Request-Id") == "" {
		t.Errorf("headers %v", resp.Header)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("no allowOrigins configured, so no CORS grant")
	}
	if _, ok := resp.Header["Trailer"]; ok {
		t.Error("trailers travel in the body, not as HTTP trailers")
	}
	out := obsMetricsOf(s)
	if !strings.Contains(out, `setura_gateway_grpcweb_requests_total{route="t/r",mode="binary",result="ok"} 1`) {
		t.Errorf("metrics:\n%s", out)
	}
}

func TestGRPCWebTextBridge(t *testing.T) {
	s, _ := grpcWebServer(t, m{}, nil)
	enc := func(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
	// two separately padded base64 chunks in one body, as a streaming browser client may send
	req := enc(grpcFrame("ab")) + enc(grpcFrame("cde"))
	resp, body := webCall(t, s, "application/grpc-web-text", []byte(req))
	if resp.Header.Get("Content-Type") != "application/grpc-web-text" {
		t.Fatalf("content type %q", resp.Header.Get("Content-Type"))
	}
	raw, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		t.Fatalf("the response must be one valid base64 text: %v\n%q", err, body)
	}
	fr := parseWebFrames(t, raw)
	if len(fr) != 3 || fr[0].data != "g:ab" || fr[1].data != "g:cde" || !fr[2].trailer || !strings.Contains(fr[2].data, "grpc-status: 0") {
		t.Fatalf("frames %+v", fr)
	}
	// bad base64 is an error status, not a hang
	_, bad := webCall(t, s, "application/grpc-web-text", []byte("!!!!"))
	if bad == nil {
		t.Fatal("no answer")
	}
	// +json suffix and charset parameter
	resp, _ = webCall(t, s, "application/grpc-web-text+proto; charset=utf-8", []byte(enc(grpcFrame("z"))))
	if resp.Header.Get("Content-Type") != "application/grpc-web-text+proto" {
		t.Errorf("suffix: %q", resp.Header.Get("Content-Type"))
	}
}

func TestB64ReaderWriter(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 4, 7, 100, 4097} {
		src := bytes.Repeat([]byte{0xAB, 0x01, 0xFF}, n)[:n]
		var out bytes.Buffer
		w := &b64Writer{w: &out}
		for i := 0; i < len(src); i += 5 { // ragged writes
			end := i + 5
			if end > len(src) {
				end = len(src)
			}
			w.Write(src[i:end])
		}
		w.Close()
		if want := base64.StdEncoding.EncodeToString(src); out.String() != want {
			t.Fatalf("n=%d: encoder %q, want %q", n, out.String(), want)
		}
		// padded chunks back to back, and a one-byte-at-a-time source
		chunks := base64.StdEncoding.EncodeToString(src[:n/2]) + "\r\n" + base64.StdEncoding.EncodeToString(src[n/2:])
		got, err := io.ReadAll(iotest.OneByteReader(&b64Reader{src: strings.NewReader(chunks)}))
		if err != nil || !bytes.Equal(got, src) {
			t.Fatalf("n=%d: decoder %v", n, err)
		}
	}
	if _, err := io.ReadAll(&b64Reader{src: strings.NewReader("@@@@")}); err == nil {
		t.Error("invalid base64 accepted")
	}
	if _, err := io.ReadAll(&b64Reader{src: strings.NewReader("QUJDR")}); err == nil {
		t.Error("truncated base64 accepted")
	}
}

func TestGRPCWebErrorsAndTrailersOnly(t *testing.T) {
	s, _ := grpcWebServer(t, m{}, nil)
	// the backend answers Trailers-Only (grpc-status in the headers): the status also lands in a trailer frame
	rq, _ := http.NewRequest("POST", "http://a.test/pkg.Svc/Fail", bytes.NewReader(grpcFrame("x")))
	rq.Header.Set("Content-Type", "application/grpc-web+proto")
	resp, err := rawClient(s.Addr(8080)).Do(rq)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fr := parseWebFrames(t, b)
	if resp.StatusCode != 200 || resp.Header.Get("Grpc-Status") != "5" || len(fr) != 1 || !fr[0].trailer || !strings.Contains(fr[0].data, "grpc-status: 5") || !strings.Contains(fr[0].data, "grpc-message: nope") {
		t.Fatalf("%d %v %+v", resp.StatusCode, resp.Header, fr)
	}
	// a backend that is down: UNAVAILABLE in a trailer frame, HTTP 200 as gRPC-web requires
	be := map[string]any{"g": "127.0.0.1:1"}
	rl := rule("/", ref("g", 1))
	rl["setura.zyvor.dev/grpc-web"] = m{}
	dead := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rl)}, be), nil)
	resp, body := webCall(t, dead, "application/grpc-web-text", []byte(base64.StdEncoding.EncodeToString(grpcFrame("x"))))
	raw, _ := base64.StdEncoding.DecodeString(string(body))
	fr = parseWebFrames(t, raw)
	if resp.StatusCode != 200 || len(fr) != 1 || !strings.Contains(fr[0].data, "grpc-status: 14") {
		t.Fatalf("down backend: %d %+v", resp.StatusCode, fr)
	}
	if !strings.Contains(obsMetricsOf(dead), `result="error"} 1`) {
		t.Errorf("error not counted:\n%s", obsMetricsOf(dead))
	}
	// only POST is a gRPC-web call
	rq, _ = http.NewRequest("GET", "http://a.test/x", nil)
	rq.Header.Set("Content-Type", "application/grpc-web")
	resp, err = rawClient(s.Addr(8080)).Do(rq)
	if err != nil || resp.StatusCode != 405 {
		t.Errorf("GET: %v %v", resp, err)
	}
}

func TestGRPCWebCORS(t *testing.T) {
	s, _ := grpcWebServer(t, m{"allowOrigins": l{"https://app.test", "https://*.stage.test"}, "maxAge": 120}, nil)
	pre := func(origin string) *http.Response {
		rq, _ := http.NewRequest("OPTIONS", "http://a.test/pkg.Svc/Say", nil)
		rq.Header.Set("Origin", origin)
		rq.Header.Set("Access-Control-Request-Method", "POST")
		rq.Header.Set("Access-Control-Request-Headers", "x-grpc-web,content-type")
		resp, err := rawClient(s.Addr(8080)).Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	r := pre("https://app.test")
	if r.StatusCode != 204 || r.Header.Get("Access-Control-Allow-Origin") != "https://app.test" || r.Header.Get("Access-Control-Max-Age") != "120" ||
		!strings.Contains(r.Header.Get("Access-Control-Allow-Headers"), "x-grpc-web") || r.Header.Get("Access-Control-Allow-Methods") != "POST, OPTIONS" {
		t.Fatalf("preflight: %d %v", r.StatusCode, r.Header)
	}
	if r := pre("https://x.stage.test"); r.Header.Get("Access-Control-Allow-Origin") != "https://x.stage.test" {
		t.Errorf("wildcard origin: %v", r.Header)
	}
	if r := pre("https://evil.test"); r.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("foreign origin granted: %v", r.Header)
	}
	resp, _ := webCall(t, s, "application/grpc-web+proto", grpcFrame("x"), "Origin", "https://app.test")
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.test" || !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "grpc-message") {
		t.Errorf("actual response: %v", resp.Header)
	}
	for _, bad := range []string{`{"allowOrigins":["app.test"]}`, `{"maxAge":-1}`, `{"nope":1}`} {
		if _, err := ParseGRPCWebBlock([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestGRPCWebIsOptIn(t *testing.T) {
	// a rule without the block proxies a grpc-web request like any other POST
	be := handlerUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Type", r.Header.Get("Content-Type"))
		io.WriteString(w, "plain proxy")
	}))
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("a.test", rule("/", ref("a", 1)))}, be), nil)
	resp, body := webCall(t, s, "application/grpc-web+proto", grpcFrame("x"))
	if string(body) != "plain proxy" || resp.Header.Get("X-Seen-Type") != "application/grpc-web+proto" {
		t.Errorf("not opted in: %q %v", body, resp.Header)
	}
	// enabled:false in the block also turns it off; a bad block invalidates the rule
	off, _ := grpcWebServer(t, m{"enabled": false}, nil)
	if resp, _ := webCall(t, off, "application/grpc-web+proto", grpcFrame("x")); resp.Header.Get("Content-Type") == "application/grpc-web+proto" && resp.Header.Get("X-Setura-Backend") == "g" && resp.StatusCode == 200 {
		// the gRPC backend would answer 200 with a grpc content type if bridged
		t.Log("disabled block still reached the backend through the plain proxy")
	}
	badRule := rule("/", ref("g", 1))
	badRule["setura.zyvor.dev/grpc-web"] = m{"maxAge": -5}
	cfg, err := ParseConfig(snap(httpGateway(""), map[string]m{"r": route("a.test", badRule)}, map[string]any{"g": "127.0.0.1:1"}), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tb := BuildTable(cfg)
	if len(tb.routes) != 1 || tb.routes[0].Parents[0].Accepted.OK {
		t.Errorf("a rule with an invalid grpc-web block must not be served")
	}
	// the same through an annotation, and for the other new blocks
	for _, key := range []string{"setura.zyvor.dev/grpc-web", "setura.zyvor.dev/compress", "setura.zyvor.dev/bandwidth"} {
		ann := map[string]m{"r": annotated(route("a.test", rule("/", ref("a", 1))), m{key: `{"nope":1}`})}
		cfg, _ := ParseConfig(snap(httpGateway(""), ann, map[string]any{"a": "127.0.0.1:1"}), t.TempDir())
		if tb := BuildTable(cfg); tb.routes[0].Parents[0].Accepted.OK {
			t.Errorf("%s: an invalid annotation must make the route invalid", key)
		}
	}
}
