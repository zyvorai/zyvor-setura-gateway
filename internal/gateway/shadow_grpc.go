package gateway

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// finalTrailers returns the trailers ReverseProxy left in the response header
// map after the body: "Trailer:"-prefixed keys and the gRPC status pair.
func finalTrailers(h http.Header) http.Header {
	out := http.Header{}
	for k, v := range h {
		if strings.HasPrefix(k, http.TrailerPrefix) {
			out[http.CanonicalHeaderKey(strings.TrimPrefix(k, http.TrailerPrefix))] = v
		}
	}
	for _, k := range []string{"Grpc-Status", "Grpc-Message"} {
		if _, ok := out[k]; !ok && len(h[k]) > 0 {
			out[k] = h[k]
		}
	}
	return out
}

// grpcStatus returns grpc-status and grpc-message from the trailers, or from
// the headers for a Trailers-Only response.
func grpcStatus(c *respCapture) (status, msg string) {
	status, msg = c.trailer.Get("Grpc-Status"), c.trailer.Get("Grpc-Message")
	if status == "" {
		status = c.hdr.Get("Grpc-Status")
	}
	if msg == "" {
		msg = c.hdr.Get("Grpc-Message")
	}
	return
}

type grpcMsg struct {
	flag byte
	data []byte
}

// parseFrames splits a gRPC message stream into length-prefixed frames
// (1 byte compressed flag, 4 byte big endian length). ok is false when the
// stream is not made of whole frames.
func parseFrames(b []byte) (frames []grpcMsg, ok bool) {
	for len(b) > 0 {
		if len(b) < 5 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(b[1:5])
		if uint64(n) > uint64(len(b)-5) {
			return nil, false
		}
		frames = append(frames, grpcMsg{b[0], b[5 : 5+n]})
		b = b[5+n:]
	}
	return frames, true
}

// byteDiff locates the first differing byte of two slices and returns redacted
// excerpts around it.
func byteDiff(pb, sb []byte) (off int, pe, se string) {
	for off < len(pb) && off < len(sb) && pb[off] == sb[off] {
		off++
	}
	rp, rs := redactSlice(pb, off), redactSlice(sb, off)
	roff := 0
	for roff < len(rp) && roff < len(rs) && rp[roff] == rs[roff] {
		roff++
	}
	if rp == rs {
		return off, "[redacted]", "[redacted]"
	}
	return off, window(rp, roff), window(rs, roff)
}

// compareGRPC compares two gRPC responses: HTTP status, content type,
// grpc-status, grpc-message and the response message frames.
func compareGRPC(p, s *respCapture, c *CShadow) []shadowMismatch {
	if c == nil {
		c = &CShadow{}
	}
	var out []shadowMismatch
	if p.status != s.status {
		out = append(out, shadowMismatch{Category: "status", Where: "status", Primary: fmt.Sprint(p.status), Shadow: fmt.Sprint(s.status)})
	}
	seen := map[string]bool{}
	for _, h := range append([]string{"Content-Type"}, c.headers...) {
		if seen[h] || ignoredHeader(h, c) {
			continue
		}
		seen[h] = true
		if pv, sv := strings.Join(p.hdr.Values(h), ", "), strings.Join(s.hdr.Values(h), ", "); pv != sv {
			out = append(out, shadowMismatch{Category: "header", Where: h, Primary: excerpt(pv), Shadow: excerpt(sv)})
		}
	}
	ps, pm := grpcStatus(p)
	ss, sm := grpcStatus(s)
	if ps != ss {
		out = append(out, shadowMismatch{Category: "grpc-status", Where: "grpc-status", Primary: excerpt(ps), Shadow: excerpt(ss)})
	}
	if pm != sm {
		out = append(out, shadowMismatch{Category: "grpc-message", Where: "grpc-message", Primary: excerpt(pm), Shadow: excerpt(sm)})
	}
	if m := compareFrames(p, s, c); m != nil {
		out = append(out, *m)
	}
	return append(out, latencyMismatch(p, s, c)...)
}

func compareFrames(p, s *respCapture, c *CShadow) *shadowMismatch {
	if bodiesSkipped(p, s) || (p.n == s.n && p.sum == s.sum && len(c.frames) == 0 && !c.frameJSON) {
		return nil
	}
	if p.n > shadowWindow || s.n > shadowWindow {
		if p.n == s.n && p.sum == s.sum {
			return nil
		}
		return compareBodies(p, s, c) // above the window frames are not parsed: whole-stream SHA-256
	}
	pf, ok1 := parseFrames(p.body)
	sf, ok2 := parseFrames(s.body)
	if !ok1 || !ok2 {
		if bytes.Equal(p.body, s.body) {
			return nil
		}
		off, a, b := byteDiff(p.body, s.body)
		return &shadowMismatch{Category: "body", Where: fmt.Sprintf("offset %d (not whole gRPC frames)", off), Primary: a, Shadow: b}
	}
	n := min(len(pf), len(sf))
	for i := 0; i < n; i++ {
		if c.frames[i] {
			continue
		}
		where := fmt.Sprintf("frame %d", i)
		if pf[i].flag != sf[i].flag {
			return &shadowMismatch{Category: "body", Where: where + " compressed flag", Primary: fmt.Sprint(pf[i].flag), Shadow: fmt.Sprint(sf[i].flag)}
		}
		if bytes.Equal(pf[i].data, sf[i].data) {
			continue
		}
		if c.frameJSON {
			if pv, ok := decodeJSON(pf[i].data); ok {
				if sv, ok := decodeJSON(sf[i].data); ok {
					for _, jp := range c.paths {
						pv, sv = jp.prune(pv), jp.prune(sv)
					}
					path, a, b, differ := firstJSONDiff(pv, sv, "$")
					if !differ {
						continue
					}
					return &shadowMismatch{Category: "body", Where: where + " " + path, Primary: valueExcerpt(path, a), Shadow: valueExcerpt(path, b)}
				}
			}
		}
		off, a, b := byteDiff(pf[i].data, sf[i].data)
		return &shadowMismatch{Category: "body", Where: fmt.Sprintf("%s offset %d (%d vs %d bytes)", where, off, len(pf[i].data), len(sf[i].data)), Primary: a, Shadow: b}
	}
	if len(pf) != len(sf) {
		return &shadowMismatch{Category: "body", Where: "frames", Primary: fmt.Sprintf("%d frames", len(pf)), Shadow: fmt.Sprintf("%d frames", len(sf))}
	}
	return nil
}

// mirrorRequest builds the copy of out sent to a mirror backend.
func mirrorRequest(out *http.Request, m *CMirror, body io.Reader, length int64) (*http.Request, *http.Client, bool) {
	ep := m.B.pick()
	if ep == nil {
		return nil, nil, false
	}
	u := *out.URL
	u.Scheme, u.Host = ep.URL.Scheme, ep.URL.Host
	req, err := http.NewRequest(out.Method, u.String(), body)
	if err != nil {
		return nil, nil, false
	}
	req.ContentLength = length
	req.Header = out.Header.Clone()
	req.Header.Set("X-Setura-Mirror", "1")
	req.Host = out.Host
	return req, nil, true
}

// fireSpooled sends the finished copy of a request body to every mirror: the
// compared ones through the pool, the rest fire-and-forget. For gRPC the
// transport is HTTP/2; plain HTTP uses the shared HTTP/1 pool.
func (s *Server) fireSpooled(out *http.Request, mirrors []*CMirror, sc *shadowReq, sp *bodySpool, grpc bool) {
	for _, m := range mirrors {
		if m.Percent <= 0 || (m.Percent < 100 && s.intn(100) >= m.Percent) {
			continue
		}
		body := sp.open()
		if body == nil {
			return
		}
		req, _, ok := mirrorRequest(out, m, body, sp.size())
		if !ok {
			body.Close()
			continue
		}
		var tr http.RoundTripper = s.backendTransport(m.B)
		if grpc {
			ep := req.URL
			g := s.grpcTransport(m.B, ep.Scheme)
			if g == nil {
				body.Close()
				continue
			}
			tr = g
			req.Header.Set("Te", "trailers")
		}
		client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
		if sc.submit(m, req, client) {
			continue
		}
		s.mirrorWG.Add(1)
		go func() {
			defer s.mirrorWG.Done()
			if resp, err := client.Do(req); err == nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
			}
		}()
	}
}

// grpcMirrors compiles the RequestMirror filters of a GRPCRoute rule.
func (t *Table) grpcMirrors(r *GRPCRoute, rule *GRPCRule, note func(fact)) ([]*CMirror, error) {
	var out []*CMirror
	for _, f := range rule.Filters {
		if f.Type != "RequestMirror" || f.RequestMirror == nil {
			continue
		}
		b, fc := t.backendFor("GRPCRoute", r.NS, f.RequestMirror.BackendRef)
		note(fc)
		if b == nil {
			continue
		}
		pct := 100
		if f.RequestMirror.Percent != nil {
			pct = *f.RequestMirror.Percent
		}
		cs, err := compileShadow(f.RequestMirror.ShadowDiff)
		if err != nil {
			return nil, err
		}
		out = append(out, &CMirror{B: b, Percent: pct, Shadow: cs})
	}
	return out, nil
}

// grpcShadow prepares mirroring for one gRPC call. It returns the comparison
// tracker (nil when no mirror compares) and the body spool standing in for the
// request body (nil when the rule has no mirror). The mirror copy is sent as
// soon as the client has finished its request, while the primary call runs.
func (s *Server) grpcShadow(r *http.Request, rule *CRule, backend string) (*shadowReq, *bodySpool) {
	if len(rule.Mirrors) == 0 {
		return nil, nil
	}
	sc := s.shadowStart(r, rule.RouteKey, backend, rule.Mirrors)
	ceiling := int64(maxMirrorBody)
	if sc != nil {
		sc.grpc = true
		ceiling = sc.max
	}
	sp := newSpool(r.Body, nil, ceiling)
	out := &http.Request{Method: http.MethodPost, URL: r.URL, Header: r.Header.Clone(), Host: r.Host}
	for _, h := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Upgrade", "Transfer-Encoding"} {
		out.Header.Del(h)
	}
	sp.onEOF = func() { s.fireSpooled(out, rule.Mirrors, sc, sp, true) }
	if sc != nil {
		route := rule.RouteKey
		sp.onOver = func() { s.shadow.skip(route) }
	}
	return sc, sp
}
