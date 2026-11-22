package gateway

import (
	"bytes"
	"io"
	"net/http"
)

// bigBody handles a request body that outgrew the in-memory mirror buffer
// (maxMirrorBody). head is what was already read. When a mirror compares and
// its maxBody ceiling allows the body, the rest streams through a spool (memory
// up to shadowWindow, then a temporary file) and the compared mirrors fire when
// the body ends. Otherwise the old behaviour holds: no mirror copy is sent; and
// when a comparing mirror's ceiling is exceeded the request counts as skipped.
func (s *Server) bigBody(r *http.Request, head []byte, mirrors []*CMirror) ([]*CMirror, *bodySpool) {
	var cm []*CMirror
	var ceiling int64
	for _, m := range mirrors {
		if on, _ := m.Shadow.effective(s.opts.ShadowDiff); on {
			cm = append(cm, m)
			ceiling = max(ceiling, m.Shadow.max())
		}
	}
	src := io.NopCloser(io.MultiReader(bytes.NewReader(head), r.Body))
	if len(cm) == 0 {
		r.Body = src
		return nil, nil
	}
	sp := newSpool(src, nil, ceiling)
	r.Body = sp
	return cm, sp
}

// fireMirrorsOrSpool sends the mirror copies now when the body is buffered in
// memory, or arms the spool to send them when the body has been read.
func (s *Server) fireMirrorsOrSpool(out *http.Request, body []byte, mirrors []*CMirror, sc *shadowReq, sp *bodySpool) {
	if sp == nil {
		s.fireMirrors(out, body, mirrors, sc)
		return
	}
	u := *out.URL
	o := &http.Request{Method: out.Method, URL: &u, Header: out.Header.Clone(), Host: out.Host}
	sp.onEOF = func() { s.fireSpooled(o, mirrors, sc, sp, false) }
}
