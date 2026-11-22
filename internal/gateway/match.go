package gateway

import (
	"net/http"
	"strings"
)

// score ranks a matching entry. Fields compare in order, which implements the
// Gateway API precedence: hostname specificity, exact path, longest prefix,
// method, header count, query-parameter count. Ties keep the earlier entry
// (older route, then name, then rule and match order).
type score struct{ host, pathKind, pathLen, method, headers, query int }

func (a score) better(b score) bool {
	switch {
	case a.host != b.host:
		return a.host > b.host
	case a.pathKind != b.pathKind:
		return a.pathKind > b.pathKind
	case a.pathLen != b.pathLen:
		return a.pathLen > b.pathLen
	case a.method != b.method:
		return a.method > b.method
	case a.headers != b.headers:
		return a.headers > b.headers
	}
	return a.query > b.query
}

// Path kinds: Exact beats RegularExpression beats PathPrefix. The spec leaves
// regular-expression precedence to the implementation; this matches Envoy
// Gateway, and keeps a catch-all "/" prefix from shadowing every regex.
const (
	kindPrefix = 1
	kindRegex  = 2
	kindExact  = 3
)

// prefixMatches implements element-wise PathPrefix matching.
func prefixMatches(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

// matches evaluates the match against a request and returns its score parts.
func (m *CMatch) matches(r *http.Request) (score, bool) {
	var s score
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	switch m.PathType {
	case "Exact":
		if path != m.PathValue {
			return s, false
		}
		s.pathKind, s.pathLen = kindExact, len(m.PathValue)
	case "PathPrefix":
		if !prefixMatches(m.PathValue, path) {
			return s, false
		}
		s.pathKind, s.pathLen = kindPrefix, len(m.PathValue)
	case "RegularExpression":
		if !m.PathRe.MatchString(path) {
			return s, false
		}
		s.pathKind = kindRegex
	}
	if m.Method != "" {
		if r.Method != m.Method {
			return s, false
		}
		s.method = 1
	}
	for _, h := range m.Headers {
		v := r.Header.Get(h.Name)
		if r.Header.Values(h.Name) == nil || !valueOK(h, v) {
			return s, false
		}
	}
	s.headers = len(m.Headers)
	if len(m.Query) > 0 {
		q := r.URL.Query()
		for _, h := range m.Query {
			vals, ok := q[h.Name]
			if !ok || !valueOK(h, vals[0]) {
				return s, false
			}
		}
	}
	s.query = len(m.Query)
	return s, true
}

func valueOK(m cvm, v string) bool {
	if m.Re != nil {
		return m.Re.MatchString(v)
	}
	return v == m.Value
}

// hostOnly strips the port and lowercases a Host header.
func hostOnly(h string) string {
	h = strings.ToLower(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.Index(h, "]"); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}
	return strings.TrimSuffix(h, ".")
}

// pickListener returns the most specific listener whose hostname matches.
func (pg *PortGroup) pickListener(host string) *RTListener {
	var best *RTListener
	bestRank := -1
	for _, l := range pg.Listeners {
		if hostMatches(l.Host, host) && hostRank(l.Host) > bestRank {
			best, bestRank = l, hostRank(l.Host)
		}
	}
	return best
}

// selectEntry finds the winning entry for a request on this listener.
func (l *RTListener) selectEntry(r *http.Request, host string) *Entry {
	var best *Entry
	var bestScore score
	for _, e := range l.Entries {
		if e.GRPC != isGRPC(r) {
			continue
		}
		rank, ok := -1, false
		for _, h := range e.Hosts {
			if hostMatches(h, host) && hostRank(h) > rank {
				rank, ok = hostRank(h), true
			}
		}
		if !ok {
			continue
		}
		s, ok := e.Match.matches(r)
		if !ok {
			continue
		}
		s.host = rank
		if best == nil || s.better(bestScore) {
			best, bestScore = e, s
		}
	}
	return best
}
