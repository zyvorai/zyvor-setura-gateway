package gateway

import (
	"fmt"
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
func (m *CMatch) matches(r *http.Request) (score, bool) { return m.matchesWhy(r, nil) }

// matchesWhy is matches with an optional explanation: when why is not nil and
// the match fails it receives the plain-language reason. The data path passes
// nil and pays nothing for it.
func (m *CMatch) matchesWhy(r *http.Request, why *string) (score, bool) {
	var s score
	no := func(format string, a ...any) (score, bool) {
		if why != nil {
			*why = fmt.Sprintf(format, a...)
		}
		return s, false
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	switch m.PathType {
	case "Exact":
		if path != m.PathValue {
			return no("path %q is not exactly %q", path, m.PathValue)
		}
		s.pathKind, s.pathLen = kindExact, len(m.PathValue)
	case "PathPrefix":
		if !prefixMatches(m.PathValue, path) {
			return no("path %q is not under the prefix %q (prefixes match whole path elements)", path, m.PathValue)
		}
		s.pathKind, s.pathLen = kindPrefix, len(m.PathValue)
	case "RegularExpression":
		if !m.PathRe.MatchString(path) {
			return no("path %q does not match the regular expression %q", path, m.PathValue)
		}
		s.pathKind = kindRegex
	}
	if m.Method != "" {
		if r.Method != m.Method {
			return no("method is %s, the match needs %s", r.Method, m.Method)
		}
		s.method = 1
	}
	for _, h := range m.Headers {
		v := r.Header.Get(h.Name)
		if r.Header.Values(h.Name) == nil {
			return no("header %s is missing (the match needs %s)", h.Name, h.describe())
		}
		if !valueOK(h, v) {
			return no("header %s is %q, the match needs %s", h.Name, v, h.describe())
		}
	}
	s.headers = len(m.Headers)
	if len(m.Query) > 0 {
		q := r.URL.Query()
		for _, h := range m.Query {
			vals, ok := q[h.Name]
			if !ok {
				return no("query parameter %s is missing (the match needs %s)", h.Name, h.describe())
			}
			if !valueOK(h, vals[0]) {
				return no("query parameter %s is %q, the match needs %s", h.Name, vals[0], h.describe())
			}
		}
	}
	s.query = len(m.Query)
	return s, true
}

// describe renders a header or query value matcher.
func (m cvm) describe() string {
	if m.Re != nil {
		return "a value matching regular expression " + fmt.Sprintf("%q", strings.TrimSuffix(strings.TrimPrefix(m.Re.String(), "^(?:"), ")$"))
	}
	return fmt.Sprintf("the value %q", m.Value)
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
func (pg *PortGroup) pickListener(host string) *RTListener { return pg.pickListenerT(host, nil) }

// pickListenerT is pickListener recording every listener it considers on tr
// (nil on the data path).
func (pg *PortGroup) pickListenerT(host string, tr *Trace) *RTListener {
	var best *RTListener
	bestRank := -1
	for _, l := range pg.Listeners {
		ok := hostMatches(l.Host, host)
		if tr != nil {
			tr.noteListener(l, ok)
		}
		if ok && hostRank(l.Host) > bestRank {
			best, bestRank = l, hostRank(l.Host)
		}
	}
	if tr != nil {
		tr.chooseListener(best)
	}
	return best
}

// selectEntry finds the winning entry for a request on this listener.
func (l *RTListener) selectEntry(r *http.Request, host string) *Entry {
	return l.selectEntryT(r, host, nil)
}

// selectEntryT is selectEntry recording every entry it considers on tr (nil on
// the data path, where it allocates nothing extra).
func (l *RTListener) selectEntryT(r *http.Request, host string, tr *Trace) *Entry {
	var best *Entry
	var bestScore score
	grpc := isGRPC(r)
	for _, e := range l.Entries {
		if e.GRPC != grpc {
			if tr != nil {
				tr.noteEntry(e, score{}, false, kindMismatchReason(e.GRPC))
			}
			continue
		}
		rank, ok := -1, false
		for _, h := range e.Hosts {
			if hostMatches(h, host) && hostRank(h) > rank {
				rank, ok = hostRank(h), true
			}
		}
		if !ok {
			if tr != nil {
				tr.noteEntry(e, score{}, false, fmt.Sprintf("host mismatch: request host %q does not match route hostnames %s", host, hostList(e.Hosts)))
			}
			continue
		}
		var why string
		var wp *string
		if tr != nil {
			wp = &why
		}
		s, ok := e.Match.matchesWhy(r, wp)
		if !ok {
			if tr != nil {
				tr.noteEntry(e, s, false, why)
			}
			continue
		}
		s.host = rank
		if tr != nil {
			tr.noteEntry(e, s, true, "")
		}
		if best == nil || s.better(bestScore) {
			best, bestScore = e, s
		}
	}
	return best
}
