package setura

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// Access-log formats replay reads.
const (
	fmtJSON   = "json"   // the gateway's default access log
	fmtText   = "text"   // the gateway's --access-log-format text (logfmt)
	fmtCommon = "common" // Common or Combined Log Format (Apache, nginx, ...)
)

// logRec is one parsed access-log line. host and path alias the line buffer
// and are valid until the next line is read; the short repeated strings are
// interned so a million lines cost no per-line allocation.
type logRec struct {
	format                           string
	listener, method, route, backend string
	host, path                       []byte
	status                           int
}

func (r *logRec) reset(f string) { *r = logRec{format: f} }

// interner shares one string per distinct short value.
type interner struct{ m map[string]string }

const internMax = 8192

func (in *interner) get(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if s, ok := in.m[string(b)]; ok { // no allocation: the compiler elides the conversion
		return s
	}
	s := string(b)
	if in.m == nil {
		in.m = map[string]string{}
	}
	if len(in.m) < internMax {
		in.m[s] = s
	}
	return s
}

// parseLogLine recognises one line. ok is false when it is none of the
// supported formats. defaultHost fills the Host that Common Log Format lacks.
func (in *interner) parseLogLine(line []byte, rec *logRec, defaultHost string) (ok bool) {
	switch {
	case line[0] == '{':
		rec.reset(fmtJSON)
		if in.parseJSONFast(line, rec) {
			return true
		}
		rec.reset(fmtJSON)
		return in.parseJSONSlow(line, rec)
	case bytes.HasPrefix(line, []byte("time=")) || bytes.Contains(line, []byte(" path=")) || bytes.Contains(line, []byte(" method=")) || bytes.HasPrefix(line, []byte("host=")):
		rec.reset(fmtText)
		return in.parseLogfmt(line, rec)
	}
	rec.reset(fmtCommon)
	return in.parseCommon(line, rec, defaultHost)
}

func (in *interner) set(rec *logRec, key string, val []byte, num int) {
	switch key {
	case "host":
		rec.host = val
	case "path":
		rec.path = val
	case "method":
		rec.method = in.get(val)
	case "listener":
		rec.listener = in.get(val)
	case "route":
		rec.route = in.get(val)
	case "backend":
		rec.backend = in.get(val)
	case "status":
		rec.status = num
	}
}

// parseJSONFast reads the flat string-and-number objects the gateway writes
// without allocating. It reports false for anything else (escapes, nesting,
// malformed input), and the caller falls back to encoding/json.
func (in *interner) parseJSONFast(b []byte, rec *logRec) bool {
	i, n := 1, len(b)
	skip := func() {
		for i < n && (b[i] == ' ' || b[i] == '\t' || b[i] == ',' || b[i] == '\r') {
			i++
		}
	}
	str := func() ([]byte, bool) { // at the opening quote
		i++
		s := i
		for i < n {
			switch b[i] {
			case '"':
				v := b[s:i]
				i++
				return v, true
			case '\\':
				return nil, false
			}
			i++
		}
		return nil, false
	}
	for {
		skip()
		if i >= n {
			return false
		}
		if b[i] == '}' {
			return true
		}
		if b[i] != '"' {
			return false
		}
		k, ok := str()
		if !ok {
			return false
		}
		for i < n && (b[i] == ' ' || b[i] == ':') {
			i++
		}
		if i >= n {
			return false
		}
		switch c := b[i]; {
		case c == '"':
			v, ok := str()
			if !ok {
				return false
			}
			in.set(rec, string(k), v, 0) // k is a short key; the conversion does not escape
		case c == '-' || (c >= '0' && c <= '9'):
			s := i
			for i < n && (b[i] == '-' || b[i] == '+' || b[i] == '.' || b[i] == 'e' || b[i] == 'E' || (b[i] >= '0' && b[i] <= '9')) {
				i++
			}
			if string(k) == "status" {
				v, err := strconv.Atoi(string(b[s:i]))
				if err != nil {
					return false
				}
				rec.status = v
			}
		case c == 't' || c == 'f' || c == 'n':
			for i < n && b[i] >= 'a' && b[i] <= 'z' {
				i++
			}
		default:
			return false
		}
	}
}

type jsonLine struct {
	Listener string `json:"listener"`
	Host     string `json:"host"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Route    string `json:"route"`
	Backend  string `json:"backend"`
	Status   int    `json:"status"`
}

func (in *interner) parseJSONSlow(line []byte, rec *logRec) bool {
	var j jsonLine
	if json.Unmarshal(line, &j) != nil {
		return false
	}
	rec.listener, rec.method, rec.route, rec.backend = j.Listener, j.Method, j.Route, j.Backend
	rec.host, rec.path, rec.status = []byte(j.Host), []byte(j.Path), j.Status
	return true
}

// parseLogfmt reads key=value pairs; values are bare or Go-quoted, which is
// how the gateway's text format writes them.
func (in *interner) parseLogfmt(b []byte, rec *logRec) bool {
	i, n := 0, len(b)
	seen := false
	for i < n {
		for i < n && b[i] == ' ' {
			i++
		}
		s := i
		for i < n && b[i] != '=' && b[i] != ' ' {
			i++
		}
		if i >= n || b[i] != '=' {
			if i == s {
				break
			}
			continue // a bare word
		}
		k := b[s:i]
		i++
		var v []byte
		if i < n && b[i] == '"' {
			s = i
			i++
			esc := false
			for i < n && b[i] != '"' {
				if b[i] == '\\' {
					esc = true
					i++
				}
				i++
			}
			if i >= n {
				return false
			}
			i++
			if esc {
				u, err := strconv.Unquote(string(b[s:i]))
				if err != nil {
					return false
				}
				v = []byte(u)
			} else {
				v = b[s+1 : i-1]
			}
		} else {
			s = i
			for i < n && b[i] != ' ' {
				i++
			}
			v = b[s:i]
		}
		num := 0
		if string(k) == "status" {
			var err error
			if num, err = strconv.Atoi(string(v)); err != nil {
				return false
			}
		}
		switch string(k) {
		case "host", "path", "method", "listener", "route", "backend", "status":
			in.set(rec, string(k), v, num)
			seen = true
		}
	}
	return seen
}

// parseCommon reads Common and Combined Log Format:
//
//	127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "ref" "agent"
//
// The format has no Host header; defaultHost (or an absolute request target)
// supplies it. Without either the line parses with an empty host and the
// caller counts it as incomplete.
func (in *interner) parseCommon(b []byte, rec *logRec, defaultHost string) bool {
	lb := bytes.IndexByte(b, '[')
	if lb < 0 {
		return false
	}
	rb := bytes.IndexByte(b[lb:], ']')
	if rb < 0 {
		return false
	}
	i := lb + rb + 1
	for i < len(b) && b[i] == ' ' {
		i++
	}
	if i >= len(b) || b[i] != '"' {
		return false
	}
	i++
	s := i
	for i < len(b) && b[i] != '"' {
		if b[i] == '\\' {
			i++
		}
		i++
	}
	if i >= len(b) {
		return false
	}
	reqLine := b[s:i]
	rest := bytes.TrimLeft(b[i+1:], " ")
	end := bytes.IndexByte(rest, ' ')
	if end < 0 {
		end = len(rest)
	}
	status, err := strconv.Atoi(string(rest[:end]))
	if err != nil {
		return false
	}
	sp := bytes.IndexByte(reqLine, ' ')
	if sp <= 0 {
		return false // "-" for a request that never completed
	}
	method, target := reqLine[:sp], reqLine[sp+1:]
	if sp2 := bytes.LastIndexByte(target, ' '); sp2 > 0 && bytes.HasPrefix(target[sp2+1:], []byte("HTTP/")) {
		target = target[:sp2]
	}
	if len(target) == 0 {
		return false
	}
	rec.method, rec.status = in.get(method), status
	rec.host = []byte(defaultHost)
	if bytes.HasPrefix(target, []byte("http://")) || bytes.HasPrefix(target, []byte("https://")) {
		u := target[bytes.Index(target, []byte("://"))+3:]
		if slash := bytes.IndexByte(u, '/'); slash >= 0 {
			rec.host, target = u[:slash], u[slash:]
		} else {
			rec.host, target = u, []byte("/")
		}
	}
	rec.path = target
	return true
}

// isGRPCLog decides whether a logged request was a gRPC call. The log has no
// content type, so this uses what it has: the route the gateway chose (a
// GRPCRoute) or, when no route matched, a POST to /package.Service/Method.
func isGRPCLog(rec *logRec) bool {
	switch {
	case strings.HasPrefix(rec.route, "GRPCRoute/"):
		return true
	case rec.route != "" || rec.method != "POST":
		return false
	}
	p := rec.path
	if q := bytes.IndexByte(p, '?'); q >= 0 {
		p = p[:q]
	}
	if len(p) < 4 || p[0] != '/' {
		return false
	}
	slash := bytes.IndexByte(p[1:], '/')
	if slash < 0 {
		return false
	}
	svc, meth := p[1:1+slash], p[2+slash:]
	return bytes.IndexByte(svc, '.') > 0 && len(meth) > 0 && meth[0] >= 'A' && meth[0] <= 'Z' && bytes.IndexByte(meth, '/') < 0
}
