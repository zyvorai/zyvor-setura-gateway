package gateway

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SessionPersistence is the Gateway API session persistence policy of a rule:
// a client that presents the token the gateway gave it goes back to the same
// backendRef and endpoint, as long as that endpoint is healthy and the session
// is neither idle nor past its absolute lifetime.
type SessionPersistence struct {
	SessionName     string `json:"sessionName,omitempty"`
	Type            string `json:"type,omitempty"` // Cookie (default) or Header
	AbsoluteTimeout string `json:"absoluteTimeout,omitempty"`
	IdleTimeout     string `json:"idleTimeout,omitempty"`
	CookieConfig    *struct {
		LifetimeType string `json:"lifetimeType,omitempty"` // Session (default) or Permanent
	} `json:"cookieConfig,omitempty"`
}

// CSession is a compiled SessionPersistence.
type CSession struct {
	Name      string
	Header    bool
	Absolute  time.Duration
	Idle      time.Duration
	Permanent bool
}

const defaultSessionName = "setura-session"

func compileSession(sp *SessionPersistence) (*CSession, error) {
	if sp == nil {
		return nil, nil
	}
	c := &CSession{Name: sp.SessionName, Header: sp.Type == "Header"}
	switch sp.Type {
	case "", "Cookie", "Header":
	default:
		return nil, fmt.Errorf("sessionPersistence.type %q is not Cookie or Header", sp.Type)
	}
	if c.Name == "" {
		c.Name = defaultSessionName
	}
	var err error
	if c.Absolute, err = parseDur(sp.AbsoluteTimeout); err != nil {
		return nil, fmt.Errorf("sessionPersistence.absoluteTimeout: %w", err)
	}
	if c.Idle, err = parseDur(sp.IdleTimeout); err != nil {
		return nil, fmt.Errorf("sessionPersistence.idleTimeout: %w", err)
	}
	if sp.CookieConfig != nil {
		switch sp.CookieConfig.LifetimeType {
		case "", "Session":
		case "Permanent":
			c.Permanent = true
			if c.Absolute <= 0 {
				return nil, fmt.Errorf("sessionPersistence: a Permanent cookie needs absoluteTimeout")
			}
		default:
			return nil, fmt.Errorf("sessionPersistence.cookieConfig.lifetimeType %q is not Session or Permanent", sp.CookieConfig.LifetimeType)
		}
		if c.Header {
			return nil, fmt.Errorf("sessionPersistence: cookieConfig applies to cookie sessions only")
		}
	}
	return c, nil
}

var (
	sessionKeyOnce sync.Once
	sessionKey     []byte
)

// sessionSecret signs tokens. SETURA_GATEWAY_SESSION_KEY lets replicas share
// one key; without it each process makes its own and a restart ends sessions.
func sessionSecret() []byte {
	sessionKeyOnce.Do(func() {
		if k := os.Getenv("SETURA_GATEWAY_SESSION_KEY"); k != "" {
			sessionKey = []byte(k)
			return
		}
		sessionKey = make([]byte, 32)
		rand.Read(sessionKey)
	})
	return sessionKey
}

// sessionToken is what the cookie or header carries: the backendRef, the
// endpoint, when the session began and when it was last used.
type sessionToken struct {
	ref, ep       string
	issued, lastN int64
}

func (t sessionToken) encode() string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(strings.Join([]string{t.ref, t.ep, strconv.FormatInt(t.issued, 10), strconv.FormatInt(t.lastN, 10)}, "|")))
	mac := hmac.New(sha256.New, sessionSecret())
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
}

func decodeSessionToken(s string) (sessionToken, bool) {
	payload, sig, ok := strings.Cut(s, ".")
	if !ok {
		return sessionToken{}, false
	}
	mac := hmac.New(sha256.New, sessionSecret())
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return sessionToken{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return sessionToken{}, false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 {
		return sessionToken{}, false
	}
	t := sessionToken{ref: parts[0], ep: parts[1]}
	t.issued, _ = strconv.ParseInt(parts[2], 10, 64)
	t.lastN, _ = strconv.ParseInt(parts[3], 10, 64)
	return t, true
}

// read finds the client's token for policy c on r.
func (c *CSession) read(r *http.Request) string {
	if c.Header {
		return r.Header.Get(c.Name)
	}
	if ck, err := r.Cookie(c.Name); err == nil {
		return ck.Value
	}
	return ""
}

// valid reports whether tok is still a live session at now.
func (c *CSession) valid(tok sessionToken, now time.Time) bool {
	if c.Absolute > 0 && now.Sub(time.Unix(tok.issued, 0)) > c.Absolute {
		return false
	}
	if c.Idle > 0 && now.Sub(time.Unix(tok.lastN, 0)) > c.Idle {
		return false
	}
	return true
}

// policies lists the session policies that can apply to rule: the rule's own
// and each backendRef's.
func (rule *CRule) sessionPolicies() []*CSession {
	var out []*CSession
	if rule.Session != nil {
		out = append(out, rule.Session)
	}
	for _, r := range rule.Refs {
		if r.Session != nil {
			out = append(out, r.Session)
		}
	}
	return out
}

// sessionPolicyFor is the policy that governs traffic to ref.
func (rule *CRule) sessionPolicyFor(ref *CRef) *CSession {
	if rule.Session != nil {
		return rule.Session
	}
	return ref.Session
}

// sessionPin returns the backendRef and endpoint the request's session names,
// when the session is live and the endpoint is still usable: never one that is
// ejected, unhealthy or gone.
func (s *Server) sessionPin(rule *CRule, r *http.Request, now time.Time) (*CRef, *Endpoint) {
	for _, pol := range rule.sessionPolicies() {
		raw := pol.read(r)
		if raw == "" {
			continue
		}
		tok, ok := decodeSessionToken(raw)
		if !ok || !pol.valid(tok, now) {
			continue
		}
		for _, ref := range rule.Refs {
			if ref.Name != tok.ref || ref.B == nil || ref.Weight <= 0 || rule.sessionPolicyFor(ref) != pol {
				continue
			}
			for _, ep := range ref.B.Eps {
				if ep.URL.Host == tok.ep && ref.B.state(ep, now) == "healthy" {
					return ref, ep
				}
			}
		}
	}
	return nil, nil
}

// sessionAnnotate stamps the session token for the endpoint that served the
// request onto the response headers. A session that was just pinned keeps its
// start time. Endpoints that are not healthy never get a session.
func (s *Server) sessionAnnotate(h http.Header, rule *CRule, ref *CRef, r *http.Request, served *Endpoint, tlsPort bool, now time.Time) {
	pol := rule.sessionPolicyFor(ref)
	if pol == nil || served == nil || ref.B.state(served, now) != "healthy" {
		return
	}
	tok := sessionToken{ref: ref.Name, ep: served.URL.Host, issued: now.Unix(), lastN: now.Unix()}
	changed := true
	if old, ok := decodeSessionToken(pol.read(r)); ok && pol.valid(old, now) {
		if old.ref == tok.ref && old.ep == tok.ep {
			tok.issued = old.issued
			changed = false
		}
	}
	if !changed && pol.Idle <= 0 {
		return // nothing to refresh
	}
	if pol.Header {
		h.Set(pol.Name, tok.encode())
		return
	}
	ck := &http.Cookie{Name: pol.Name, Value: tok.encode(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Secure: tlsPort}
	if pol.Permanent {
		left := pol.Absolute - now.Sub(time.Unix(tok.issued, 0))
		if left < time.Second {
			left = time.Second
		}
		ck.MaxAge = int(left / time.Second)
	}
	h.Add("Set-Cookie", ck.String())
}

func describeSession(c *CSession) string {
	kind := "cookie"
	if c.Header {
		kind = "header"
	}
	s := fmt.Sprintf("session persistence by %s %q", kind, c.Name)
	if c.Absolute > 0 {
		s += ", absolute timeout " + c.Absolute.String()
	}
	if c.Idle > 0 {
		s += ", idle timeout " + c.Idle.String()
	}
	return s
}
