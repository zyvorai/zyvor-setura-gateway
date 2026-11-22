package gateway

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig is a local (per gateway process) token bucket.
type RateLimitConfig struct {
	Rate  float64       // tokens added per Per; 0 disables limiting
	Per   time.Duration // default one second
	Burst int           // bucket size; default ceil(rate per second), at least 1
	Key   string        // "ip" (default), "route" or "header:NAME"
}

// ParseRate parses "100/s", "30/m", "5000/h" or a bare number (per second).
func ParseRate(v string) (float64, time.Duration, error) {
	num, unit, _ := strings.Cut(strings.TrimSpace(v), "/")
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n <= 0 || math.IsInf(n, 0) || math.IsNaN(n) {
		return 0, 0, fmt.Errorf("rate %q: want N/s, N/m or N/h with N > 0", v)
	}
	switch unit {
	case "", "s", "sec", "second":
		return n, time.Second, nil
	case "m", "min", "minute":
		return n, time.Minute, nil
	case "h", "hour":
		return n, time.Hour, nil
	}
	return 0, 0, fmt.Errorf("rate %q: unit must be s, m or h", v)
}

func (c *RateLimitConfig) validate() error {
	if c.Rate == 0 {
		return nil
	}
	if c.Rate < 0 {
		return errors.New("rate must be positive")
	}
	if c.Burst < 0 {
		return errors.New("burst must not be negative")
	}
	switch k := c.Key; {
	case k == "" || k == "ip" || k == "route":
	case strings.HasPrefix(k, "header:") && len(k) > len("header:"):
	default:
		return fmt.Errorf("rate key %q: want ip, route or header:NAME", k)
	}
	return nil
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	sweepAbove = 10000  // sweep idle buckets once the table is this big
	maxBuckets = 100000 // hard cap; new keys share nothing and are refused above it
)

type limiter struct {
	mu      sync.Mutex
	perSec  float64
	burst   float64
	key     string
	header  string
	now     func() time.Time
	buckets map[string]*bucket
	limited map[string]int64 // per route
	allowed int64
}

func newLimiter(c RateLimitConfig, now func() time.Time) *limiter {
	if c.Rate <= 0 {
		return nil
	}
	if c.Per <= 0 {
		c.Per = time.Second
	}
	if now == nil {
		now = time.Now
	}
	perSec := c.Rate / c.Per.Seconds()
	burst := c.Burst
	if burst <= 0 {
		burst = int(math.Ceil(perSec))
		if burst < 1 {
			burst = 1
		}
	}
	l := &limiter{perSec: perSec, burst: float64(burst), key: c.Key, now: now, buckets: map[string]*bucket{}, limited: map[string]int64{}}
	if l.key == "" {
		l.key = "ip"
	}
	if h, ok := strings.CutPrefix(l.key, "header:"); ok {
		l.header = h
	}
	return l
}

func clientIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// allow takes one token for the request. When refused it returns how long
// until a token is available.
func (l *limiter) allow(route string, r *http.Request) (bool, time.Duration) {
	var k string
	switch {
	case l.key == "route":
		k = route
	case l.header != "":
		v := r.Header.Get(l.header)
		if v == "" {
			v = "ip:" + clientIP(r)
		}
		k = route + "\x00" + v
	default:
		k = route + "\x00" + clientIP(r)
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[k]
	if b == nil {
		if len(l.buckets) >= sweepAbove {
			l.sweep(now)
		}
		if len(l.buckets) >= maxBuckets {
			l.limited[route]++
			return false, time.Second
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[k] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.perSec)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		l.allowed++
		return true, 0
	}
	l.limited[route]++
	return false, time.Duration((1 - b.tokens) / l.perSec * float64(time.Second))
}

// sweep drops buckets that have refilled completely (they carry no state).
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.perSec >= l.burst {
			delete(l.buckets, k)
		}
	}
}

func (l *limiter) snapshot() (allowed int64, limited map[string]int64, buckets int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	limited = make(map[string]int64, len(l.limited))
	for k, v := range l.limited {
		limited[k] = v
	}
	return l.allowed, limited, len(l.buckets)
}

func sortedRoutes(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rateLimited answers 429 with Retry-After when the route's bucket is empty.
func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, st *reqState) bool {
	l := s.obs.limiter
	if l == nil {
		return false
	}
	ok, wait := l.allow(st.route, r)
	if ok {
		return false
	}
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	st.errMsg = "rate limited"
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	plain(w, http.StatusTooManyRequests, "rate limit exceeded")
	return true
}
