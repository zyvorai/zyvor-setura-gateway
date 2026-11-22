package gateway

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"strings"
)

// Admin endpoint authentication. The rules are the dashboard's: with no token
// the endpoint answers only a loopback Host (so a hostile web page cannot read
// it through DNS rebinding) and may bind only loopback; with a token every
// request needs it as "Authorization: Bearer TOKEN" or the session cookie, and
// the endpoint may bind anywhere. The token is compared in constant time and is
// never logged, printed or put in an error.

// adminCookie is the session cookie a valid ?token= request sets.
const adminCookie = "setura_admin"

// loopbackHost reports whether host (a name, an address, or host:port) is
// loopback. An empty host is not: net.Listen(":port") binds every interface.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkAdminBind refuses a non-loopback admin address without a token.
func checkAdminBind(addr, token string) error {
	if token != "" || loopbackHost(addr) {
		return nil
	}
	return errors.New("refusing to expose the admin endpoint on a non-loopback address without a token; add --admin-token VALUE (or set SETURA_ADMIN_TOKEN), or bind 127.0.0.1")
}

func tokenEq(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func adminAuthed(r *http.Request, token string) bool {
	if a := r.Header.Get("Authorization"); len(a) > 7 && strings.EqualFold(a[:7], "bearer ") && tokenEq(a[7:], token) {
		return true
	}
	if c, err := r.Cookie(adminCookie); err == nil && tokenEq(c.Value, token) {
		return true
	}
	return false
}

// adminGuard wraps the admin handler. openReady leaves /ready reachable
// without the token (for kubelet probes).
func adminGuard(next http.Handler, token string, openReady bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if openReady && r.URL.Path == "/ready" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			next.ServeHTTP(w, r)
			return
		}
		if token == "" {
			if !loopbackHost(r.Host) {
				http.Error(w, "forbidden host; use http://127.0.0.1:PORT or http://localhost:PORT", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if t := r.URL.Query().Get("token"); t != "" && r.Method == http.MethodGet && tokenEq(t, token) {
			// Trade the token in the URL for a cookie, and take it out of the address bar.
			http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: t, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil})
			q := r.URL.Query()
			q.Del("token")
			target := r.URL.Path
			if len(q) > 0 {
				target += "?" + q.Encode()
			}
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
		if !adminAuthed(r, token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="setura-admin"`)
			http.Error(w, "token required: send Authorization: Bearer TOKEN", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
