package gateway

import (
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type authSeen struct {
	Path, Method, Host, Authorization, Other string
	ContentLength                            int64
	Body                                     string
}

// httpAuthServer allows "Bearer ok", denies "Bearer bad" with 403 and a body.
func httpAuthServer(t *testing.T) (*httptest.Server, func() []authSeen) {
	var mu sync.Mutex
	var seen []authSeen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, authSeen{Path: r.URL.RequestURI(), Method: r.Method, Host: r.Host, Authorization: r.Header.Get("Authorization"),
			Other: r.Header.Get("X-Other"), ContentLength: r.ContentLength, Body: string(b)})
		mu.Unlock()
		switch r.Header.Get("Authorization") {
		case "Bearer ok":
			w.Header().Set("X-User", "alice")
			w.Header().Set("X-Secret", "dropped")
			w.WriteHeader(200)
		case "Bearer bad":
			w.Header().Set("X-Reason", "bad-token")
			w.WriteHeader(403)
			io.WriteString(w, "nope")
		default:
			w.WriteHeader(401)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []authSeen { mu.Lock(); defer mu.Unlock(); return append([]authSeen(nil), seen...) }
}

func authRoute(proto string, backend string, extra m) m {
	a := m{"protocol": proto, "backendRef": ref(backend, -1)}
	for k, v := range extra {
		a[k] = v
	}
	rl := rule("/", ref("a", 1))
	rl["filters"] = l{m{"type": "ExternalAuth", "externalAuth": a}, m{"type": "CORS", "cors": m{"allowOrigins": l{"*"}}}}
	return route("auth.test", rl)
}

func TestExternalAuthHTTP(t *testing.T) {
	be, ups := upstreams(t, "a")
	auth, seen := httpAuthServer(t)
	be["authz"] = strings.TrimPrefix(auth.URL, "http://")
	route1 := authRoute("HTTP", "authz", m{"http": m{"path": "/verify", "allowedHeaders": l{"X-Other"}, "allowedResponseHeaders": l{"X-User"}}})
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route1}, be), nil)
	c := client(s.Addr(8080), nil)

	// Allowed: the auth service's X-User replaces the client's, X-Secret is not copied.
	r := req(t, c, "http", "POST", "auth.test:8080", "/orders?x=1", "payload", "Authorization", "Bearer ok", "X-Other", "o", "X-User", "mallory", "X-Secret", "client", "Cookie", "c=1")
	if r.Status != 200 || r.Echo.Headers["x-user"] != "alice" || r.Echo.Headers["x-secret"] != "client" {
		t.Fatalf("allowed request: %d %+v", r.Status, r.Echo.Headers)
	}
	if r.Echo.Body != "payload" {
		t.Errorf("the backend must still get the body, got %q", r.Echo.Body)
	}
	a := seen()
	if len(a) != 1 || a[0].Path != "/verify/orders?x=1" || a[0].Method != "POST" || a[0].Host != "auth.test:8080" || a[0].Authorization != "Bearer ok" || a[0].Other != "o" {
		t.Fatalf("auth request: %+v", a)
	}
	if a[0].ContentLength != 0 || a[0].Body != "" {
		t.Errorf("without forwardBody the auth request has no body: %+v", a[0])
	}
	// Denied: the auth service's status, headers and body go to the client; the backend is never reached.
	n := len(ups["a"].seen())
	r = req(t, c, "http", "GET", "auth.test:8080", "/orders", "", "Authorization", "Bearer bad", "Origin", "https://app.test")
	if r.Status != 403 || r.Body != "nope" || r.Header.Get("X-Reason") != "bad-token" {
		t.Errorf("denied: %d %q %v", r.Status, r.Body, r.Header)
	}
	if r.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("a denial must still carry CORS headers: %v", r.Header)
	}
	if r = req(t, c, "http", "GET", "auth.test:8080", "/orders", ""); r.Status != 401 {
		t.Errorf("anonymous: %d", r.Status)
	}
	if len(ups["a"].seen()) != n {
		t.Errorf("denied requests reached the backend")
	}
	// The auth service is down: fail closed with 403.
	auth.Close()
	if r = req(t, c, "http", "GET", "auth.test:8080", "/orders", "", "Authorization", "Bearer ok"); r.Status != 403 {
		t.Errorf("unreachable auth service must deny, got %d", r.Status)
	}
}

func TestExternalAuthForwardBodyAndAllHeaders(t *testing.T) {
	be, ups := upstreams(t, "a")
	auth, seen := httpAuthServer(t)
	be["authz"] = strings.TrimPrefix(auth.URL, "http://")
	// No allowedResponseHeaders: every header of the answer (bar the hop and entity ones) is copied.
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": authRoute("HTTP", "authz", m{"forwardBody": m{"maxSize": 4}})}, be), nil)
	r := req(t, client(s.Addr(8080), nil), "http", "POST", "auth.test:8080", "/x", "abcdefgh", "Authorization", "Bearer ok")
	if r.Status != 200 || r.Echo.Body != "abcdefgh" || r.Echo.Headers["x-user"] != "alice" || r.Echo.Headers["x-secret"] != "dropped" {
		t.Fatalf("forwarded: %d body %q %v", r.Status, r.Echo.Body, r.Echo.Headers)
	}
	if a := seen(); len(a) != 1 || a[0].Body != "abcd" {
		t.Errorf("the auth service gets the first maxSize bytes: %+v", a)
	}
	_ = ups
}

// grpcAuthServer is an h2c Envoy ext_authz server: "authorization: ok" allows
// and sets x-user, anything else is denied with 401 and a body.
func grpcAuthServer(t *testing.T) string {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != grpcAuthPath {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var hdr = map[string]string{}
		attrs, _ := pbParse(raw[5:])
		for _, a := range attrs { // CheckRequest.attributes
			af, _ := pbParse(a.b)
			for _, f := range af {
				if f.num != 4 {
					continue
				}
				rf, _ := pbParse(f.b) // request
				for _, x := range rf {
					if x.num != 2 {
						continue
					}
					hf, _ := pbParse(x.b) // http
					for _, h := range hf {
						if h.num == 3 {
							kv, _ := pbParse(h.b)
							hdr[string(kv[0].b)] = string(kv[1].b)
						}
					}
				}
			}
		}
		var resp []byte
		if hdr["authorization"] == "ok" {
			hv := pbString(pbString(nil, 1, "x-user"), 2, "bob")
			opt := pbBytes(nil, 1, hv)
			resp = pbBytes(resp, 3, pbBytes(nil, 2, opt))
		} else {
			resp = pbBytes(resp, 1, pbVarint(pbVarint(nil, 1<<3), 7)) // status.code = PERMISSION_DENIED
			status := pbVarint(pbVarint(nil, 1<<3), 401)
			hv := pbBytes(nil, 1, pbString(pbString(nil, 1, "x-deny"), 2, "yes"))
			denied := append(pbBytes(nil, 1, status), pbBytes(nil, 2, hv)...)
			denied = pbBytes(denied, 3, []byte("go away"))
			resp = pbBytes(resp, 2, denied)
		}
		frame := make([]byte, 5, 5+len(resp))
		binary.BigEndian.PutUint32(frame[1:], uint32(len(resp)))
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.Write(append(frame, resp...))
		w.Header().Set("Grpc-Status", "0")
	}))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &p
	srv.Start()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestExternalAuthGRPC(t *testing.T) {
	be, ups := upstreams(t, "a")
	be["authz"] = grpcAuthServer(t)
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": authRoute("GRPC", "authz", m{"grpc": m{"allowedHeaders": l{"Authorization"}}})}, be), nil)
	c := client(s.Addr(8080), nil)
	r := req(t, c, "http", "GET", "auth.test:8080", "/x", "", "Authorization", "ok", "X-User", "mallory")
	if r.Status != 200 || r.Echo.Headers["x-user"] != "bob" {
		t.Fatalf("grpc allow: %d %+v", r.Status, r.Echo.Headers)
	}
	n := len(ups["a"].seen())
	r = req(t, c, "http", "GET", "auth.test:8080", "/x", "", "Authorization", "nope")
	if r.Status != 401 || r.Body != "go away" || r.Header.Get("X-Deny") != "yes" {
		t.Fatalf("grpc deny: %d %q %v", r.Status, r.Body, r.Header)
	}
	if len(ups["a"].seen()) != n {
		t.Error("a denied request reached the backend")
	}
}

func TestExternalAuthInvalid(t *testing.T) {
	be, _ := upstreams(t, "a")
	for _, a := range []m{{"protocol": "SOAP", "backendRef": ref("a", -1)}, {"protocol": "HTTP"}, {"protocol": "HTTP", "backendRef": ref("a", -1), "grpc": m{}}} {
		rl := rule("/", ref("a", 1))
		rl["filters"] = l{m{"type": "ExternalAuth", "externalAuth": a}}
		tb := tableOf(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, be), nil)
		st := BuildStatus(tb, nil, tnow(), nil)
		if c := cond(st.Routes["t/r"].Parents[0].Conditions, "Accepted"); c.Status != "False" {
			t.Errorf("%v must be refused: %+v", a, c)
		}
	}
	// An unresolvable auth backend fails closed with a 500 and shows in ResolvedRefs.
	rl := rule("/", ref("a", 1))
	rl["filters"] = l{m{"type": "ExternalAuth", "externalAuth": m{"protocol": "HTTP", "backendRef": ref("missing", -1)}}}
	s := startServer(t, snap(httpGateway(""), map[string]m{"r": route("", rl)}, be), nil)
	if r := get(t, s, "x.test", "/"); r.Status != 500 {
		t.Errorf("unresolved auth backend: %d", r.Status)
	}
	if c := cond(s.Status().Routes["t/r"].Parents[0].Conditions, "ResolvedRefs"); c.Status != "False" || c.Reason != "BackendNotFound" {
		t.Errorf("ResolvedRefs: %+v", c)
	}
}
