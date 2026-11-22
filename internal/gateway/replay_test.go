package gateway

import "testing"

func TestResolveHTTPSWithoutCertsAndHeaders(t *testing.T) {
	raw := `{"schema":"setura.route-specs/v1","namespace":"t","resources":{
"gateways.gateway.networking.k8s.io/gw":{"gatewayClassName":"setura","listeners":[{"name":"tls","protocol":"HTTPS","port":443,"tls":{"certificateRefs":[{"name":"missing"}]}}]},
"httproutes.gateway.networking.k8s.io/r":{"parentRefs":[{"name":"gw"}],"rules":[
{"matches":[{"headers":[{"name":"X-A","value":"1"}]}],"backendRefs":[{"name":"b","port":80}]},
{"backendRefs":[{"name":"a","port":80},{"name":"ghost","port":80,"weight":3}]}]}},
"backends":{"a:80":{"endpoints":["127.0.0.1:1"]},"b:80":{"endpoints":["127.0.0.1:2"]}}}`
	tb, err := ParseReplayConfig([]byte(raw), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := tb.Resolve(ReqSpec{Host: "x.test:443", Method: "get", Path: "/p?q=1"})
	if d.Outcome != OutcomeRouted || d.Listener != "t/gw/tls" || !d.HeaderDependent || len(d.Backends) != 2 {
		t.Fatalf("%+v", d)
	}
	if d.Backends[1].Key != NoBackendKey && d.Backends[0].Key != NoBackendKey {
		t.Errorf("backends %+v", d.Backends)
	}
	if got := tb.ListenerPort("t/gw/tls"); got != 443 {
		t.Errorf("port %d", got)
	}
	if d := tb.Resolve(ReqSpec{Port: 8080, Host: "x.test", Method: "GET", Path: "/"}); d.Outcome != OutcomeNoListener || d.Status != 404 {
		t.Errorf("wrong port: %+v", d)
	}
}
