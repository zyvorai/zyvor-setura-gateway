package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"testing"
)

func adminJSON(t *testing.T, s *Server, path string, v any) {
	t.Helper()
	resp, err := http.Get("http://" + s.AdminAddr() + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("%s: %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

// With --port-map the spec port 8080 is served on a random real port. Asking
// why about the real port must give the verdict that port serves.
func TestWhyAdminMapsRealPortThroughPortMap(t *testing.T) {
	be, _ := upstreams(t, "a")
	routes := map[string]m{"r": route("", rule("/", ref("a", 1)))}
	s := startServer(t, snap(httpGateway(""), routes, be), nil)
	s.opts.Admin = "127.0.0.1:0"
	if err := s.startAdmin(); err != nil {
		t.Fatal(err)
	}
	var st StatusDoc
	adminJSON(t, s, "/status", &st)
	if len(st.Listening) != 1 || st.Listening[0].Spec != 8080 || st.Listening[0].Port() == 8080 || st.Listening[0].Port() == 0 {
		t.Fatalf("/status must list the real listener: %+v", st.Listening)
	}
	real := st.Listening[0].Port()
	for _, port := range []int{real, 8080} { // the real port, and the spec port itself
		var tr Trace
		adminJSON(t, s, "/why?method=GET&url="+url.QueryEscape(fmt.Sprintf("http://127.0.0.1:%d/a/1", port)), &tr)
		if tr.Verdict != VerdictRouted {
			t.Errorf("port %d: verdict %s\n%s", port, tr.Verdict, dumpTrace(&tr))
		}
	}
	var tr Trace
	adminJSON(t, s, "/why?method=GET&url="+url.QueryEscape("http://127.0.0.1:"+strconv.Itoa(real+1)+"/a/1"), &tr)
	if tr.Verdict == VerdictRouted {
		t.Errorf("a port nothing listens on must not route: %s", dumpTrace(&tr))
	}
}
