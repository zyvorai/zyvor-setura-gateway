package gateway

import (
	"flag"
	"os"
	"regexp"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

func goldenCheck(t *testing.T, name, got string) {
	t.Helper()
	path := "testdata/" + name
	if *updateGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/gateway -run %s -update)", err, t.Name())
	}
	if got != string(want) {
		t.Errorf("%s differs from the golden file; run go test ./internal/gateway -run %s -update and review the diff", name, t.Name())
	}
}

func fullInstall() InstallOptions {
	return InstallOptions{
		Namespace: "gw", Image: "example.test/setura:1", ClassName: "edge", Replicas: 2, ExposePorts: true,
		ServiceType: "NodePort", NodePorts: map[string]int{"http": 30080, "https": 30443, "7443": 30743},
		ListenerPorts: []int{18443, 7443, 7443}, ExternalTrafficPolicy: "Local", HostNetwork: true,
		Args:             []string{"--rate-limit=100", "--rate-key=header:X-Api-Key"},
		Resources:        map[string]string{"requests.cpu": "100m", "requests.memory": "64Mi", "limits.cpu": "1", "limits.memory": "256Mi"},
		NodeSelector:     map[string]string{"node-role.kubernetes.io/edge": "true", "disk": "ssd"},
		AdminTokenSecret: "edge-admin", CreateAdminSecret: true, CRDs: true, GatewayAPIVersion: "v1.7.0",
		adminToken: "0123456789abcdef",
	}
}

func TestInstallGoldenAllOptions(t *testing.T) {
	o := fullInstall()
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	goldenCheck(t, "install_all_options.golden.yaml", Install(o))
}

func TestInstallGoldenDefaults(t *testing.T) {
	goldenCheck(t, "install_defaults.golden.yaml", Install(InstallOptions{Image: "example.test/setura:1"}))
}

// Re-applying `gateway install` output must never rotate the admin token: with
// no --create-admin-secret there is no Secret, and the output is identical run to run.
func TestInstallAdminTokenIsStable(t *testing.T) {
	a, b := Install(InstallOptions{}), Install(InstallOptions{})
	if a != b {
		t.Fatal("two prints of the same options differ")
	}
	if strings.Contains(a, "kind: Secret") || strings.Contains(a, "stringData") {
		t.Error("the default output must not contain the admin Secret")
	}
	if !strings.Contains(a, "name: setura-gateway-admin, key: token") || !strings.Contains(a, "kubectl -n setura-system create secret generic setura-gateway-admin") {
		t.Error("the Deployment must reference the Secret and the header must say how to create it")
	}
	c := Install(InstallOptions{CreateAdminSecret: true})
	d := Install(InstallOptions{CreateAdminSecret: true})
	re := regexp.MustCompile(`token: ([0-9a-f]{48})`)
	if m := re.FindStringSubmatch(c); m == nil || re.FindStringSubmatch(d)[1] == m[1] {
		t.Error("--create-admin-secret must print a fresh random 24-byte token each time")
	}
	e := Install(InstallOptions{AdminTokenSecret: "mine"})
	if !strings.Contains(e, "name: mine, key: token") || strings.Contains(e, "kind: Secret") {
		t.Error("--admin-token-secret must point the Deployment at the named Secret and print nothing")
	}
}

func TestInstallDefaultOutputUnchangedExceptSecret(t *testing.T) {
	y := Install(InstallOptions{})
	for _, want := range []string{"  type: ClusterIP\n", "    - {name: http, port: 80, targetPort: http}\n", "    - {name: https, port: 443, targetPort: https}\n", "  replicas: 1\n"} {
		if !strings.Contains(y, want) {
			t.Errorf("default output lost %q", want)
		}
	}
	for _, not := range []string{"hostNetwork", "nodeSelector", "          resources:", "nodePort", "externalTrafficPolicy", "name: listener-"} {
		if strings.Contains(y, not) {
			t.Errorf("default output has %q", not)
		}
	}
}

func TestInstallValuesCannotBreakTheTemplate(t *testing.T) {
	y := Install(InstallOptions{Args: []string{"--note=NS CLASS IMAGE"}, NodeSelector: map[string]string{"k": "NS: x"}})
	if !strings.Contains(y, `- "--note=NS CLASS IMAGE"`) || !strings.Contains(y, `k: "NS: x"`) {
		t.Errorf("values were rewritten or left unquoted:\n%s", y)
	}
}

func TestInstallValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		o    InstallOptions
		want string // "" = valid
	}{
		"ok":               {InstallOptions{ServiceType: "LoadBalancer", ExternalTrafficPolicy: "Cluster"}, ""},
		"bad type":         {InstallOptions{ServiceType: "Headless"}, "--service-type"},
		"policy on ip":     {InstallOptions{ExternalTrafficPolicy: "Local"}, "--external-traffic-policy needs"},
		"bad policy":       {InstallOptions{ServiceType: "NodePort", ExternalTrafficPolicy: "x"}, "Local or Cluster"},
		"nodeport on ip":   {InstallOptions{NodePorts: map[string]int{"http": 30080}}, "--node-port needs"},
		"nodeport unknown": {InstallOptions{ServiceType: "NodePort", NodePorts: map[string]int{"7443": 30743}}, `no port "7443"`},
		"nodeport clash":   {InstallOptions{ServiceType: "NodePort", NodePorts: map[string]int{"http": 30080, "https": 30080}}, "both use node port"},
		"reserved port":    {InstallOptions{ListenerPorts: []int{443}}, "already a port"},
		"admin port":       {InstallOptions{ListenerPorts: []int{19000}}, "already a port"},
		"port range":       {InstallOptions{ListenerPorts: []int{70000}}, "out of range"},
		"arg without dash": {InstallOptions{Args: []string{"rate-limit"}}, "--arg"},
		"bad version":      {InstallOptions{CRDs: true, GatewayAPIVersion: "1.7"}, "--gateway-api-version"},
		"bad channel":      {InstallOptions{GatewayAPIChannel: "beta"}, "standard or experimental"},
		"bad secret":       {InstallOptions{AdminTokenSecret: "Bad_Name"}, "Secret name"},
	} {
		err := tc.o.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

func TestParseInstallOptionStrings(t *testing.T) {
	np, err := ParseNodePorts("HTTP=30080, https=30443", nil)
	if err != nil || np["http"] != 30080 || np["https"] != 30443 {
		t.Errorf("%v %v", np, err)
	}
	np, err = ParseNodePorts("7443=30743", np)
	if err != nil || len(np) != 3 {
		t.Errorf("repeatable: %v %v", np, err)
	}
	for _, bad := range []string{"HTTP", "HTTP=x", "HTTP=0", "HTTP=70000", "=3"} {
		if _, err := ParseNodePorts(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseNodePorts("http=1,HTTP=2", nil); err == nil {
		t.Error("duplicate accepted")
	}
	r, err := ParseResources("requests.cpu=250m,limits.memory=1Gi", nil)
	if err != nil || r["requests.cpu"] != "250m" || r["limits.memory"] != "1Gi" {
		t.Errorf("%v %v", r, err)
	}
	for _, bad := range []string{"cpu=1", "requests.cpu=lots", "requests.gpu=1", "limits.memory"} {
		if _, err := ParseResources(bad, nil); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if kv, err := ParseKeyValues("node-selector", "a=b,c=d", nil); err != nil || kv["c"] != "d" {
		t.Errorf("%v %v", kv, err)
	}
	if _, err := ParseKeyValues("node-selector", "novalue", nil); err == nil {
		t.Error("missing = accepted")
	}
}

func TestGatewayAPIVersionHelpers(t *testing.T) {
	if c, err := CompareGatewayAPIVersion("v1.6.3", "v1.7.0"); err != nil || c != -1 {
		t.Errorf("%d %v", c, err)
	}
	if c, _ := CompareGatewayAPIVersion("v1.10.0", "v1.9.9"); c != 1 {
		t.Error("numeric, not lexical, comparison")
	}
	if c, _ := CompareGatewayAPIVersion("v1.7.0-rc.1", "v1.7.0"); c != 0 {
		t.Error("pre-release suffix is ignored")
	}
	if _, err := ParseGatewayAPIVersion("latest"); err == nil {
		t.Error("latest accepted")
	}
	if u := CRDInstallURL("v1.7.0", ""); u != "https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.7.0/standard-install.yaml" {
		t.Error(u)
	}
	if !strings.HasSuffix(CRDInstallURL("v1.7.0", "experimental"), "/experimental-install.yaml") {
		t.Error("experimental channel")
	}
}

// --envoy-compat adds the arg and read/status access to the Envoy Gateway CRDs, and nothing otherwise.
func TestInstallGoldenEnvoyCompat(t *testing.T) {
	out := Install(InstallOptions{Image: "example.test/setura:1", EnvoyCompat: true})
	goldenCheck(t, "install_envoy_compat.golden.yaml", out)
	for _, want := range []string{"--envoy-compat", `apiGroups: ["gateway.envoyproxy.io"]`, "securitypolicies/status"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	for _, plain := range []string{Install(InstallOptions{}), Install(fullInstall())} {
		if strings.Contains(plain, "envoyproxy") || strings.Contains(plain, "--envoy-compat") {
			t.Error("Envoy Gateway permissions printed without --envoy-compat")
		}
	}
}
