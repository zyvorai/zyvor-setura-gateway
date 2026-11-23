package gateway

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// GatewayAPIVersion is the Gateway API release Setura documents and passes
// conformance against (docs/conformance/v1.7.0); "gateway install --crds"
// points at its CRDs unless --gateway-api-version says otherwise.
const GatewayAPIVersion = "v1.7.0"

// MinGatewayAPIVersion is the oldest release whose Gateway, GatewayClass and
// HTTPRoute CRDs the controller can work with at all.
const MinGatewayAPIVersion = "v1.1.0"

// CRDGroup is the API group of the Gateway API CRDs.
const CRDGroup = "gateway.networking.k8s.io"

var versionRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.]+)?$`)

// ParseGatewayAPIVersion splits vX.Y.Z[-pre] into its numbers.
func ParseGatewayAPIVersion(v string) ([3]int, error) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return [3]int{}, fmt.Errorf("%q is not a Gateway API version like v1.7.0", v)
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, nil
}

// CompareGatewayAPIVersion returns -1, 0 or 1; a pre-release suffix is ignored.
func CompareGatewayAPIVersion(a, b string) (int, error) {
	x, err := ParseGatewayAPIVersion(a)
	if err != nil {
		return 0, err
	}
	y, err := ParseGatewayAPIVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range x {
		switch {
		case x[i] < y[i]:
			return -1, nil
		case x[i] > y[i]:
			return 1, nil
		}
	}
	return 0, nil
}

// CRDInstallURL is the release asset that installs the CRDs of a channel
// ("standard" or "experimental").
func CRDInstallURL(version, channel string) string {
	if channel == "" {
		channel = "standard"
	}
	return "https://github.com/kubernetes-sigs/gateway-api/releases/download/" + version + "/" + channel + "-install.yaml"
}

// CRDFeature ties a Setura feature to the CRD (and CRD version) it needs.
type CRDFeature struct {
	Name string // what the operator sees
	CRD  string // plural resource name in CRDGroup
	// Path is a field the served v1 schema must contain, below the CRD's
	// openAPIV3Schema; array levels are stepped through automatically. Empty
	// means the CRD alone is the feature. On a live cluster this beats the
	// version number, which only explains what to upgrade to.
	Path []string
	// MinStandard is the first release carrying the feature in the standard
	// channel; Experimental marks kinds that exist in the experimental channel only.
	MinStandard  string
	Experimental bool
	// Required features make the controller unusable when absent.
	Required bool
	Note     string
}

// CRDFeatures lists what Setura uses from the Gateway API CRDs. Versions come
// from the Gateway API release notes; the ExternalAuth entry is also confirmed
// by a field report (v1.6.3 standard CRDs reject "externalAuth" as an unknown field).
var CRDFeatures = []CRDFeature{
	{Name: "GatewayClass", CRD: "gatewayclasses", MinStandard: "v1.1.0", Required: true},
	{Name: "Gateway", CRD: "gateways", MinStandard: "v1.1.0", Required: true},
	{Name: "HTTPRoute", CRD: "httproutes", MinStandard: "v1.1.0", Required: true},
	{Name: "GRPCRoute", CRD: "grpcroutes", MinStandard: "v1.1.0"},
	{Name: "ReferenceGrant (cross-namespace references)", CRD: "referencegrants", MinStandard: "v1.1.0"},
	{Name: "HTTPRoute CORS filter", CRD: "httproutes", Path: []string{"spec", "rules", "filters", "cors"}, MinStandard: "v1.5.0"},
	{Name: "HTTPRoute ExternalAuth filter", CRD: "httproutes", Path: []string{"spec", "rules", "filters", "externalAuth"}, MinStandard: "v1.7.0"},
	{Name: "BackendTLSPolicy (TLS to backends)", CRD: "backendtlspolicies", MinStandard: "v1.4.0"},
	{Name: "ListenerSet", CRD: "listenersets", MinStandard: "v1.5.0"},
	{Name: "TLSRoute (TLS passthrough and termination)", CRD: "tlsroutes", MinStandard: "v1.5.0"},
	{Name: "TCPRoute", CRD: "tcproutes", Experimental: true, Note: "experimental channel only"},
	{Name: "UDPRoute", CRD: "udproutes", Experimental: true, Note: "experimental channel only"},
}

// NeedsText says which release (and channel) a feature needs.
func (f CRDFeature) NeedsText() string {
	if f.Experimental {
		return "the experimental channel (any release)"
	}
	return "Gateway API " + f.MinStandard + " or newer"
}
