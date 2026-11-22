// Package conformance wraps the upstream Gateway API conformance suite and
// points it at `setura gateway run --kubernetes`. It lives in its own module so
// the main module stays standard-library only.
package conformance

import (
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

// supported is the explicit list of features Setura claims. Everything not
// listed here is not claimed, and the suite skips tests that need it.
// Keep in sync with docs/builtin-gateway.md and scripts/run-conformance.sh.
var supported = []features.FeatureName{
	features.SupportGateway,
	features.SupportHTTPRoute,
	features.SupportReferenceGrant,
	// GRPCRoute (h2c and h2, streaming) and TLSRoute with TLS passthrough.
	features.SupportGRPCRoute,
	features.SupportTLSRoute,
	// The controller (run with --expose-gateway-ports) adds Service ports for listeners
	// such as 8080 and publishes the Service address in Gateway status.addresses.
	features.SupportGatewayPort8080,
	// HTTPRoute extended features the data plane implements.
	features.SupportHTTPRouteQueryParamMatching,
	features.SupportHTTPRouteMethodMatching,
	features.SupportHTTPRouteResponseHeaderModification,
	features.SupportHTTPRoutePortRedirect,
	features.SupportHTTPRouteSchemeRedirect,
	features.SupportHTTPRoutePathRedirect,
	features.SupportHTTPRouteHostRewrite,
	features.SupportHTTPRoutePathRewrite,
	features.SupportHTTPRouteRequestMirror,
	features.SupportHTTPRouteRequestTimeout,
	features.SupportHTTPRouteRequestPercentageMirror,
	features.SupportHTTPRouteParentRefPort,
	features.SupportHTTPRouteBackendRequestHeaderModification,
	// Gateway API 1.5 features (docs/gateway-api-1-5.md), implemented in the data plane
	// and the Kubernetes source but not yet verified by an upstream run.
	features.SupportHTTPRouteCORS,
	features.SupportHTTPRouteBackendTimeout,
	features.SupportHTTPRouteDestinationPortMatching,
	features.SupportHTTPRouteNamedRouteRule,
	features.SupportGRPCRouteNamedRouteRule,
	features.SupportBackendTLSPolicy,
	features.SupportBackendTLSPolicySANValidation,
	features.SupportListenerSet,
	features.SupportGatewayStaticAddresses,
	// Plain layer 4 listeners with weighted backends.
	features.SupportTCPRoute,
	features.SupportUDPRoute,
}

// Deliberately not claimed (see docs/builtin-gateway.md): GatewayAddressEmpty,
// GatewayHTTPListenerIsolation, GatewayInfrastructurePropagation,
// HTTPRouteRequestMultipleMirrors, HTTPRouteBackendProtocolH2C,
// HTTPRouteBackendProtocolWebSocket, TLSRouteModeTerminate, TLSRouteModeMixed,
// GRPCRouteRequestHeaderModifier, BackendTLSPolicy use from GRPCRoute and TLSRoute terminate
// (those tests need features that are not claimed), the Gateway client certificate validation
// features, and the mesh profiles. ExternalAuth has no feature name in v1.7.0, so the suite
// cannot exercise it.

// skipTests lists upstream ShortNames known to need behaviour Setura does not
// implement, so a run reports them as skipped instead of failing. Extend with
// SETURA_CONFORMANCE_SKIP (comma separated).
var skipTests = []string{
	"HTTPRouteBackendProtocolH2C",       // no h2c upstreams
	"HTTPRouteBackendProtocolWebSocket", // Service appProtocol selection not implemented
	"GatewayOptionalAddressValue",       // needs GatewayAddressEmpty: the gateway cannot assign an address
	"GatewayInfrastructure",
	"GatewayHTTPListenerIsolation",
}

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	opts.GatewayClassName = envOr("SETURA_GATEWAY_CLASS", "setura")
	opts.CleanupBaseResources = envOr("SETURA_CLEANUP", "true") == "true"

	// Profiles: HTTP, GRPC, TLS (passthrough), TCP and UDP. The mesh profiles are not supported.
	opts.ConformanceProfiles = []suite.ConformanceProfileName{
		suite.GatewayHTTPConformanceProfileName,
		suite.GatewayGRPCConformanceProfileName,
		suite.GatewayTLSConformanceProfileName,
		suite.GatewayTCPConformanceProfileName,
		suite.GatewayUDPConformanceProfileName,
	}
	opts.EnableAllSupportedFeatures = false
	opts.SupportedFeatures = supported
	opts.SkipTests = append(append([]string{}, skipTests...), splitList(os.Getenv("SETURA_CONFORMANCE_SKIP"))...)

	opts.Implementation.Organization = "Zyvor AI Labs"
	opts.Implementation.Project = "zyvor-setura-gateway"
	opts.Implementation.URL = "https://github.com/zyvorai/zyvor-setura-gateway"
	opts.Implementation.Version = envOr("SETURA_VERSION", "dev")
	opts.Implementation.Contact = []string{"https://github.com/zyvorai/zyvor-setura-gateway/issues"}

	opts.ReportOutputPath = envOr("SETURA_REPORT", "report.yaml")

	conformance.RunConformanceWithOptions(t, opts)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
