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
}

// Deliberately not claimed (see docs/builtin-gateway.md): GatewayStaticAddresses, GatewayAddressEmpty, GatewayHTTPListenerIsolation,
// GatewayInfrastructurePropagation, HTTPRouteBackendTimeout, HTTPRouteCORS,
// HTTPRouteDestinationPortMatching, HTTPRouteNamedRouteRule,
// HTTPRouteRequestMultipleMirrors, HTTPRouteBackendProtocolH2C,
// HTTPRouteBackendProtocolWebSocket, BackendTLSPolicy*, TLSRouteModeTerminate,
// TLSRouteModeMixed, GRPCRouteNamedRouteRule, GRPCRouteRequestHeaderModifier, TCPRoute,
// UDPRoute and the mesh profiles.

// skipTests lists upstream ShortNames known to need behaviour Setura does not
// implement, so a run reports them as skipped instead of failing. Extend with
// SETURA_CONFORMANCE_SKIP (comma separated).
var skipTests = []string{
	"HTTPRouteTimeoutBackendRequest",        // timeouts.backendRequest not implemented
	"HTTPRouteCORSAllowCredentialsBehavior", // CORS filter not implemented
	"HTTPRouteBackendProtocolH2C",           // no h2c upstreams
	"HTTPRouteBackendProtocolWebSocket",     // Service appProtocol selection not implemented
	"BackendTLSPolicy",                      // BackendTLSPolicy not implemented
	"BackendTLSPolicyConflictResolution",
	"BackendTLSPolicyInvalidCACertificateRef",
	"BackendTLSPolicyInvalidKind",
	"BackendTLSPolicyObservedGenerationBump",
	"BackendTLSPolicySANValidation",
	"GatewayStaticAddresses", // Gateway spec.addresses not implemented
	"GatewayOptionalAddressValue",
	"GatewayInfrastructure",
	"GatewayHTTPListenerIsolation",
}

func TestConformance(t *testing.T) {
	opts := conformance.DefaultOptions(t)

	opts.GatewayClassName = envOr("SETURA_GATEWAY_CLASS", "setura")
	opts.CleanupBaseResources = envOr("SETURA_CLEANUP", "true") == "true"

	// Profiles: HTTP, GRPC and TLS (passthrough). TCP, UDP and mesh are not supported.
	opts.ConformanceProfiles = []suite.ConformanceProfileName{
		suite.GatewayHTTPConformanceProfileName,
		suite.GatewayGRPCConformanceProfileName,
		suite.GatewayTLSConformanceProfileName,
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
