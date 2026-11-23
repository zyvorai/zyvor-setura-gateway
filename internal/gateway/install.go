package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// DefaultImage is the controller image used by Install when none is given.
var DefaultImage = "ghcr.io/zyvorai/zyvor-setura-gateway:latest"

// InstallOptions configures the printed manifests.
type InstallOptions struct {
	Namespace, Image, ClassName string
	Replicas                    int
	ExposePorts                 bool // controller adds Service ports for Gateway listener ports
	WithMonitoring              bool // add an admin Service port, ServiceMonitor, PrometheusRule and the Grafana dashboard
	EnvoyCompat                 bool // run the controller with --envoy-compat and grant it read and status access to the Envoy Gateway policy CRDs

	// The options below are checked by Validate; the zero value prints what
	// earlier versions printed (apart from the admin Secret, see CreateAdminSecret).
	ServiceType           string            // ClusterIP (default), NodePort or LoadBalancer
	NodePorts             map[string]int    // Service port (name http|https, or a number) to nodePort
	ListenerPorts         []int             // extra Service ports for Gateway listeners
	ExternalTrafficPolicy string            // Local or Cluster; NodePort and LoadBalancer only
	HostNetwork           bool              // run the pod in the node's network namespace
	Args                  []string          // appended to the controller container args
	Resources             map[string]string // requests.cpu, requests.memory, limits.cpu, limits.memory
	NodeSelector          map[string]string
	AdminTokenSecret      string // Secret the admin token is read from (default setura-gateway-admin, key token)
	CreateAdminSecret     bool   // also print that Secret, holding a fresh random token
	CRDs                  bool   // print the exact command that installs the Gateway API CRDs
	GatewayAPIVersion     string // for CRDs (default GatewayAPIVersion)
	GatewayAPIChannel     string // standard (default) or experimental

	adminToken string // tests: fixed token for golden output
}

// AdminSecretKey is the key of the admin token inside its Secret.
const AdminSecretKey = "token"

// DefaultAdminSecret is the Secret the controller reads its admin token from
// unless --admin-token-secret names another one.
const DefaultAdminSecret = "setura-gateway-admin"

// adminPort is the controller's admin container and Service port.
const adminPort = 19000

// Install returns Kubernetes YAML for the in-cluster controller. Setura only
// prints it; applying it is always the operator's decision.
func Install(o InstallOptions) string {
	if o.Namespace == "" {
		o.Namespace = "setura-system"
	}
	if o.Image == "" {
		o.Image = DefaultImage
	}
	if o.ClassName == "" {
		o.ClassName = "setura"
	}
	if o.Replicas < 1 {
		o.Replicas = 1
	}
	if o.AdminTokenSecret == "" {
		o.AdminTokenSecret = DefaultAdminSecret
	}
	y := `# Setura built-in gateway: controller and data plane in one static binary.
# Printed by "setura gateway install"; review it, then apply it yourself.
HEADER_NOTESapiVersion: v1
kind: Namespace
metadata:
  name: NS
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: setura-gateway
  namespace: NS
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: setura-gateway
rules:
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gatewayclasses", "gateways", "httproutes", "grpcroutes", "tlsroutes", "tcproutes", "udproutes", "listenersets", "backendtlspolicies", "referencegrants"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gatewayclasses/status", "gateways/status", "httproutes/status", "grpcroutes/status", "tlsroutes/status", "tcproutes/status", "udproutes/status", "listenersets/status", "backendtlspolicies/status"]
    verbs: ["get", "patch", "update"]
  - apiGroups: [""]
    resources: ["services", "namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["secrets", "configmaps"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list", "watch"]
ENVOY_RULES---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: setura-gateway
  namespace: NS
rules:
  # Leader election Lease (--leader-elect).
  - apiGroups: ["coordination.k8s.io"]
    resources: ["leases"]
    verbs: ["get", "create", "update"]
EXPOSE_RULES---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: setura-gateway
  namespace: NS
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: setura-gateway
subjects:
  - kind: ServiceAccount
    name: setura-gateway
    namespace: NS
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: setura-gateway
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: setura-gateway
subjects:
  - kind: ServiceAccount
    name: setura-gateway
    namespace: NS
---
SECRET_DOCapiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: CLASS
spec:
  controllerName: ` + ControllerName + `
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: setura-gateway
  namespace: NS
  labels: {app.kubernetes.io/name: setura-gateway}
spec:
  replicas: REPLICAS
STRATEGY  selector:
    matchLabels: {app.kubernetes.io/name: setura-gateway}
  template:
    metadata:
      labels: {app.kubernetes.io/name: setura-gateway}
    spec:
      serviceAccountName: setura-gateway
POD_SPEC_EXTRA      securityContext:
        runAsNonRoot: true
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: gateway
          image: IMAGE
          args:
            - gateway
            - run
            - --kubernetes
            - --bind=0.0.0.0
            - --port-offset=8000   # 80 -> 8080, 443 -> 8443 without root
            - --admin=0.0.0.0:19000
            - --admin-open-ready   # kubelet probes read /ready; every other admin path needs the token
            - --leader-elect       # one replica writes status, all serve traffic
EXPOSE_ARG          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: ["ALL"]}
          env:
            - name: SETURA_ADMIN_TOKEN
              valueFrom: {secretKeyRef: {name: ADMIN_SECRET, key: ADMIN_KEY}}
            - name: POD_NAME
              valueFrom: {fieldRef: {fieldPath: metadata.name}}
            - name: POD_NAMESPACE
              valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
          ports:
            - {name: http, containerPort: 8080}
            - {name: https, containerPort: 8443}
            - {name: admin, containerPort: 19000}
EXTRA_CONTAINER_PORTS          readinessProbe:
            httpGet: {path: /ready, port: admin}
          livenessProbe:
            httpGet: {path: /ready, port: admin}
            initialDelaySeconds: 10
RESOURCES---
apiVersion: v1
kind: Service
metadata:
  name: setura-gateway
  namespace: NS
spec:
SERVICE_SPEC`
	exposeRules, exposeArg := "", ""
	if o.ExposePorts {
		exposeRules = `  # --expose-gateway-ports: patch the controller's own Service, nothing else.
  - apiGroups: [""]
    resources: ["services"]
    resourceNames: ["setura-gateway"]
    verbs: ["patch"]
`
		exposeArg = "            - --expose-gateway-ports\n"
	}
	// Every operator-supplied value goes in through the one replacer below, which
	// never rescans what it wrote, so a value such as "NS" cannot be rewritten.
	envoyRules := ""
	if o.EnvoyCompat {
		envoyRules = `  # --envoy-compat: read Envoy Gateway's policy CRDs and report on them. Nothing else of that group.
  - apiGroups: ["` + EnvoyGroup + `"]
    resources: ["backendtrafficpolicies", "clienttrafficpolicies", "securitypolicies", "httproutefilters", "backends"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["` + EnvoyGroup + `"]
    resources: ["backendtrafficpolicies/status", "clienttrafficpolicies/status", "securitypolicies/status"]
    verbs: ["get", "patch", "update"]
`
		exposeArg += "            - --envoy-compat       # translate Envoy Gateway policies (docs/envoy-compat.md)\n"
	}
	r := strings.NewReplacer("ENVOY_RULES", envoyRules, "EXPOSE_RULES", exposeRules, "EXPOSE_ARG", exposeArg+extraArgs(o.Args),
		"HEADER_NOTES", installHeader(o), "SECRET_DOC", adminSecretDoc(o), "STRATEGY", installStrategy(o),
		"POD_SPEC_EXTRA", podSpecExtra(o), "EXTRA_CONTAINER_PORTS", extraContainerPorts(o),
		"RESOURCES", resourcesYAML(o.Resources), "SERVICE_SPEC", serviceSpec(o),
		"ADMIN_SECRET", yamlScalar(o.AdminTokenSecret), "ADMIN_KEY", AdminSecretKey,
		"NS", o.Namespace, "CLASS", o.ClassName, "IMAGE", o.Image, "REPLICAS", fmt.Sprint(o.Replicas))
	if o.WithMonitoring {
		return r.Replace(y) + MonitoringYAML(o.Namespace)
	}
	return r.Replace(y)
}

// serviceSpec renders the Service spec: type, optional traffic policy, selector and ports.
func serviceSpec(o InstallOptions) string {
	var b strings.Builder
	if o.ServiceType == "" {
		b.WriteString(`  # Change the type to LoadBalancer to expose the gateway (or install with --service-type).
  # The controller writes this Service's address into Gateway status.addresses. Add a port
  # for every extra listener port your Gateways declare (--listener-port N; spec port N maps
  # to N+8000 below 1024), or install with --expose-gateway-ports and the controller adds
  # the ports itself.
  type: ClusterIP
`)
	} else {
		fmt.Fprintf(&b, "  type: %s\n", o.ServiceType)
	}
	if o.ExternalTrafficPolicy != "" {
		fmt.Fprintf(&b, "  externalTrafficPolicy: %s\n", o.ExternalTrafficPolicy)
	}
	b.WriteString("  selector: {app.kubernetes.io/name: setura-gateway}\n  ports:\n")
	port := func(name string, port int, target string) {
		fmt.Fprintf(&b, "    - {name: %s, port: %d, targetPort: %s", name, port, target)
		if np := o.nodePortFor(name, port); np != 0 {
			fmt.Fprintf(&b, ", nodePort: %d", np)
		}
		b.WriteString("}\n")
	}
	port("http", 80, "http")
	port("https", 443, "https")
	if o.WithMonitoring {
		port("admin", adminPort, "admin")
	}
	for _, p := range uniqueSorted(o.ListenerPorts) {
		port(listenerPortName(p), p, fmt.Sprint(listenerTarget(p)))
	}
	return b.String()
}

// nodePortFor looks a nodePort up by Service port name or number.
func (o InstallOptions) nodePortFor(name string, port int) int {
	if v, ok := o.NodePorts[name]; ok {
		return v
	}
	return o.NodePorts[fmt.Sprint(port)]
}

func listenerPortName(p int) string { return fmt.Sprintf("listener-%d", p) }

// listenerTarget is the container port the controller serves spec port p on:
// the same remapping as --port-offset=8000.
func listenerTarget(p int) int {
	if p < 1024 {
		return p + 8000
	}
	return p
}

func extraContainerPorts(o InstallOptions) string {
	var b strings.Builder
	for _, p := range uniqueSorted(o.ListenerPorts) {
		t := listenerTarget(p)
		if t == 8080 || t == 8443 || t == adminPort {
			continue // already declared above
		}
		fmt.Fprintf(&b, "            - {name: lp%d, containerPort: %d}\n", p, t)
	}
	return b.String()
}

func extraArgs(args []string) string {
	var b strings.Builder
	for _, a := range args {
		fmt.Fprintf(&b, "            - %s\n", yamlScalar(a))
	}
	return b.String()
}

func installStrategy(o InstallOptions) string {
	if !o.HostNetwork {
		return ""
	}
	return `  # hostNetwork: two pods cannot bind the same node port, so replace one at a time.
  strategy:
    type: RollingUpdate
    rollingUpdate: {maxSurge: 0, maxUnavailable: 1}
`
}

func podSpecExtra(o InstallOptions) string {
	var b strings.Builder
	if o.HostNetwork {
		b.WriteString("      hostNetwork: true   # --host-network: the controller binds node ports 8080, 8443 and the listener ports\n      dnsPolicy: ClusterFirstWithHostNet\n")
	}
	if len(o.NodeSelector) > 0 {
		b.WriteString("      nodeSelector:\n")
		for _, k := range sortedStrKeys(o.NodeSelector) {
			fmt.Fprintf(&b, "        %s: %s\n", yamlScalar(k), yamlScalar(o.NodeSelector[k]))
		}
	}
	return b.String()
}

func resourcesYAML(res map[string]string) string {
	if len(res) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("          resources:\n")
	for _, kind := range []string{"requests", "limits"} {
		var lines []string
		for _, r := range []string{"cpu", "memory"} {
			if v, ok := res[kind+"."+r]; ok {
				lines = append(lines, fmt.Sprintf("              %s: %s\n", r, yamlScalar(v)))
			}
		}
		if len(lines) > 0 {
			fmt.Fprintf(&b, "            %s:\n%s", kind, strings.Join(lines, ""))
		}
	}
	return b.String()
}

// adminSecretDoc prints the admin Secret only on request: a Secret printed on
// every run would carry a new random token each time and rotate it on re-apply.
func adminSecretDoc(o InstallOptions) string {
	if !o.CreateAdminSecret {
		return ""
	}
	tok := o.adminToken
	if tok == "" {
		b := make([]byte, 24)
		rand.Read(b)
		tok = hex.EncodeToString(b)
	}
	return "apiVersion: v1\nkind: Secret\nmetadata:\n  name: " + yamlScalar(o.AdminTokenSecret) + "\n  namespace: " + o.Namespace + "\ntype: Opaque\nstringData:\n  " + AdminSecretKey + ": " + tok +
		"   # random, generated for this printout: apply this document once and do not re-apply it\n---\n"
}

// installHeader is the comment block at the top: admin token and CRD notes.
func installHeader(o InstallOptions) string {
	var b strings.Builder
	if o.CRDs {
		v, ch := o.GatewayAPIVersion, o.GatewayAPIChannel
		if v == "" {
			v = GatewayAPIVersion
		}
		if ch == "" {
			ch = "standard"
		}
		fmt.Fprintf(&b, "#\n# Gateway API CRDs %s (%s channel) are not part of this document. Install them first, once per cluster:\n#   kubectl apply --server-side -f %s\n", v, ch, CRDInstallURL(v, ch))
	}
	if !o.CreateAdminSecret {
		fmt.Fprintf(&b, "#\n# The admin token is read from Secret %s (key %s), which is not printed here so that\n# re-applying this document never rotates it. Create it once, right after the first apply (the pod starts when it exists):\n#   kubectl -n %s create secret generic %s --from-literal=%s=$(openssl rand -hex 24)\n# or print a Secret with --create-admin-secret.\n", o.AdminTokenSecret, AdminSecretKey, o.Namespace, o.AdminTokenSecret, AdminSecretKey)
	}
	if b.Len() > 0 {
		b.WriteString("#\n")
	}
	return b.String()
}

// plainScalar matches strings that need no YAML quoting here.
var plainScalar = regexp.MustCompile(`^-{0,2}[A-Za-z0-9][A-Za-z0-9_./:=,@%+-]*$`)

// yamlScalar returns s as a YAML scalar: plain when that is safe, otherwise a
// JSON-style quoted string (which YAML accepts).
func yamlScalar(s string) string {
	if !plainScalar.MatchString(s) {
		return strconv.Quote(s)
	}
	switch strings.ToLower(s) {
	case "true", "false", "null", "yes", "no", "on", "off", "y", "n":
		return strconv.Quote(s)
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return strconv.Quote(s)
	}
	return s
}

func sortedStrKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(in []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}
