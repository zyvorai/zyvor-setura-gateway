package gateway

import (
	"fmt"
	"strings"
)

// DefaultImage is the controller image used by Install when none is given.
var DefaultImage = "ghcr.io/zyvorai/zyvor-setura-gateway:latest"

// InstallOptions configures the printed manifests.
type InstallOptions struct {
	Namespace, Image, ClassName string
	Replicas                    int
	ExposePorts                 bool // controller adds Service ports for Gateway listener ports
}

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
	y := `# Setura built-in gateway: controller and data plane in one static binary.
# Printed by "setura gateway install"; review it, then apply it yourself.
apiVersion: v1
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
    verbs: ["get"]
  - apiGroups: ["discovery.k8s.io"]
    resources: ["endpointslices"]
    verbs: ["get", "list", "watch"]
---
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
apiVersion: gateway.networking.k8s.io/v1
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
  selector:
    matchLabels: {app.kubernetes.io/name: setura-gateway}
  template:
    metadata:
      labels: {app.kubernetes.io/name: setura-gateway}
    spec:
      serviceAccountName: setura-gateway
      securityContext:
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
            - --leader-elect       # one replica writes status, all serve traffic
EXPOSE_ARG          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: ["ALL"]}
          env:
            - name: POD_NAME
              valueFrom: {fieldRef: {fieldPath: metadata.name}}
            - name: POD_NAMESPACE
              valueFrom: {fieldRef: {fieldPath: metadata.namespace}}
          ports:
            - {name: http, containerPort: 8080}
            - {name: https, containerPort: 8443}
            - {name: admin, containerPort: 19000}
          readinessProbe:
            httpGet: {path: /ready, port: admin}
          livenessProbe:
            httpGet: {path: /ready, port: admin}
            initialDelaySeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: setura-gateway
  namespace: NS
spec:
  # Change the type to LoadBalancer to expose the gateway. The controller writes this
  # Service's address into Gateway status.addresses. Add a port for every extra listener
  # port your Gateways declare (spec port N maps to N+8000 below 1024), or install with
  # --expose-gateway-ports and the controller adds the ports itself.
  type: ClusterIP
  selector: {app.kubernetes.io/name: setura-gateway}
  ports:
    - {name: http, port: 80, targetPort: http}
    - {name: https, port: 443, targetPort: https}
`
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
	y = strings.Replace(y, "EXPOSE_RULES", exposeRules, 1)
	y = strings.Replace(y, "EXPOSE_ARG", exposeArg, 1)
	r := strings.NewReplacer("NS", o.Namespace, "CLASS", o.ClassName, "IMAGE", o.Image, "REPLICAS", fmt.Sprint(o.Replicas))
	return r.Replace(y)
}
