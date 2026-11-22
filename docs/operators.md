# Operating Setura on K3s and Kubernetes

## What changes for a cluster user

| Operator question | Decision and evidence |
| --- | --- |
| Will this GatewayClass serve the feature I need? | Enumerate installed classes, controller names and advertised supported features. An absent feature list means unreported. Consult the implementation’s version-specific conformance report for unsupported or unreported behavior. [Supported features](https://gateway-api.sigs.k8s.io/geps/gep-2162/) |
| Why did a programmed Gateway stop serving the release? | Inspect listener conditions, attached route counts and route parent conditions. Match observedGeneration to the desired generation before crediting a successful probe. [Gateway status](https://gateway-api.sigs.k8s.io/docs/concepts/troubleshooting/) |
| Why is the K3s LoadBalancer pending? | Show missing ingress addresses and overlapping Service ports in the selected namespace. K3s ServiceLB needs available host ports on eligible nodes. Inspect ServiceLB pods, node pools and scheduling events to establish the cause. Other load balancer implementations can legitimately share port numbers. [K3s ServiceLB](https://docs.k3s.io/networking/networking-services) |
| Will my account work in the application and proxy namespaces? | Issue operation-specific authorization queries against the selected context. Distinguish explicit denials from failed queries. A positive result alone does not validate resource existence, network access, admission or cross-namespace backend grants. [Authorization checks](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/) |
| Are the cluster path and the Mac path healthy? | Run a pod-origin assertion as a CronJob, and run a separate host assertion against the gateway. Compare numeric destinations from the same host while preserving HTTP Host and TLS identity. Record which path each check exercises. [CronJob behavior](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/) |

## Discovery, publication and rollout

```sh
setura --context edge capabilities
setura --context edge exposure -n kube-system
setura --context edge doctor -n apps --proxy-namespace kube-system
setura --context edge listeners public -n apps
setura --context edge inspect orders -n apps
setura --context edge publish public -n apps --listener websecure \
  --proxy-namespace kube-system --service traefik --service-port 443 --port 8443 --dry-run
```

Explicit Service mode works with a pod-backed proxy Service the caller selects. Verify the Service is the data plane for that Gateway. The CLI validates listener protocol and Service port. The operator supplies the mapping when the Service port differs from the controller listener. Remove --dry-run to open the foreground forward. Implementations that intercept traffic outside the selected pod may require probing their advertised ingress address instead.

```sh
setura gate orders https://orders.example.test/checkout -n apps \
  --gateway public --gateway-namespace infra --listener websecure \
  --backend orders-v2 --attempts 10 --streak 3 --interval 2
setura compare https://orders.example.test/checkout --target dns \
  --target 192.0.2.10 --target 2001:db8::10 --backend orders-v2
```

Replace example addresses and names with your deployment’s values. Each gate sample checks one parent’s Accepted and ResolvedRefs conditions, sends the supplied request, and checks route identity, generation and parent state again after success. Multiple matching parent reports require a narrower selector, such as --listener or --controller. A missing condition, unexpected identity, or changed generation prevents the sample from counting. The supplied URL must exercise the intended route. Another route to the same application could return the same header. Per-request Envoy tracing is a separate milestone.

Compare runs sequentially from the invoking host. It preserves the full URL and TLS verification across targets. It can reveal differences in external ingress IPs and DNS resolution; it does not simulate a second network origin.

## Drift and CI

```sh
setura --context staging snapshot -n apps > staging.json
setura --context production snapshot -n apps > production.json
setura diff staging.json production.json
setura check examples/checks.json --junit checks.xml
```

Snapshots include Gateway and HTTPRoute specs only. Diff compares names and specs, ignoring status and metadata, and preserves order within arrays. The selected namespaces can differ. Reads of the two resource kinds happen sequentially. Diff reports exit 1 for a difference, check reports exit 1 for a failed assertion, and errors use exit 2. GitHub Actions and other CI systems can retain the JSON or ingest the JUnit file.

## In-cluster synthetic monitoring

Build the included image with `docker build -t setura:0.3.0 .`. Import it into every eligible cluster node’s image store or push it to your registry and update the image reference in examples/cluster-check.yaml. The image is a probe runtime. Cluster-discovery workflows run on a host with kubectl.

Apply examples/demo.yaml and examples/cluster-check.yaml. The sample runs every five minutes and checks the demo Service directly from a pod. Supply a gateway URL in the ConfigMap to check ingress from that origin. Adjust the DNS suffix if the cluster domain differs from cluster.local. The pod uses no service account token. Network policy must permit DNS and the intended destination. The successful job log contains JSON evidence.

```sh
kubectl -n setura-demo create job setura-manual-01 --from=cronjob/setura-internal-checks
kubectl -n setura-demo logs -f job/setura-manual-01
```

The cluster smoke workflow builds and imports the image, runs a one-shot Job and checks its exit state. The foreground development forward and the in-cluster Job exercise separate paths.
