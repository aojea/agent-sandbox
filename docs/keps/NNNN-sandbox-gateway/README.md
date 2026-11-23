# KEP-NNNN: `sandbox-gateway` — Standardized `agents.net` Traffic Plumbing via DRA and NRI

<!--
TOC is auto-generated via `make toc-update`.
-->

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [User Stories](#user-stories)
    - [Story 1: Platform operator standardizes on <code>agents.net</code> with an existing egress portal](#story-1-platform-operator-standardizes-on-agentsnet-with-an-existing-egress-portal)
    - [Story 2: Workload owner customizes upstream or private metadata per <code>SandboxTemplate</code>](#story-2-workload-owner-customizes-upstream-or-private-metadata-per-sandboxtemplate)
    - [Story 3: Standalone Kubernetes <code>Pod</code> user adopts <code>agents.net</code> plumbing directly](#story-3-standalone-kubernetes-pod-user-adopts-agentsnet-plumbing-directly)
    - [Story 4: Operator adopts isolated plumbing on an existing cluster without KEP-6313](#story-4-operator-adopts-isolated-plumbing-on-an-existing-cluster-without-kep-6313)
  - [High-Level Design](#high-level-design)
    - [Why DRA + NRI (Following DraNet)](#why-dra--nri-following-dranet)
    - [Pod Adapter Modes (Per-Pod Network Namespace Invariant)](#pod-adapter-modes-per-pod-network-namespace-invariant)
    - [Upstream Authentication Modes](#upstream-authentication-modes)
    - [Standardized <code>agents.net</code> Upstream Wire &amp; Attested Metadata](#standardized-agentsnet-upstream-wire--attested-metadata)
    - [API Changes](#api-changes)
    - [Implementation Guidance](#implementation-guidance)
- [Scalability](#scalability)
- [Alternatives](#alternatives)
  - [Alternative 1: Standalone <code>SandboxNetworkPolicy</code> and <code>SandboxNetworkBinding</code> CRDs with embedded CEL engine](#alternative-1-standalone-sandboxnetworkpolicy-and-sandboxnetworkbinding-crds-with-embedded-cel-engine)
  - [Alternative 2: Sidecar-only upstream authentication without a node DaemonSet](#alternative-2-sidecar-only-upstream-authentication-without-a-node-daemonset)
  - [Alternative 3: Hardcoding a single upstream authentication mechanism](#alternative-3-hardcoding-a-single-upstream-authentication-mechanism)
<!-- /toc -->

## Summary

This KEP defines `sandbox-gateway`, a minimal, node-local traffic plumbing layer for `agent-sandbox` that isolates sandbox Pods from direct network egress and forwards all TCP, UDP, and DNS traffic over the **`agents.net`** wire protocol (`HTTP CONNECT`, RFC 9298 `connect-udp`, RFC 9209 `Proxy-Status`) to an authenticated **upstream** proxy or portal.

Rather than introducing standalone network policy or credential-broker CRDs into `agent-sandbox`, `sandbox-gateway` configures traffic plumbing directly on `Sandbox` / `SandboxTemplate` (`SandboxBlueprint.network`) and standard Kubernetes `PodSpec` via **Dynamic Resource Allocation (DRA)** and the **Node Resource Interface (NRI)**, following the architecture proven by [DraNet](https://github.com/google/dranet). Policy enforcement (allowlists, CEL, L7 HTTP/MCP inspection, SSRF filtering) and secret/credential injection (such as `gke-labs/service-portals`, Envoy/Agentgateway, or corporate egress gateways) remain decoupled in the upstream. To let the upstream enforce per-sandbox policies and inject per-sandbox credentials without exposing secrets to untrusted agent code, the node plumbing supports all four Kubernetes-native upstream authentication modes: **mTLS**, **SPIFFE**, **KEP-4317 `PodCertificate`**, and **bound `ServiceAccountToken`**.

## Motivation

AI coding agents and autonomous workloads running inside `Sandbox` Pods execute untrusted code and need strict network confinement alongside authenticated access to external APIs, MCP servers, and package registries.

Existing approaches force painful trade-offs:

1. **CNI `NetworkPolicy` alone operates at L3/L4 only.** It cannot enforce hostname, HTTP, or MCP rules, cannot inject credentials transparently, and still attaches a cluster-routable interface (`eth0`) and Pod IP to every sandbox.
2. **In-container proxies and environment variables are bypassable and leak secrets.** Untrusted processes ignore `HTTP_PROXY`, make raw TCP/UDP sockets, or exfiltrate any credential or ServiceAccount token mounted inside the container.
3. **Baking a bespoke policy engine and secret broker into `agent-sandbox` CRDs fragments the ecosystem.** Cluster operators already deploy diverse egress gateways, portals (`gke-labs/service-portals`), service meshes, and corporate proxies. Duplicating policy schemas and secret-store integrations as new `agent-sandbox` CRDs creates maintenance burden and locks users into a single policy language.

### Goals

- **Promote `agents.net` as a vendor-neutral standard** for sandbox network interception (`CONNECT` + RFC 9298 `connect-udp` over per-Pod Unix domain sockets) and upstream forwarding (`HTTP/1.1`, `HTTP/2`, or `HTTP/3` MASQUE + RFC 9209 `Proxy-Status` + attested `Agents-Net-*` identity headers).
- **Keep `agent-sandbox` strictly focused on plumbing** with zero new policy or binding CRDs. Expose configuration directly in `SandboxBlueprint.network` (shared by `Sandbox` and `SandboxTemplate`) and standard Kubernetes DRA `DeviceClass` / `ResourceClaim` `OpaqueDeviceConfiguration` (supporting raw `Pod` workloads as well).
- **Reuse Kubernetes DRA + NRI mechanics (DraNet pattern):** one shared consumable-capacity `ResourceSlice` device per node, slow-path DRA preparation with zero CDI files, and fast-path NRI hooks running synchronously during `RunPodSandbox` before any container starts.
- **Support both KEP-6313 and existing CNI clusters:** default to `PodNetworkIsolated` (loopback-only Pod network namespace with no CNI attachment or Pod IP), and provide backward-compatible `NetworkPolicyDenyAll` (controller-managed deny-all `NetworkPolicy` plus `NRI RunPodSandbox` non-loopback route flush).
- **Support all four native Kubernetes upstream authentication modes** (`MTLS`, `SPIFFE`, `PodCertificate`, and `ServiceAccountToken`) while keeping private keys and tokens completely inaccessible to untrusted workload containers.
- **Preserve `SandboxWarmPool` sub-second adoption** by keeping attested Pod/Sandbox/Claim identity synchronized via a node-scoped `core/v1` Pod informer and revoking pre-claim tunnels on adoption.

### Non-Goals

- Defining a new network policy CRD (`SandboxNetworkPolicy`), binding CRD, or CEL policy evaluator inside `agent-sandbox`.
- Building a secret vault, OAuth broker, or TLS-terminating L7 inspection engine inside the node plumbing DaemonSet (those belong in the upstream gateway/portal).
- Creating per-container network interfaces (Linux network interfaces belong strictly to the Pod network namespace: at most one `tun2connect` / `tun0` per Pod or microVM).

## Proposal

### User Stories

#### Story 1: Platform operator standardizes on `agents.net` with an existing egress portal

A platform team already runs an egress gateway (such as `gke-labs/service-portals`, Envoy/Agentgateway, or a corporate proxy) that manages egress allowlists and injects API keys. They deploy the `sandbox-gateway` DaemonSet and configure cluster-wide defaults (upstream URL, TLS trust bundle, auth mode) in a DRA `DeviceClass`. Every `SandboxTemplate` simply enables `spec.network` and automatically receives loopback-only confinement and authenticated `agents.net` forwarding without adopting any new policy CRDs.

#### Story 2: Workload owner customizes upstream or private metadata per `SandboxTemplate`

A team running specialized agents overrides `spec.network.upstream` on their `SandboxTemplate` to point at a tenant-specific portal, selects `PodCertificate` or `SPIFFE` authentication, and passes team-specific metadata via `spec.network.parameters` (propagated via DRA `OpaqueDeviceConfiguration` and `Agents-Net-Param-*` headers).

#### Story 3: Standalone Kubernetes `Pod` user adopts `agents.net` plumbing directly

A cluster user running workloads outside the `Sandbox` CRD attaches the `sandbox-gateway.agents.x-k8s.io` DRA `DeviceClass` via a standard `ResourceClaim` (the exact DraNet UX) and receives identical `agents.net` confinement and upstream forwarding.

#### Story 4: Operator adopts isolated plumbing on an existing cluster without KEP-6313

An operator on a Kubernetes cluster whose CNI does not yet support loopback-only `PodNetworkIsolated` sets `confinementMode: NetworkPolicyDenyAll`. The controller reconciles a strict deny-all `NetworkPolicy` (enforced synchronously by the CNI during `RunPodSandbox`), and `sandbox-gateway`'s `NRI RunPodSandbox` hook flushes `eth0` routes before any container starts so `tun0` owns `0.0.0.0/0` and `::/0` cleanly.

### High-Level Design

```text
+-------------------------------------------------------------------+
| Sandbox Pod (Network Namespace)                                   |
|                                                                   |
|  [Untrusted Agent Container]                                      |
|   - automountServiceAccountToken: false                           |
|   - capabilities.drop: ["ALL"] (zero NET_ADMIN, zero credentials) |
|   - dnsPolicy: None -> VirtualDNS 100.127.255.253                 |
|             │  standard TCP / UDP / DNS                           |
|             ▼                                                     |
|  [sandbox-gateway-tun2connect] (1 native sidecar per Pod netns)   |
|   - owns tun0 + VirtualDNS; drops NET_ADMIN/SETPCAP after setup   |
|   - mounts /run/agents.net/egress.sock (injected via NRI)         |
+-------------------------------------------------------------------+
              │  agents.net wire over per-Pod host UDS
              │  HTTP/1.1 CONNECT + RFC 9298 connect-udp
              ▼
+-------------------------------------------------------------------+
| Node Plumbing DaemonSet: sandbox-gateway (DRA + NRI)              |
|  - DRA slow path: ResourceSlice (consumable capacity.sandboxes),  |
|    PrepareResourceClaims decodes DeviceClass+Claim Opaque params, |
|    opens per-Pod egress.sock, checkpoints to tmpfs BoltDB         |
|  - NRI fast path (zero CDI files):                                |
|    * RunPodSandbox: verify loopback-only OR flush eth0 routes     |
|    * CreateContainer: inject UDS + /dev/net/tun on tun2connect    |
|    * StopPodSandbox: immediate tunnel revocation                  |
|  - Auth Resolver (credentials never enter workload containers):   |
|    * MTLS | SPIFFE (Node / DelegatedPod) | PodCertificate | JWT   |
|  - Node-scoped core/v1 Pod informer: syncs SA & WarmPool claims   |
+-------------------------------------------------------------------+
              │  TLS / mTLS over HTTP/1.1, HTTP/2, or HTTP/3 MASQUE
              │  CONNECT + RFC 9298 connect-udp
              │  + Proxy-Authorization (JWT) / Client Cert (mTLS)
              │  + Attested Agents-Net-* Identity Headers
              ▼
+-------------------------------------------------------------------+
| Upstream Gateway / Portal (service-portals, Envoy, Corp Proxy...) |
|  - Authenticates peer & verifies Sandbox/Pod identity             |
|  - Enforces egress policy, L7 inspection, SSRF protection         |
|  - Injects API credentials / secrets                              |
+-------------------------------------------------------------------+
```

#### Why DRA + NRI (Following DraNet)

[DraNet](https://github.com/google/dranet) demonstrates a clean separation of concerns in Kubernetes node networking that avoids CDI file churn and kubelet/runtime coupling:

1. **DRA Slow Path (`PrepareResourceClaims` / `UnprepareResourceClaims`):**
   - Each node advertises **one shared device** (`sandbox-gateway`) in its `ResourceSlice` with `allowMultipleAllocations: true` and consumable `capacity.sandboxes` (default `1000`, request policy `default: 1`, `validValues: [1]`).
   - If the node daemon becomes unhealthy, it publishes a `NoSchedule` `DeviceTaint` (`sandbox-gateway.agents.x-k8s.io/unhealthy`) to stop new placements cleanly.
   - `DeviceClass.spec.config[].opaque` carries cluster-wide defaults, while per-Pod `ResourceClaim.spec.devices.config[].opaque` overlays user upstream, auth, and custom/private parameters.
   - `PrepareResourceClaims` decodes the layered parameters, creates `/run/sandbox-gateway/pods/<podUID>/egress/egress.sock`, resolves upstream auth, probes socket readiness, checkpoints state to memory-backed BoltDB, and returns **zero CDI devices**.
2. **NRI Fast Path (`RunPodSandbox` / `CreateContainer` / `StopPodSandbox` / `RemovePodSandbox` / `Synchronize`):**
   - `RunPodSandbox` executes synchronously **before any container is created or started**. Under `PodNetworkIsolated`, it verifies via netlink inside the Pod netns that only loopback exists (rejecting `hostNetwork` or unexpected CNI interfaces). Under `NetworkPolicyDenyAll` (where enforcing CNIs also apply the `NetworkPolicy` during `RunPodSandbox`), it flushes routes on non-loopback interfaces so `tun0` cleanly owns default routes without conflict.
   - `CreateContainer` injects `/run/agents.net` bind mount, `/dev/net/tun` device node, and `AGENTS_NET_*` env vars in memory via `ContainerAdjustment` **only on the Pod's single `sandbox-gateway-tun2connect` container** (in `TunSidecar` mode), leaving workload containers unmodified with zero capabilities.
   - `StopPodSandbox` immediately revokes the per-Pod listener and terminates all active upstream tunnels.
   - `Synchronize` restores live Pods' UDS listeners and auth configs across DaemonSet restarts and reaps orphans.

#### Pod Adapter Modes (Per-Pod Network Namespace Invariant)

Because Linux network interfaces belong to the Pod network namespace (never to individual containers), `adapterMode` offers three strictly Pod-scoped options:

- **`TunSidecar` (default):** Injects one distroless native sidecar initContainer (`sandbox-gateway-tun2connect`, `restartPolicy: Always`) per Pod. It declares `NET_ADMIN` + `SETPCAP` solely to create `tun0` once and drop both capabilities before entering its packet loop. All workload containers stay at zero capabilities (`drop: ["ALL"]`) and receive zero `/dev/net/tun` or UDS mounts.
- **`TunVM`:** For hypervisor/microVM runtimes (Kata, gVisor, Firecracker) that attach one `tun2connect` per microVM over vsock or Unix socket.
- **`ExplicitProxy`:** Skips TUN creation and injects `/run/agents.net/egress.sock` plus `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY` (`unix:///run/agents.net/egress.sock`) into workload containers.

#### Upstream Authentication Modes

The node plumbing terminates the per-Pod UDS outside the Pod, allowing all four Kubernetes-native authentication modes to operate without exposing private keys or tokens to untrusted workload containers (`automountServiceAccountToken: false` remains enforced):

| Mode | Mechanism | Credential Location | Best Fit |
| :--- | :--- | :--- | :--- |
| **`MTLS`** | Hot-reloaded PEM client cert/key (`certDir` or `Secret`) + CA/SPIFFE server verification + attested `Agents-Net-*` headers. | Node host dir or K8s `Secret` (never in Pod). | Works on any K8s cluster; enables shared node-level H2/H3 multiplexing and instant WarmPool claim transitions. |
| **`SPIFFE` (`Node`)** | Official SPIFFE Workload API (`go-spiffe/v2`) X.509-SVID + auto-rotating Trust Bundle + strict server SPIFFE ID/TrustDomain authorizer + attested `Agents-Net-*` headers. | Local SPIRE Agent UDS (never in Pod). | Clusters with SPIRE seeking shared node-level H2/H3 multiplexing with zero static secrets. |
| **`SPIFFE` (`DelegatedPod`)** | Streaming SPIRE Delegated Identity v1 API (`SubscribeToX509SVIDs` with selector `k8s:pod-uid:<uid>` + `SubscribeToX509Bundles`). | Fetched in memory by node DaemonSet (never in Pod). | Strongest cryptographic per-Pod workload identity with SPIRE; zero header trust. |
| **`PodCertificate` (KEP-4317)** | Controller adds a `podCertificate` projected volume (`credential-bundle.pem`, PKCS#8 + cert chain) mounted read-only **only** on `sandbox-gateway-tun2connect`. Node DaemonSet reads and hot-reloads `<kubeletRoot>/pods/<uid>/volumes/kubernetes.io~projected/sandbox-gateway-pod-cert/credential-bundle.pem`. | Kubelet projected volume isolated from workload containers. | Kubernetes 1.34+ clusters with a native KEP-4317 signer (cert-manager, GKE Workload Identity, SPIRE signer) without needing SPIRE Delegated Identity. |
| **`ServiceAccountToken` (`Node`)** | Node DaemonSet reads its own audience-bound projected SA token and sends `Proxy-Authorization: Bearer <jwt>` + attested `Agents-Net-*` headers over TLS. | Node DaemonSet projected volume (never in Pod). | Matches `gke-labs/service-portals` (`TokenReview` `authentication.kubernetes.io/node-name` verification); zero PKI required. |
| **`ServiceAccountToken` (`Pod`)** | Controller adds an audience-bound `serviceAccountToken` projected volume mounted read-only **only** on `sandbox-gateway-tun2connect`. Node DaemonSet reads and hot-reloads `<kubeletRoot>/pods/<uid>/volumes/kubernetes.io~projected/sandbox-gateway-sa-token/token` and sends `Proxy-Authorization: Bearer <jwt>`. | Kubelet projected volume isolated from workload containers. | External or out-of-cluster upstreams verifying per-Pod tokens via cluster OIDC JWKS without API server access. |

**Security invariant for Pod-projected credentials:** CEL validation enforces that `PodCertificate` and Pod-mode `ServiceAccountToken` require `adapterMode: TunSidecar`, guaranteeing kubelet-projected credentials are mounted only on the trusted `sandbox-gateway-tun2connect` sidecar and never inside untrusted workload containers.

#### Standardized `agents.net` Upstream Wire & Attested Metadata

- **TCP egress:** Standard `CONNECT host:port` over HTTP/2 (default, multiplexed over persistent TLS/mTLS connections) or HTTP/1.1.
- **UDP egress:** Standard RFC 9298 `connect-udp` (`GET /.well-known/masque/udp/{host}/{port}/`, `Upgrade: connect-udp`, `Capsule-Protocol: ?1`, RFC 9297/9298 `DATAGRAM` capsules).
- **Denials and diagnostics:** Upstream HTTP status codes (`403`, `407`, `502`) and RFC 9209 `Proxy-Status` headers propagate transparently back to the sandbox. Unconfigured upstreams or auth failures fail closed (`503` / `502`).
- **Attested workload metadata:** The node plumbing attaches sanitized, unforgeable headers from kubelet/DRA/NRI/Pod watch:
  - `Agents-Net-Sandbox-Namespace`, `Agents-Net-Sandbox-Name`
  - `Agents-Net-Pod-Name`, `Agents-Net-Pod-Uid`, `Agents-Net-Service-Account`, `Agents-Net-Node-Name`
  - `Agents-Net-Claim-Uid`, `Agents-Net-Claim-Name` (updated live on `SandboxWarmPool` adoption)
  - `Agents-Net-Param-<name>` (sanitized custom key-value parameters from `spec.network.parameters` / DRA `Opaque` config)

#### API Changes

Zero new CRDs are introduced. One optional `network` field is added to `SandboxBlueprint` in `api/v1beta1`, making it available on both `Sandbox` and `SandboxTemplate`:

```yaml
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: coding-agent
  namespace: agents
spec:
  network:
    deviceClassName: sandbox-gateway.agents.x-k8s.io # optional default
    confinementMode: PodNetworkIsolated              # PodNetworkIsolated | NetworkPolicyDenyAll
    adapterMode: TunSidecar                          # TunSidecar | TunVM | ExplicitProxy
    caTrustMode: None                                # None | MountOnly | InjectEnv
    upstream:                                        # optional if DeviceClass provides default
      address: https://egress-portal.sandbox-system.svc:8443
      protocol: HTTP2                                # HTTP1 | HTTP2 | HTTP3
      tls:
        serverName: egress-portal.sandbox-system.svc
        caBundleConfigMapRef:
          name: portal-ca
        trustDomain: cluster.local
        acceptedSPIFFEIDs:
          - spiffe://cluster.local/ns/sandbox-system/sa/portal
      auth:                                          # discriminated union (exactly one branch)
        type: SPIFFE                                 # MTLS | SPIFFE | PodCertificate | ServiceAccountToken
        spiffe:
          mode: DelegatedPod                         # Node | DelegatedPod
    ingressPorts:
      - port: 8080
        protocol: TCP
    parameters:                                      # custom key-value metadata -> DRA Opaque config
      - name: tenant
        value: team-a
  podTemplate:
    spec:
      containers:
        - name: agent
          image: example.com/agent:v1
```

Validation rules (CEL `XValidation`):
- `Sandbox` and `SandboxTemplate`: forbid `spec.service: true` when `spec.network.confinementMode` is `PodNetworkIsolated` (default).
- `SandboxTemplate`: forbid setting both `spec.network` and legacy `spec.networkPolicy`.
- `SandboxUpstreamAuth`: enforce strict discriminated union matching `type`.
- `SandboxNetworkSpec`: require `adapterMode: TunSidecar` for `PodCertificate` and Pod-mode `ServiceAccountToken`.

#### Implementation Guidance

1. **Core API (`api/v1beta1/sandbox_network_types.go`, `api/v1beta1/sandbox_types.go`, `extensions/api/v1beta1/sandboxtemplate_types.go`):**
   - Add `SandboxNetworkSpec` to `SandboxBlueprint` and register nested apply-configuration externals in `dev/tools/client-gen-go.sh`.
   - Keep all API fields KAL-compliant (enums over booleans, slices over maps, explicit `+optional`/`+required`).
2. **Controllers (`controllers/sandbox_network.go`, `controllers/sandbox_controller.go`, `extensions/controllers/`):**
   - When `sandbox.Spec.Network != nil` and `OperatingMode == Running`, reconcile a controller-owned standard Kubernetes `resource.k8s.io/v1` `ResourceClaim` carrying JSON `GatewayParameters` in `OpaqueDeviceConfiguration`. Delete the claim on suspension or expiry to release consumable node capacity.
   - Inject `ApplySandboxNetworkPodSpec` defaults (`enableServiceLinks: false`, `dnsPolicy: None` with `100.127.255.253`, single `sandbox-gateway-tun2connect` sidecar, isolated projected volumes for `PodCertificate`/`ServiceAccountToken(Pod)`, and `pod.Spec.ResourceClaims`).
   - Allow `PodNetworkIsolated` Sandboxes to become `Ready=True` and be adopted from `SandboxWarmPool` based on `NodeName` without requiring `PodIPs`.
   - Update `compareSandboxBlueprint` in `extensions/controllers/sandboxwarmpool_controller.go` to track `Network` drift.
   - Under `SandboxTemplate` with `NetworkPolicyDenyAll`, reconcile a strict empty-ingress/empty-egress deny-all `NetworkPolicy`. Under `PodNetworkIsolated`, skip/clean owned `NetworkPolicy`.
3. **Node Plumbing DaemonSet (`packages/sandbox-gateway`):**
   - `pkg/params`: layered `DeviceClass` + `ResourceClaim` `OpaqueDeviceConfiguration` decoder with `custom` and arbitrary `opaque` JSON blocks.
   - `pkg/auth`: all four native auth modes (`mtls.go`, `spiffe.go` using `github.com/spiffe/go-spiffe/v2` + streaming SPIRE Delegated Identity v1 client, `podcert.go` atomic KEP-4317 PEM bundle reader, `satoken.go` hot-reloading Node/Pod JWT reader).
   - `pkg/tunnel`: per-Pod UDS listener manager, strict RFC 9110/9112/9209/9298 parser and capsule stream, multiplexed HTTP/2 + HTTP/1.1 upstream dialer, immediate revocation, and structured `agents.net` JSONL audit logging.
   - `pkg/store`: schema-versioned BoltDB tmpfs checkpoint store.
   - `pkg/driver`: DraNet-style DRA `kubeletplugin.DRAPlugin` + NRI plugin + node-scoped `core/v1` Pod informer for `ServiceAccount` and warm-pool claim sync.
   - `pkg/metrics`: bounded-cardinality Prometheus counters/gauges/histograms.

## Scalability

- **Zero extra CRDs and zero per-Pod policy watches:** Because configuration flows through standard Kubernetes DRA `ResourceClaim` allocations delivered by kubelet, the node DaemonSet requires no custom CRD informers. Its single API watch is a node-scoped `core/v1` Pod informer (`fieldSelector: spec.nodeName=<node>`), scaling linearly with local Pod count only.
- **Single `ResourceSlice` per node:** Using DRA consumable capacity (`allowMultipleAllocations: true`, `capacity.sandboxes: 1000`) produces exactly **one** `ResourceSlice` object per node instead of thousands of individual device entries.
- **Zero CDI disk I/O on the Pod start path:** NRI `CreateContainer` injects mounts and `/dev/net/tun` in memory, avoiding per-Pod CDI JSON file creation and fsync overhead at high Pod churn.
- **Multiplexed HTTP/2 upstream connections:** `MTLS`, `SPIFFE (Node)`, and `ServiceAccountToken` modes multiplex tunnels over persistent HTTP/2 TLS connections, keeping TLS handshake overhead negligible even under bursty agent tool calls.
- **WarmPool compatibility:** Pre-warmed Sandboxes remain ready with zero cold start; on `SandboxClaim` adoption, the node-scoped Pod informer detects `agents.x-k8s.io/claim-uid` changes, refreshes attested headers, and revokes pre-claim tunnels immediately.

## Alternatives

### Alternative 1: Standalone `SandboxNetworkPolicy` and `SandboxNetworkBinding` CRDs with embedded CEL engine

An earlier design proposed shipping a `network.agents.x-k8s.io/v1alpha1` API group with a node-local CEL policy engine and credential-injection proxy directly inside `agent-sandbox`. We rejected this because:
- It duplicates policy, L7 inspection, and secret-injection responsibilities already solved by specialized upstreams (`gke-labs/service-portals`, Envoy/Agentgateway, Cilium, corporate egress gateways).
- It expands CRD surface area, controller RBAC, and API-server watch load (`SandboxNetworkBinding` per Sandbox).
- Decoupling the plumbing from policy/secrets promotes **`agents.net`** as a clean interoperability boundary that any upstream can implement.

### Alternative 2: Sidecar-only upstream authentication without a node DaemonSet

Having `tun2connect` dial the upstream directly over the cluster network avoids a node DaemonSet, but:
- Cannot work under KEP-6313 `PodNetworkIsolated` (loopback-only Pod network namespaces have no routable interface to reach an upstream Service).
- Requires allowing egress to the upstream IP in CNI `NetworkPolicy` (weakening isolation) and prevents NRI `RunPodSandbox` verification and `eth0` route flushing before container start.
- Prevents using node-level SPIFFE Delegated Identity or node-attested credentials completely outside the Pod.

### Alternative 3: Hardcoding a single upstream authentication mechanism

Choosing only mTLS or only ServiceAccount JWTs breaks real clusters: SPIRE environments expect SPIFFE X.509-SVIDs, Kubernetes 1.34+ clusters are adopting KEP-4317 `PodCertificateRequest`, `gke-labs/service-portals` uses node-attested `ServiceAccountToken` (`TokenReview`), and corporate proxies often use standard rotated mTLS certs. Supporting all four native Kubernetes auth modes behind a compact discriminated union covers every deployment environment cleanly.
