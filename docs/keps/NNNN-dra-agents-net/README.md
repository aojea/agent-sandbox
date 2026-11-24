# KEP-NNNN: `dra-agents-net` — Standardized `agents.net` Traffic Plumbing via DRA and NRI

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
    - [Story 1: Platform operator standardizes on <code>agents.net</code> with an existing Policy Enforcement Point](#story-1-platform-operator-standardizes-on-agentsnet-with-an-existing-policy-enforcement-point)
    - [Story 2: Cluster operator plugs in a CNI or alternative Kubernetes Network Driver](#story-2-cluster-operator-plugs-in-a-cni-or-alternative-kubernetes-network-driver)
    - [Story 3: Workload owner customizes PEP auth, Pod CA trust, or custom metadata per <code>SandboxTemplate</code>](#story-3-workload-owner-customizes-pep-auth-pod-ca-trust-or-custom-metadata-per-sandboxtemplate)
    - [Story 4: Standalone Kubernetes <code>Pod</code> user adopts <code>agents.net</code> plumbing directly](#story-4-standalone-kubernetes-pod-user-adopts-agentsnet-plumbing-directly)
    - [Story 5: Operator adopts isolated plumbing on an existing cluster without KEP-6313](#story-5-operator-adopts-isolated-plumbing-on-an-existing-cluster-without-kep-6313)
  - [High-Level Design](#high-level-design)
    - [Why the Kubernetes Network Driver (KND) Model (DRA + NRI)](#why-the-kubernetes-network-driver-knd-model-dra--nri)
    - [DRA Opaque Configuration Layering (<code>DeviceClass</code> Driver Config + <code>ResourceClaim</code> Sandbox Stanza)](#dra-opaque-configuration-layering-deviceclass-driver-config--resourceclaim-sandbox-stanza)
    - [Driver-Configured Pod Adapter Modes &amp; Multi-Language Proxy Environment Variables](#driver-configured-pod-adapter-modes--multi-language-proxy-environment-variables)
    - [Declarative Pod CA Certificates (<code>agents.net</code> + Language Trust Env Vars)](#declarative-pod-ca-certificates-agentsnet--language-trust-env-vars)
    - [Policy Enforcement Point Authentication Modes](#policy-enforcement-point-authentication-modes)
    - [Standardized <code>agents.net</code> PEP Wire &amp; Attested Metadata](#standardized-agentsnet-pep-wire--attested-metadata)
    - [Explicit Host-Side Ingress &amp; <code>sandbox-router</code> Integration](#explicit-host-side-ingress--sandbox-router-integration)
    - [API Changes](#api-changes)
    - [Implementation Guidance](#implementation-guidance)
- [Scalability](#scalability)
- [Alternatives](#alternatives)
  - [Alternative 1: Standalone <code>SandboxNetworkPolicy</code> and <code>SandboxNetworkBinding</code> CRDs with embedded CEL engine](#alternative-1-standalone-sandboxnetworkpolicy-and-sandboxnetworkbinding-crds-with-embedded-cel-engine)
  - [Alternative 2: Exposing <code>HTTP_PROXY=unix:///run/agents.net/egress.sock</code> in <code>ExplicitProxy</code> mode](#alternative-2-exposing-http_proxyunixrunagentsnetegresssock-in-explicitproxy-mode)
  - [Alternative 3: Hardcoding a single PEP authentication mechanism](#alternative-3-hardcoding-a-single-pep-authentication-mechanism)
  - [Alternative 4: Publishing per-pod exclusive slot devices (<code>slot-0</code>..<code>slot-&lt;N-1&gt;</code>)](#alternative-4-publishing-per-pod-exclusive-slot-devices-slot-0slot-n-1)
  - [Alternative 5: Embedding the entire <code>Sandbox</code> CR or injecting driver sidecars in the <code>agent-sandbox</code> controller](#alternative-5-embedding-the-entire-sandbox-cr-or-injecting-driver-sidecars-in-the-agent-sandbox-controller)
- [References](#references)
<!-- /toc -->

## Summary

This KEP defines a driver-agnostic `SandboxBlueprint.network` API for `agent-sandbox` together with `dra-agents-net`, a standalone, node-local Kubernetes DRA + NRI traffic plumbing driver (developed initially in `packages/dra-agents-net/` with zero Go module dependency on `sigs.k8s.io/agent-sandbox`, designed to move cleanly to its own repository). `dra-agents-net` isolates sandbox Pods from direct network egress and forwards all TCP, UDP, and DNS traffic over the **`agents.net`** wire protocol (`HTTP CONNECT`, RFC 9298 `connect-udp`, `Boundary-Reason`, RFC 9209 `Proxy-Status`) to an authenticated **Policy Enforcement Point (PEP)** proxy or portal.

Rather than introducing standalone network policy or credential-broker CRDs into `agent-sandbox`, `agent-sandbox` declares traffic plumbing directly on `Sandbox` / `SandboxTemplate` (`SandboxBlueprint.network`) and projects it onto standard Kubernetes `ResourceClaim` objects via the **Kubernetes Network Driver (KND) Model** — using **Dynamic Resource Allocation (DRA)** (default driver `dra.agents.net`, overridable via `driverName` for OVN-Kubernetes, Calico, Cilium, Antrea, or any other KND driver) and the **Node Resource Interface (NRI)**, as introduced in Antonio Ojea, *"[The Kubernetes Network Driver Model: A Composable Architecture for High-Performance Networking](https://doi.org/10.1109/LCN65610.2025.11146291)"* (2025 IEEE 50th Conference on Local Computer Networks (LCN), [arXiv:2506.23628](https://arxiv.org/abs/2506.23628)) and demonstrated by [DRANET](https://github.com/kubernetes-sigs/dranet) (`dra.net`).

Just as [`kube-network-policies`](https://github.com/kubernetes-sigs/kube-network-policies) breaks the hard dependency on the underlying CNI by providing a CNI-agnostic Kubernetes reference implementation for network policy, the KND Model lets `dra-agents-net` serve as a **batteries-included**, CNI-agnostic reference implementation that works out of the box on any Kubernetes cluster. At the same time, because `Sandbox.spec.network` and its DRA `SandboxNetworkConfiguration` contract are strictly driver-agnostic, existing networking ecosystems — including **OVN-Kubernetes**, **Calico**, **Cilium**, **Antrea**, service meshes, and cloud dataplanes — can assume these responsibilities natively in their own dataplanes. This design balances **batteries-included portability** with **ecosystem diversity**, helping the broader Kubernetes networking ecosystem adapt without picking winners.

The `agent-sandbox` controller stays strictly driver-agnostic: it does not inject sidecars, synthetic DNS resolvers, or driver-specific projected volumes. Instead, it embeds the `Sandbox.spec.network` stanza as a versioned `SandboxNetworkConfiguration` payload inside `ResourceClaim.spec.devices.config[].opaque.parameters` (addressed to `spec.network.driverName`), while driver-specific parameters such as `adapterMode`, loopback proxy ports, and CNI/eBPF knobs live in the driver's `DeviceClass.spec.config`. Policy enforcement (allowlists, CEL, L7 HTTP/MCP inspection, SSRF filtering) and secret/credential injection (such as `gke-labs/service-portals`, Envoy/Agentgateway, or corporate egress gateways) remain decoupled in the required Policy Enforcement Point (PEP). To let the PEP enforce per-sandbox policies and inject per-sandbox credentials without exposing secrets to untrusted agent code, `dra-agents-net` supports all four Kubernetes-native PEP authentication modes (**mTLS**, **SPIFFE**, **KEP-4317 `PodCertificate`**, and **bound `ServiceAccountToken`**), declarative Pod CA trust bundles (`AGENT_CA_CERT` plus language-specific CA env vars), goroutine-safe `socketat` Pod-loopback listeners with full language proxy env var injection for `ExplicitProxy` mode, and an explicit node-local HTTP `CONNECT` ingress bridge wired into `sandbox-router`.

## Motivation

AI coding agents and autonomous workloads running inside `Sandbox` Pods execute untrusted code and need strict network confinement alongside authenticated access to external APIs, MCP servers, and package registries.

Existing approaches force painful trade-offs:

1. **CNI `NetworkPolicy` alone operates at L3/L4 only.** It cannot enforce hostname, HTTP, or MCP rules, cannot inject credentials transparently, and still attaches a cluster-routable interface (`eth0`) and Pod IP to every sandbox.
2. **In-container proxies and environment variables alone are bypassable and leak secrets.** Untrusted processes ignore `HTTP_PROXY`, open raw TCP/UDP sockets, or exfiltrate any credential or ServiceAccount token mounted inside the container.
3. **Baking a bespoke policy engine, secret broker, or single network driver into `agent-sandbox` fragments the ecosystem and promotes lock-in.** Cluster operators run diverse Policy Enforcement Points (`gke-labs/service-portals`, Envoy/Agentgateway, corporate proxies) and diverse CNI and networking stacks (OVN-Kubernetes, Calico, Cilium, Antrea, Istio, and cloud-managed CNIs). Coupling the `Sandbox` controller to one CNI or to one driver's sidecar injection prevents other ecosystem projects from implementing `Sandbox.spec.network` natively.
4. **Depending on CNI-specific extensions blocks out-of-the-box adoption.** Historically, Kubernetes networking features either waited for every CNI to implement them or forced operators onto a single CNI. Projects such as [`kube-network-policies`](https://github.com/kubernetes-sigs/kube-network-policies) proved the value of CNI-agnostic Kubernetes reference implementations that solve the CNI dependency problem immediately while allowing existing CNIs to take over enforcement natively.

### Goals

- **Promote `agents.net` as a vendor-neutral standard** for sandbox network interception (`CONNECT` + RFC 9298 `connect-udp` over per-Pod Unix domain sockets, `Boundary-Reason`, `AGENT_CA_CERT`) and Policy Enforcement Point (PEP) forwarding (`HTTP/1.1` and multiplexed `HTTP/2`, with future `HTTP/3` MASQUE compatibility, plus RFC 9209 `Proxy-Status` and attested `Agents-Net-*` identity headers).
- **Balance batteries-included portability with ecosystem diversity (zero CNI lock-in):** Follow the reference-implementation pattern of [`kube-network-policies`](https://github.com/kubernetes-sigs/kube-network-policies) and [DRANET](https://github.com/kubernetes-sigs/dranet). Ship `dra-agents-net` as a CNI-agnostic Kubernetes reference driver that works on any cluster, while keeping `agent-sandbox` strictly driver-agnostic (zero new policy or binding CRDs and zero sidecar injection). Declare `driverName` (defaulting to `dra.agents.net`), optional `deviceClassName` (defaulting to `driverName`), confinement mode, and required `policyEnforcementPoint` on `SandboxBlueprint.network`, and embed the `network` stanza inside DRA `OpaqueDeviceConfiguration` so `dra-agents-net`, OVN-Kubernetes, Calico, Cilium, Antrea, or any other KND driver can assume these responsibilities directly without `GET`ing the `Sandbox` CR.
- **Keep driver-specific parameters in `DeviceClass`:** Place implementation-specific knobs (`adapterMode`, `ExplicitProxy` port/`noProxy`, connection limits, or CNI dataplane settings for OVS/OVN, eBPF, or nftables/iptables) in `DeviceClass.spec.config[].opaque.parameters`, cleanly separated from portable `Sandbox` intent via Kubernetes `apiVersion`/`kind` (`TypeMeta`) discrimination.
- **Keep `dra-agents-net` completely standalone and reusable across Kubernetes.** Ship `packages/dra-agents-net` as an independent Go module with its own `pkg/apis` DRA wire schema and zero imports from `sigs.k8s.io/agent-sandbox`, so raw Kubernetes `Pod` users can adopt it immediately and the driver can move to its own repository without breaking contracts.
- **Reuse native Kubernetes DRA (`DRAConsumableCapacity`) + NRI mechanics (DraNet pattern):** publish a single shared `resource.k8s.io/v1` device (`agents-net`, `allowMultipleAllocations: true`) per node using `DRAConsumableCapacity` (Beta, enabled by default since Kubernetes 1.36) with consumable `sandboxes` capacity auto-sized to `node.Status.Allocatable.Pods()` and `requestPolicy.default: "1"`, slow-path DRA preparation with zero CDI files, and fast-path NRI hooks running synchronously during `RunPodSandbox` before any container starts.
- **Support both KEP-6313 and existing CNI clusters:** default to `PodNetworkIsolated` (loopback-only Pod network namespace with no CNI attachment or Pod IP), and provide backward-compatible `NetworkPolicyDenyAll` (controller-managed deny-all `NetworkPolicy` plus `NRI RunPodSandbox` non-loopback route flush).
- **Support all four native Kubernetes PEP authentication modes** (`MTLS`, `SPIFFE`, `PodCertificate`, and `ServiceAccountToken`) while keeping private keys and tokens completely inaccessible to untrusted workload containers.
- **Follow Kubernetes, `cert-manager`, `trust-manager`, and Gateway API certificate conventions:** support `ConfigMap`, `Secret` (strictly extracting `CERTIFICATE` PEM blocks only), `ClusterTrustBundle`, and `HostPath` uniformly on both `caTrust.sources` and `policyEnforcementPoint.tls.caCertificateRefs`, with `AGENT_CA_CERT` + full multi-language CA/proxy env var injection and a parametrizable `socketat`-bound `127.0.0.1:<port>` (default `15001`) loopback listener for `ExplicitProxy`.
- **Preserve `SandboxWarmPool` sub-second adoption** by keeping attested Pod/Sandbox/Claim identity synchronized via a node-scoped `core/v1` Pod informer and revoking pre-claim tunnels on adoption.

### Non-Goals

- Defining a new network policy CRD (`SandboxNetworkPolicy`), binding CRD, or CEL policy evaluator inside `agent-sandbox`.
- Building a secret vault, OAuth broker, or TLS-terminating L7 inspection engine inside `dra-agents-net` (those belong in the Policy Enforcement Point).
- Injecting driver-specific sidecar containers (such as `tun2connect`), synthetic DNS resolvers, or projected credential volumes inside the `agent-sandbox` controller (those belong to the network driver, via its own mutating webhook or `SandboxTemplate.spec.podTemplate`).
- Creating per-container network interfaces (Linux network interfaces belong strictly to the Pod network namespace: at most one `tun2connect` / `tun0` per Pod or microVM).

## Proposal

### User Stories

#### Story 1: Platform operator standardizes on `agents.net` with an existing Policy Enforcement Point

A platform team runs a Policy Enforcement Point (such as `gke-labs/service-portals`, Envoy/Agentgateway, or a corporate proxy) that enforces egress allowlists and injects API keys. They deploy the `dra-agents-net` DaemonSet and configure driver-specific defaults (`adapterMode: ExplicitProxy`, `proxy.port: 15001`, connection limits, and optional default TLS/CA/auth bundles) in the `dra.agents.net` DRA `DeviceClass`. Every `SandboxTemplate` sets `spec.network.policyEnforcementPoint.url` and automatically receives loopback-only confinement and authenticated `agents.net` forwarding without introducing new policy CRDs.

#### Story 2: Cluster operator plugs in a CNI or alternative Kubernetes Network Driver

A cluster operator running a CNI or networking stack with native KND support (such as OVN-Kubernetes, Calico, Cilium, or Antrea) creates a `DeviceClass` with that driver's `OpaqueDeviceConfiguration` (for example, `apiVersion: dra.cni.example/v1alpha1, kind: DriverConfig`). Workload owners set `spec.network.driverName: dra.cni.example` (and optional `deviceClassName`) plus `spec.network.policyEnforcementPoint`. The `agent-sandbox` controller generates a `ResourceClaim` targeting that driver and embeds the `Sandbox.spec.network` stanza inside `Opaque.Parameters`, without injecting `dra-agents-net` sidecars or DNS overrides. The CNI assumes confinement and traffic redirection directly in its own dataplane.

#### Story 3: Workload owner customizes PEP auth, Pod CA trust, or custom metadata per `SandboxTemplate`

A team configures `spec.network.policyEnforcementPoint` on its `SandboxTemplate` to target a tenant-specific PEP, selects `PodCertificate`, `MTLS`, `SPIFFE`, or `ServiceAccountToken` authentication, declares its inspection CA via `spec.network.caTrust` (`ConfigMap`, `cert-manager` `kubernetes.io/tls` `Secret`, or KEP-3257 `ClusterTrustBundle`), and passes team-specific metadata via `spec.network.parameters` (propagated via DRA `OpaqueDeviceConfiguration` and `Agents-Net-Param-*` headers).

#### Story 4: Standalone Kubernetes `Pod` user adopts `agents.net` plumbing directly

A cluster user running workloads outside the `Sandbox` CRD attaches the `dra.agents.net` DRA `DeviceClass` via a standard `ResourceClaim` carrying `dra.agents.net/v1alpha1` `DriverConfig` (the exact DraNet UX) and receives identical `agents.net` confinement, CA trust injection, and PEP forwarding.

#### Story 5: Operator adopts isolated plumbing on an existing cluster without KEP-6313

An operator on a Kubernetes cluster whose CNI does not yet support loopback-only `PodNetworkIsolated` sets `confinementMode: NetworkPolicyDenyAll`. The controller reconciles a strict deny-all `NetworkPolicy` (enforced synchronously by the CNI during `RunPodSandbox`), and `dra-agents-net`'s `NRI RunPodSandbox` hook flushes non-loopback routes before any container starts so no container can bypass the configured PEP.

### High-Level Design

```text
+-------------------------------------------------------------------+
| Sandbox Pod (Network Namespace)                                   |
|                                                                   |
|  [Untrusted Agent Container]                                      |
|   - automountServiceAccountToken: false                           |
|   - enableServiceLinks: false                                     |
|   - capabilities.drop: ["ALL"] (zero NET_ADMIN, zero credentials) |
|   - Pod CA bundles mounted at /var/run/agent-ca.pem (+ extra-ca)  |
|     with AGENT_CA_CERT + language CA env vars                     |
|   - ExplicitProxy (default DeviceClass): 127.0.0.1:<port> via     |
|     socketat + language proxy env vars (zero sidecar needed)      |
|   - TunSidecar (driver-configured DeviceClass + driver webhook    |
|     or PodTemplate): 1 agents-net-tun2connect sidecar per Pod     |
+-------------------------------------------------------------------+
              │  agents.net wire over per-Pod host UDS (or socketat loopback)
              │  HTTP/1.1 CONNECT + RFC 9298 connect-udp
              ▼
+-------------------------------------------------------------------+
| Standalone Node DaemonSet: dra-agents-net (DRA "dra.agents.net")  |
|  - DRA slow path: 1 ResourceSlice / 1 shared device ("agents-net",|
|    allowMultipleAllocations, capacity.sandboxes = maxPods, def=1),|
|    PrepareResourceClaims decodes ordered Opaque configs:          |
|      1. Class: dra.agents.net/v1alpha1 DriverConfig               |
|      2. Claim: agents.x-k8s.io/v1beta1 SandboxNetworkConfiguration|
|    opens per-Pod egress.sock, materializes Pod CA bundles,        |
|    checkpoints to tmpfs BoltDB                                    |
|  - NRI fast path (zero CDI files):                                |
|    * RunPodSandbox: verify loopback-only OR flush eth0 routes;    |
|      for ExplicitProxy, bind 127.0.0.1:<port> via socketat        |
|    * CreateContainer: inject UDS + /dev/net/tun (TunSidecar),     |
|      mount Pod CA bundles, inject CA + language proxy env vars    |
|    * StopPodSandbox: immediate tunnel & ingress revocation        |
|  - Auth Resolver (credentials never enter workload containers):   |
|    * MTLS | SPIFFE (Node / DelegatedPod) | PodCertificate | JWT   |
|  - Host Ingress Bridge (:15080, optional TLS/mTLS):               |
|    * HTTP/1.1 CONNECT <podUID>:<port> -> ingress.sock or socketat |
|  - Node-scoped core/v1 Pod informer: syncs SA & WarmPool claims   |
+-------------------------------------------------------------------+
              │  TLS / mTLS over HTTP/1.1 or multiplexed HTTP/2
              │  CONNECT + RFC 9298 connect-udp
              │  + Proxy-Authorization (JWT) / Client Cert (mTLS)
              │  + Attested Agents-Net-* Identity Headers
              ▼
+-------------------------------------------------------------------+
| Policy Enforcement Point (PEP) (service-portals, Envoy, Proxy...) |
|  - Authenticates peer & verifies Sandbox/Pod identity             |
|  - Enforces egress policy, L7 inspection, SSRF protection         |
|  - Injects API credentials / secrets                              |
+-------------------------------------------------------------------+
```

#### Why the Kubernetes Network Driver (KND) Model (DRA + NRI)

The **Kubernetes Network Driver (KND) Model** (Antonio Ojea, *"[The Kubernetes Network Driver Model: A Composable Architecture for High-Performance Networking](https://doi.org/10.1109/LCN65610.2025.11146291)"*, IEEE LCN 2025, [arXiv:2506.23628](https://arxiv.org/abs/2506.23628)), validated by [DRANET](https://github.com/kubernetes-sigs/dranet) (`dra.net`), replaces fragile CNI chaining and container-scoped Device Plugins with composable DRA + NRI drivers that avoid CDI file churn and API-server lookups on the critical Pod startup path.

Critically, the KND Model solves Kubernetes's long-standing **CNI dependency problem** in the same way [`kubernetes-sigs/kube-network-policies`](https://github.com/kubernetes-sigs/kube-network-policies) does for `NetworkPolicy`. Both projects provide CNI-agnostic Kubernetes reference implementations that work on any cluster immediately — **batteries included** — without waiting on CNI-specific extensions or locking operators into a single CNI vendor. At the same time, because `agent-sandbox` communicates solely through standard DRA `ResourceClaim` objects carrying `SandboxNetworkConfiguration`, existing CNI and networking ecosystems — **OVN-Kubernetes**, **Calico**, **Cilium**, **Antrea**, service meshes, and cloud-managed dataplanes — can assume those exact responsibilities natively in their own dataplanes (OVS/OVN flows, nftables/iptables, eBPF, or hardware offload) with zero changes to `Sandbox` manifests or the `agent-sandbox` controller. This achieves the ideal balance between **batteries included** and **ecosystem diversity**.

`dra-agents-net` (`dra.agents.net`) implements this KND reference architecture as follows:

1. **DRA Slow Path (`PrepareResourceClaims` / `UnprepareResourceClaims`):**
   - Each node advertises **one** shared `resource.k8s.io/v1` device (`agents-net`, `allowMultipleAllocations: true`) inside a single `ResourceSlice` using `DRAConsumableCapacity` (Beta, enabled by default since Kubernetes 1.36). Its `sandboxes` capacity auto-detects `node.Status.Allocatable.Pods()` (defaulting to `110`, overridable via `--max-sandboxes`) with `requestPolicy: {default: "1", validValues: ["1"]}`. Because `requestPolicy.default` is `1`, standard `ResourceClaim`s without explicit capacity requests automatically consume `1` unit each, avoiding per-pod slot enumeration and never needing `ResourceSlice` chunking even on high-density (>128 pod) nodes.
   - If the node daemon becomes unhealthy, it withdraws its `ResourceSlice` cleanly (stopping new placements without disrupting running Pods and without requiring `DRADeviceTaints`).
   - `PrepareResourceClaims` decodes the ordered `OpaqueDeviceConfiguration` entries from `claim.Status.Allocation.Devices.Config` (first `DeviceClass` driver-specific config, then `ResourceClaim` portable `SandboxNetworkConfiguration`), creates `/run/dra-agents-net/pods/<podUID>/egress/egress.sock`, resolves PEP auth, materializes any declarative Pod CA bundles, probes socket readiness, checkpoints state (including `shareID`) to memory-backed BoltDB, and returns **zero CDI devices**.
   - Device readiness is reported on `ResourceClaim.status.devices` (propagating `matchedResult.ShareID` to match `status.allocation.devices.results`) via a targeted `MergePatch` on the `status` subresource using least-privilege `resourceclaims/driver` (`associated-node:patch`) RBAC so immutable `status.allocation` is never rewritten.
2. **NRI Fast Path (`RunPodSandbox` / `CreateContainer` / `StopPodSandbox` / `RemovePodSandbox` / `Synchronize`):**
   - `RunPodSandbox` executes synchronously **before any container is created or started**. Under `PodNetworkIsolated`, it verifies via `socketat.DoAtNSPath` + netlink that only loopback exists (rejecting `hostNetwork` or unexpected CNI interfaces). Under `NetworkPolicyDenyAll` (where enforcing CNIs also apply the `NetworkPolicy` during `RunPodSandbox`), it flushes routes on non-loopback interfaces and (by default, `nicBlockMode: DropAll`) attaches pure-netlink `tc clsact` `matchall` `TC_ACT_SHOT` drop filters on both ingress and egress of every non-loopback NIC inside the Pod netns so primary and secondary NICs stay blocked independently of CNI `NetworkPolicy` enforcement (without touching host-side CNI hooks; cluster admins may opt out via driver-only `DeviceClass` `nicBlockMode: Disabled`).
   - Under `ExplicitProxy`, `RunPodSandbox` also binds `127.0.0.1:<port>` inside the Pod's network namespace using the [`aojea/socketat`](https://github.com/aojea/socketat) mechanism (`runtime.LockOSThread()`, opening `/proc/<pid>/task/<tid>/ns/net`, `unix.Setns`, synchronous `net.Listen`, restoring the thread's original namespace) and attaches the resulting `net.Listener` to the Pod's tunnel pipeline. Once created, the listening FD lives in the Pod's loopback namespace while `Accept()` and forwarding run safely on host goroutines with zero namespace leakage.
   - `CreateContainer` injects `/run/agents.net` bind mount, `/dev/net/tun` device node, and `AGENTS_NET_*` env vars in memory via `ContainerAdjustment` **only on the Pod's single `agents-net-tun2connect` container** (when the `DeviceClass` selects `TunSidecar`), plus Pod CA mounts and CA/proxy env vars on workload containers without clobbering user-defined environment variables.
   - `StopPodSandbox` immediately revokes both UDS and `socketat` loopback listeners, terminates active PEP tunnels, and revokes active host ingress tunnels.
   - `Synchronize` restores live Pods' UDS and `socketat` loopback listeners across restarts (skipping already-live listeners on in-place NRI reconnects via `HasExtraListener`), reaps orphans, and inspects running prepared Pods for missing confinement or mounts.
3. **DRA/NRI Lifecycle Supervision & Observability (DraNet `#403`, `#426`, `#427`):**
   - **Startup ordering & fail-fast bind:** `dra-agents-net` binds `--metrics-addr` (`/healthz`, `/healthz/dra`, `/healthz/nri`, `/metrics`) before starting the driver, connects NRI FIRST with `FailurePolicy{FailRequest: true, KeepConnected: true}`, and waits until `nriConnected` is true before starting and registering the DRA kubelet plugin.
   - **Reconnect supervision & claim gating:** `runNRI` reconnects with exponential backoff (`1s..16s`), resetting its failure streak after each successful session so routine runtime restarts do not crash the driver (exiting after 5 consecutive failures). While NRI is disconnected, `PrepareResourceClaims` rejects non-empty batches so kubelet cannot start unconfined Pods.
   - **Graceful 3-step shutdown drain:** `Stop` halts DRA first, waits until prepared Pods pass a 10s quiet grace period after their last NRI hook (capped at 5m), and only then cancels the context and stops NRI.
   - **Auditing unplumbed Pods on `Synchronize`:** If a fault (`SIGKILL`, panic, or runtime restart) lets the runtime create a prepared Pod while NRI is absent, `Synchronize` detects missing netns isolation or container mounts on any running container, logs an error, increments `dra_agents_net_pods_missing_plumbing_total`, and emits a Pod `Warning` Event (`AgentsNetPlumbingMissing`).
   - **Health & Prometheus endpoints:** `/healthz` evaluates the logical AND of `dra` and `nri` (supporting `?verbose` and `?exclude=<name>`), wired to DaemonSet `startupProbe` and `readinessProbe` (not `livenessProbe`, avoiding killing live sandboxes on brief runtime restarts). `/metrics` exposes DRA/NRI request counters and latency histograms, published device gauges, disconnect/reconnect counters, and tunnel/ingress metrics.

#### DRA Opaque Configuration Layering (`DeviceClass` Driver Config + `ResourceClaim` Sandbox Stanza)

A key design goal is letting multiple Kubernetes Network Drivers (`dra.agents.net`, OVN-Kubernetes, Calico, Cilium, Antrea, Istio, or cloud-provider drivers) implement `Sandbox.spec.network` cleanly without leaking any driver's internal configuration into the `agent-sandbox` controller and without forcing node drivers to issue API-server `GET` requests back to the `Sandbox` CR.

Kubernetes GA DRA (`resource.k8s.io/v1`) solves this directly because `ResourceClaim.status.allocation.devices.config` is an **ordered slice** of self-identifying `OpaqueDeviceConfiguration` entries (each tagged with `opaque.driver` and carrying JSON with Kubernetes `apiVersion` + `kind` `TypeMeta`, up to 10 KiB per entry):

1. **Class layer (`Source: Class`, from `DeviceClass.spec.config`):** Owned by the cluster administrator / driver operator. Carries **driver-specific parameters** using the driver's own `apiVersion` and `kind`.
   - For `dra-agents-net`, `DeviceClass.spec.config` carries `apiVersion: dra.agents.net/v1alpha1`, `kind: DriverConfig` containing admin-owned driver settings (`nicBlockMode`, `adapterMode`, `proxy.port`/`noProxy`, `maxConnections`, `idleTimeoutSeconds`, host-local CA/mTLS/SPIFFE paths) plus optional cluster-wide defaults (`policyEnforcementPoint.tls`/`auth`, `caTrust`, `custom`, and default `confinementMode` for standalone raw Pods; `Sandbox` CRs default `confinementMode` to `PodNetworkIsolated` at the CRD/controller level):
     ```yaml
     apiVersion: resource.k8s.io/v1
     kind: DeviceClass
     metadata:
       name: dra.agents.net
     spec:
       selectors:
         - cel:
             expression: device.driver == "dra.agents.net"
       config:
         - opaque:
             driver: dra.agents.net
             parameters:
               apiVersion: dra.agents.net/v1alpha1
               kind: DriverConfig
               confinementMode: PodNetworkIsolated
               adapterMode: ExplicitProxy
               proxy:
                 port: 15001
               maxConnections: 1024
               idleTimeoutSeconds: 300
     ```
   - An ecosystem CNI driver (such as OVN-Kubernetes, Calico, Cilium, or Antrea) defines its own `DeviceClass` with its driver name (for example, `opaque.driver: dra.cni.example`) and its own `apiVersion`/`kind` parameters (such as OVS/OVN, nftables/iptables, eBPF, or DNS proxy settings).
2. **Claim layer (`Source: Claim`, from `ResourceClaim.spec.devices.config`):** Generated automatically by the `agent-sandbox` controller when reconciling `Sandbox.spec.network`. The controller stamps `opaque.driver` with `spec.network.driverName` (defaulting to `dra.agents.net`) and targets `deviceClassName` (defaulting to `driverName` when omitted), embedding the exact `Sandbox.spec.network` stanza inside a versioned `SandboxNetworkConfiguration` envelope:
   ```json
   {
     "apiVersion": "agents.x-k8s.io/v1beta1",
     "kind": "SandboxNetworkConfiguration",
     "network": {
       "driverName": "dra.agents.net",
       "deviceClassName": "dra.agents.net",
       "confinementMode": "PodNetworkIsolated",
       "policyEnforcementPoint": {
         "url": "https://egress-portal.sandbox-system.svc:8443",
         "tls": { "..." },
         "auth": { "..." }
       },
       "caTrust": { "..." },
       "ingressPorts": [ { "port": 8080, "protocol": "TCP" } ],
       "parameters": [ { "name": "tenant", "value": "team-a" } ]
     }
   }
   ```
3. **Driver decoding (`NodePrepareResources`):** Kubelet delivers `[Class configs..., Claim config]` in order to the driver matching `opaque.driver`. The driver inspects each entry's `apiVersion` and `kind`:
   - Recognizes its own `DriverConfig` (`dra.agents.net/v1alpha1`) for driver-specific mechanics (`adapterMode`, `proxy.port`, `proxy.noProxy`, `maxConnections`, class defaults).
   - Recognizes `agents.x-k8s.io/v1beta1` `SandboxNetworkConfiguration` and overlays `network.confinementMode`, `network.policyEnforcementPoint` (inheriting any class-level `tls`/`auth` defaults omitted on the `Sandbox`), `network.caTrust`, `network.ingressPorts`, and `network.parameters`.
   - Never needs to `GET` the `Sandbox` CR or carry `agents.x-k8s.io` RBAC, while drivers that prefer watching `Sandbox` directly can still follow `ResourceClaim.metadata.ownerReferences`.
   - External dynamic/sensitive references (`Secret`, `ConfigMap`, `ClusterTrustBundle`) remain references inside `network` so private keys never enter `ResourceClaim`, large CA bundles never exceed DRA's 10 KiB raw-parameter limit, and live certificate rotation continues to work across immutable `ResourceClaims`.

#### Driver-Configured Pod Adapter Modes & Multi-Language Proxy Environment Variables

Because how a Pod network namespace attaches to the dataplane is driver-specific (for example, OVS/OVN flows in OVN-Kubernetes, nftables/iptables or eBPF redirection in Calico, eBPF interception in Cilium, OVS rules in Antrea, or `socketat` loopback / `tun2connect` in `dra-agents-net`), `adapterMode` and `proxy` live in the `dra-agents-net` `DeviceClass` `DriverConfig` rather than in `Sandbox.spec.network`.

In `dra-agents-net`, `adapterMode` offers three strictly Pod-scoped options:

- **`ExplicitProxy` (default in `dra.agents.net` `DeviceClass`):** Requires zero sidecar container and zero mutating webhook. Skips TUN creation and binds `127.0.0.1:<port>` (parametrizable via `DriverConfig.proxy.port`, defaulting to fixed `15001` so clients have a predictable convention without ephemeral-port churn) directly inside the Pod's loopback namespace via `socketat`, working even in loopback-only `PodNetworkIsolated` Pods. Both HTTPS (`CONNECT`) and plain HTTP absolute-form `HTTP_PROXY` requests are tunneled over PEP `CONNECT`. Because standard HTTP clients do not accept `HTTP_PROXY=unix://...`, `NRI CreateContainer` mounts `/run/agents.net/egress.sock` and injects the complete matrix of language-specific proxy env vars (non-clobbering, appending safely to `JAVA_TOOL_OPTIONS`):
  - `AGENTS_NET_EGRESS_SOCKET=/run/agents.net/egress.sock`, `AGENTS_NET_PROXY_URL=http://127.0.0.1:<port>`
  - Uppercase & lowercase: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy` (`localhost,127.0.0.1,::1` + configured `proxy.noProxy`)
  - Node.js 22+ & npm: `NODE_USE_ENV_PROXY=1`, `npm_config_proxy`, `npm_config_https_proxy`
  - gRPC: `GRPC_PROXY_EXP`
  - JVM: `JAVA_TOOL_OPTIONS` (`-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=<port> -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=<port> -Dhttp.nonProxyHosts=localhost|127.0.0.1|...`)
- **`TunSidecar`:** Uses one distroless native sidecar initContainer (`agents-net-tun2connect`, `restartPolicy: Always`) per Pod, provided by the driver's own mutating admission webhook or explicitly declared in `SandboxTemplate.spec.podTemplate` — never injected by the `agent-sandbox` controller. The sidecar declares `NET_ADMIN` + `SETPCAP` solely to create `tun0` once and drop both capabilities before entering its packet loop. All workload containers stay at zero capabilities (`drop: ["ALL"]`) and receive zero `/dev/net/tun` or UDS mounts.
- **`TunVM`:** For hypervisor/microVM runtimes (Kata, gVisor, Firecracker) that attach one `tun2connect` per microVM over vsock or Unix socket.

#### Declarative Pod CA Certificates (`agents.net` + Language Trust Env Vars)

When a Policy Enforcement Point performs TLS inspection or uses private internal CAs, `spec.network.caTrust` (layered on top of any `DeviceClass` defaults) declaratively defines Pod CA certificates using standard Kubernetes, `cert-manager`, `trust-manager`, and Gateway API conventions (`SandboxCASource`: `ConfigMap`, `Secret`, KEP-3257 `ClusterTrustBundle`, or `HostPath`, with `ca.crt` as the default key):

- **Safe `Secret` support (`cert-manager` compatible):** Because `cert-manager` writes `ca.crt` alongside `tls.crt`/`tls.key` inside `kubernetes.io/tls` Secrets (and `trust-manager` can target Secrets), `SandboxCASource` accepts `Secret` references scoped strictly to the Sandbox's namespace. `dra-agents-net` parses PEM blocks and extracts **only valid X.509 `CERTIFICATE` blocks**, ensuring private keys are never written to `/var/run/agent-ca.pem` or mounted into the Pod. The same `SandboxCASource` list is reused on `policyEnforcementPoint.tls.caCertificateRefs` (matching Gateway API `BackendTLSPolicy`).
- **`AppendSystemRoots` (default) vs `Replace`:** Because `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, and `DENO_CERT` replace the runtime's trust store while `NODE_EXTRA_CA_CERTS` appends, `dra-agents-net` writes two PEM files per Pod and mounts them read-only into every workload container:
  - `/var/run/agent-ca.pem` (standard system roots + custom CAs in `AppendSystemRoots` mode, or custom-only in `Replace` mode — matching `agents.net` Section 2.3.B)
  - `/var/run/agent-extra-ca.pem` (custom CAs only, targeted by `NODE_EXTRA_CA_CERTS`)
- When `mode: InjectEnv` (default when `caTrust` is set), `NRI CreateContainer` injects: `AGENT_CA_CERT`, `AGENTS_NET_CA_BUNDLE`, `AGENTS_NET_EXTRA_CA_BUNDLE`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `NPM_CONFIG_CAFILE`, `DENO_CERT`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE`, and `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`.
- *(Future enhancement / TODO):* Generate a PKCS#12 truststore from the merged PEM bundle and append `-Djavax.net.ssl.trustStore` / `-Djavax.net.ssl.trustStoreType=PKCS12` to `JAVA_TOOL_OPTIONS` for JVM runtimes.

#### Policy Enforcement Point Authentication Modes

`dra-agents-net` terminates the per-Pod channel outside the untrusted workload container, allowing all four Kubernetes-native authentication modes to operate without exposing private keys or tokens to agent code (`automountServiceAccountToken: false` remains enforced):

| Mode | Mechanism | Credential Location | Best Fit |
| :--- | :--- | :--- | :--- |
| **`MTLS`** | Hot-reloaded PEM client cert/key (`certDir` or `Secret`) + CA/SPIFFE server verification + attested `Agents-Net-*` headers. | Node host dir or K8s `Secret` (never in Pod). | Works on any K8s cluster; enables shared node-level H2 multiplexing and instant WarmPool claim transitions. |
| **`SPIFFE` (`Node`)** | Official SPIFFE Workload API (`go-spiffe/v2`) X.509-SVID + auto-rotating Trust Bundle + strict server SPIFFE ID/TrustDomain authorizer + attested `Agents-Net-*` headers. | Local SPIRE Agent UDS (never in Pod). | Clusters with SPIRE seeking shared node-level H2 multiplexing with zero static secrets. |
| **`SPIFFE` (`DelegatedPod`)** | Streaming SPIRE Delegated Identity v1 API (`SubscribeToX509SVIDs` with selector `k8s:pod-uid:<uid>` + `SubscribeToX509Bundles`). | Fetched in memory by `dra-agents-net` (never in Pod). | Strongest cryptographic per-Pod workload identity with SPIRE; zero header trust. |
| **`PodCertificate` (KEP-4317)** | Driver webhook or `SandboxTemplate` mounts a `podCertificate` projected volume (`credential-bundle.pem`, PKCS#8 + cert chain) read-only **only** on the trusted sidecar (`agents-net-tun2connect`). `dra-agents-net` reads and hot-reloads `<kubeletRoot>/pods/<uid>/volumes/kubernetes.io~projected/<volName>/credential-bundle.pem`. | Kubelet projected volume isolated from workload containers. | Kubernetes 1.34+ clusters with a native KEP-4317 signer (cert-manager, GKE Workload Identity, SPIRE signer). |
| **`ServiceAccountToken` (`Node`)** | `dra-agents-net` reads its own audience-bound projected SA token and sends `Proxy-Authorization: Bearer <jwt>` + attested `Agents-Net-*` headers over TLS. | DaemonSet projected volume (never in Pod). | PEPs using Kubernetes `TokenReview` with `authentication.kubernetes.io/node-name` verification (such as `gke-labs/service-portals`); zero PKI required. |
| **`ServiceAccountToken` (`Pod`)** | Driver webhook or `SandboxTemplate` mounts an audience-bound `serviceAccountToken` projected volume read-only **only** on the trusted sidecar (`agents-net-tun2connect`). `dra-agents-net` reads and hot-reloads `<kubeletRoot>/pods/<uid>/volumes/kubernetes.io~projected/<volName>/token` and sends `Proxy-Authorization: Bearer <jwt>`. | Kubelet projected volume isolated from workload containers. | External or out-of-cluster PEPs verifying per-Pod tokens via cluster OIDC JWKS without API server access. |

**Security invariant for Pod-projected credentials:** Isolating `PodCertificate` and Pod-mode `ServiceAccountToken` projected volumes on a trusted sidecar is enforced by the network driver (its webhook/validator and `DeviceClass` configuration), never by injecting sidecars from the core `agent-sandbox` controller.

#### Standardized `agents.net` PEP Wire & Attested Metadata

- **TCP egress:** Standard `CONNECT host:port` negotiated automatically from the PEP URL scheme and TLS ALPN: over `https://`, `dra-agents-net` advertises ALPN `["h2", "http/1.1"]`, using multiplexed HTTP/2 over persistent TLS/mTLS connections when the PEP negotiates `h2` and automatically falling back to HTTP/1.1 `CONNECT` when the PEP speaks HTTP/1.1 only; over `http://` or `unix://`, it uses HTTP/1.1 `CONNECT`.
- **UDP egress:** Standard RFC 9298 `connect-udp` (`GET /.well-known/masque/udp/{host}/{port}/`, `Upgrade: connect-udp`, `Capsule-Protocol: ?1`, RFC 9297/9298 `DATAGRAM` capsules).
- **Denials and diagnostics:** PEP HTTP status codes (`403`, `407`, `502`), `agents.net` `Boundary-Reason`, and RFC 9209 `Proxy-Status` headers propagate transparently back to the sandbox. Unreachable PEPs or auth failures fail closed (`503` / `502`).
- **Attested workload metadata:** `dra-agents-net` attaches sanitized, unforgeable headers from kubelet/DRA/NRI/Pod watch:
  - `Agents-Net-Sandbox-Namespace`, `Agents-Net-Sandbox-Name`
  - `Agents-Net-Pod-Name`, `Agents-Net-Pod-Uid`, `Agents-Net-Service-Account`, `Agents-Net-Node-Name`
  - `Agents-Net-Claim-Uid`, `Agents-Net-Claim-Name` (updated live on `SandboxWarmPool` adoption)
  - `Agents-Net-Param-<name>` (sanitized custom key-value parameters from `spec.network.parameters` / DRA `Opaque` config)

#### Explicit Host-Side Ingress & `sandbox-router` Integration

Isolated sandboxes (`PodNetworkIsolated` with no Pod IP, or `NetworkPolicyDenyAll` with empty ingress rules) cannot receive direct Pod-IP traffic. When `spec.network.ingressPorts` declares allowed TCP ports, `dra-agents-net` exposes a minimal node-local HTTP/1.1 `CONNECT <podUID>:<port>` ingress bridge (default `:15080`, optional TLS/mTLS via `--ingress-tls-cert`, `--ingress-tls-key`, and `--ingress-client-ca`; UDP ingress forwarding is driver-dependent and not handled by the HTTP/1.1 `CONNECT` bridge):

- **Strict port allowlist:** The bridge looks up `podUID` in the node's live store, rejects unknown Pods with `404 Not Found` (`Boundary-Reason: unknown-sandbox`), and rejects undeclared ports with `403 Forbidden` (`Boundary-Reason: ingress-port-denied`).
- **Dual delivery without Pod IPs:** If the Pod adapter created `/run/agents.net/ingress.sock` (`TunSidecar`/`TunVM`), the bridge dials the Unix socket; otherwise (`ExplicitProxy`), it dials `127.0.0.1:<port>` inside the Pod's network namespace via `socketat.DialAtPath` (goroutine-safe `setns` with synchronous IP-literal `connect(2)`).
- **Immediate revocation:** `StopPodSandbox`, `RemovePodSandbox`, `UnprepareResourceClaims`, and orphan `Synchronize` immediately revoke and close active ingress tunnels for the Pod.
- **`sandbox-router` opt-in integration:** Setting `--agents-net-ingress-port=15080` (with `--cache-enabled=true` and optional `--agents-net-ingress-{ca,cert,key}-file`) enables `sandbox-router` to watch scheduled sandbox Pods with `spec.nodeName!=` (admitting Ready zero-PodIP `agents.net` Pods carrying `HostIP` and `PodUID`), isolate `http.Transport` and gRPC (`h2c`) connection pools per `<podUID>.agents-net.local:<port>`, and tunnel HTTP, WebSocket, and gRPC ingress over `CONNECT <podUID>:<port>` to `<HostIP>:15080`. Bridge `403`/`404` rejections surface directly to the caller without retrying or evicting the Pod cache.

#### API Changes

Zero new CRDs are introduced. One optional `network` field is added to `SandboxBlueprint` in `api/v1beta1`, making it available on both `Sandbox` and `SandboxTemplate`. Every field is portable and driver-agnostic; `policyEnforcementPoint` is required whenever `spec.network` is configured, and driver-specific implementation settings (such as `adapterMode` or `ExplicitProxy` port/`noProxy`) belong in the referenced `DeviceClass`:

```yaml
apiVersion: agents.x-k8s.io/v1beta1
kind: Sandbox
metadata:
  name: coding-agent
  namespace: agents
spec:
  network:
    driverName: dra.agents.net                   # optional; defaults to dra.agents.net (or any KND driver, e.g. dra.cni.example)
    deviceClassName: dra.agents.net              # optional; defaults to driverName
    confinementMode: PodNetworkIsolated          # PodNetworkIsolated | NetworkPolicyDenyAll
    policyEnforcementPoint:                      # required (URL scheme + TLS ALPN negotiate HTTP/2 vs HTTP/1.1)
      url: https://egress-portal.sandbox-system.svc:8443
      tls:
        serverName: egress-portal.sandbox-system.svc
        caCertificateRefs:
          - type: ConfigMap                      # ConfigMap | Secret | ClusterTrustBundle | HostPath
            configMapRef:
              name: portal-ca
              key: ca.crt
        trustDomain: cluster.local
        acceptedSPIFFEIDs:
          - spiffe://cluster.local/ns/sandbox-system/sa/portal
      auth:                                      # discriminated union (exactly one branch)
        type: SPIFFE                             # MTLS | SPIFFE | PodCertificate | ServiceAccountToken
        spiffe:
          mode: DelegatedPod                     # Node | DelegatedPod
    caTrust:
      mode: InjectEnv                            # None | MountOnly | InjectEnv
      bundleMode: AppendSystemRoots              # AppendSystemRoots | Replace
      sources:
        - type: Secret                           # ConfigMap | Secret | ClusterTrustBundle | HostPath
          secretRef:
            name: corp-proxy-ca                  # cert-manager kubernetes.io/tls Secret
            key: ca.crt
    ingressPorts:
      - port: 8080
        protocol: TCP
    parameters:                                  # custom key-value metadata -> DRA Opaque config
      - name: tenant
        value: team-a
  podTemplate:
    spec:
      containers:
        - name: agent
          image: example.com/agent:v1
```

Validation rules (CEL `XValidation` and OpenAPI schema):
- `Sandbox`: make `spec.network` immutable after creation (matching `volumeClaimTemplates`), and forbid `spec.service: true` under `PodNetworkIsolated` or `spec.podTemplate.spec.hostNetwork: true` when `spec.network` is configured.
- `SandboxTemplate`: forbid setting `spec.networkPolicy` or `spec.networkPolicyManagement: Unmanaged`, `spec.service: true` under `PodNetworkIsolated`, or `spec.podTemplate.spec.hostNetwork: true` when `spec.network` is configured.
- `SandboxPEPAuth`, `SandboxCASource`, `SandboxMTLSAuth`, and `SandboxClusterTrustBundleRef`: enforce strict discriminated unions and mutually exclusive reference rules via CEL.
- `SandboxNetworkSpec`: validate `driverName` (<= 63 chars) and `deviceClassName` as lowercase DNS-1123 subdomains, require `policyEnforcementPoint.url` with an `https://`, `http://`, or `unix://` scheme, and require absolute paths for host filesystem fields.

#### Implementation Guidance

The implementation is structured into seven reviewable commits (starting with this KEP) so each boundary can be audited and maintained independently:

1. **KEP (`docs/keps/NNNN-dra-agents-net/README.md`):**
   - Documents the architecture, KND Model alignment, DRA `OpaqueDeviceConfiguration` layering (`DeviceClass` driver config + `ResourceClaim` `SandboxNetworkConfiguration`), driver-agnostic controller contract, and verification plan.
2. **Core API (`api/v1beta1/sandbox_network_types.go`, `api/v1beta1/sandbox_types.go`, `extensions/api/v1beta1/sandboxtemplate_types.go`):**
   - Add `SandboxNetworkSpec` (with `driverName`, optional `deviceClassName`, `confinementMode`, required `policyEnforcementPoint`, `caTrust`, `ingressPorts`, `parameters`) and `SandboxNetworkConfiguration` (`TypeMeta` + `Network`) to `api/v1beta1`.
   - Register nested apply-configuration externals in `dev/tools/client-gen-go.sh` and keep all API fields KAL-compliant (enums over booleans, slices over maps, explicit `+optional`/`+required`).
3. **Generated Artifacts (`k8s/`, `helm/`, `olm/`, `clients/k8s/`, `docs/api.md`):**
   - Regenerate CRDs, deepcopy, typed apply configurations, Helm chart (`0.1.5 -> 0.1.6`), OLM manifests, and API docs via `make fix-go-generate`, `make fix-api-docs`, and `make bump-chart-version`.
4. **Driver-Agnostic Controllers (`controllers/sandbox_network.go`, `controllers/sandbox_controller.go`, `extensions/controllers/`):**
   - When `sandbox.Spec.Network != nil` and `OperatingMode == Running`, reconcile a controller-owned standard Kubernetes `resource.k8s.io/v1` `ResourceClaim` targeting `deviceClassName` (falling back to `driverName`) and stamping `Opaque.Driver = driverName` with the marshaled `SandboxNetworkConfiguration` JSON (validating `<= 10 KiB`). Delete the claim on suspension or expiry to release the node DRA capacity share.
   - Keep `ApplySandboxNetworkPodSpec` strictly driver-agnostic: default `enableServiceLinks: false` and `automountServiceAccountToken: false`, and attach `pod.Spec.ResourceClaims` (plus `containers` and `initContainers` `resources.claims` so CDI-based drivers also work). Never inject sidecars, synthetic DNS resolvers, or driver-specific projected volumes.
   - Allow `PodNetworkIsolated` Sandboxes to become `Ready=True` and be adopted from `SandboxWarmPool` based on `NodeName` without requiring `PodIPs`.
   - Update `compareSandboxBlueprint` in `extensions/controllers/sandboxwarmpool_controller.go` to track `Network` drift.
   - Under `NetworkPolicyDenyAll`, reconcile a strict empty-ingress/empty-egress deny-all `NetworkPolicy` — one shared policy per `SandboxTemplate` (owned by `SandboxTemplateReconciler`) and one owned policy per standalone `Sandbox` created directly without a template (created before Pod creation and retained until Pod termination). Under `PodNetworkIsolated`, skip/clean owned `NetworkPolicy`.
5. **Standalone Node Plumbing Driver (`packages/dra-agents-net/`):**
   - Independent Go module (`module sigs.k8s.io/agent-sandbox/packages/dra-agents-net`) with **zero** imports or `replace` directives pointing at `sigs.k8s.io/agent-sandbox`, plus a self-contained `README.md`, `Dockerfile`, and `deploy/{rbac,deviceclass,daemonset}.yaml` manifests so it can move to its own repository later with a one-line module rename.
   - `pkg/apis`: standalone DRA `OpaqueDeviceConfiguration` wire schema (`DriverConfigAPIVersion = "dra.agents.net/v1alpha1"`, `DriverConfigKind = "DriverConfig"`, `SandboxNetworkConfigKind = "SandboxNetworkConfiguration"`) and `agents.net` constants (`DriverName = "dra.agents.net"`, `ClaimUIDLabel = "agents.x-k8s.io/claim-uid"`, `ClaimNameAnnotation = "agents.x-k8s.io/claim-name"`).
   - `pkg/params`: layered DRA `OpaqueDeviceConfiguration` decoder dispatching by `TypeMeta` (`DriverConfig` from `DeviceClass` / standalone Pod claims + `SandboxNetworkConfiguration` from `agent-sandbox` `ResourceClaims`), merging class defaults with claim overrides and unifying `parameters` into attested `custom` metadata.
   - `pkg/socketat`: goroutine-safe cross-netns execution, `ListenAt` / `ListenAtPath` (egress loopback listener), and `DialAt` / `DialAtPath` (ingress loopback dialing) following `github.com/aojea/socketat`.
   - `pkg/catrust`: shared CA bundle resolver (`ConfigMap`, `Secret`, `ClusterTrustBundle`, `HostPath`) extracting strictly `CERTIFICATE` PEM blocks for both Pod `caTrust` (`AppendSystemRoots` / `Replace`) and `policyEnforcementPoint.tls.caCertificateRefs`, plus the `agents.net` and multi-language CA env map.
   - `pkg/proxyenv`: full language magic proxy env var generator and non-clobbering container env merge (including `JAVA_TOOL_OPTIONS` append).
   - `pkg/auth`: all four native auth modes (`mtls.go` with live `cert-manager` Secret reload via `GetClientCertificate`, `spiffe.go` using `github.com/spiffe/go-spiffe/v2` + streaming SPIRE Delegated Identity v1 client, `podcert.go` atomic KEP-4317 PEM bundle reader, `satoken.go` hot-reloading Node/Pod JWT reader).
   - `pkg/tunnel`: per-Pod UDS + attached `socketat` loopback listener manager, strict RFC 9110/9112/9209/9298 parser (including plain HTTP `HTTP_PROXY` tunneling over PEP `CONNECT`), stdlib multiplexed HTTP/2 + HTTP/1.1 PEP dialer, immediate revocation (canceling in-flight dials), and structured `agents.net` JSONL audit logging.
   - `pkg/ingress`: node-local HTTP/1.1 `CONNECT <podUID>:<port>` host ingress bridge with optional TLS/mTLS, `spec.network.ingressPorts` enforcement (`403`/`404` + `Boundary-Reason`), `ingress.sock` or `socketat.DialAtPath` delivery, and per-Pod `Revoke`.
   - `pkg/store`: schema-versioned BoltDB tmpfs checkpoint store.
   - `pkg/driver`: DraNet-style `resource.k8s.io/v1` `kubeletplugin.DRAPlugin` (single per-node `DRAConsumableCapacity` device `agents-net`, `MergePatch` `status.devices` with `ShareID` via `resourceclaims/driver`) + supervised NRI plugin (`FailurePolicy`, NRI-before-DRA startup, exponential backoff reconnect, claim gating, 3-step graceful `Stop` drain, `Synchronize` `AgentsNetPlumbingMissing` auditing) + node-scoped `core/v1` Pod informer for `ServiceAccount` and warm-pool claim sync.
   - `pkg/metrics`: bounded-cardinality Prometheus counters/gauges/histograms under subsystem `dra_agents_net` (DRA/NRI request counters & timeout-aligned latency histograms, published device gauges, NRI disconnect/reconnect counters, `pods_missing_plumbing_total`, plus tunnel & ingress metrics), paired with Kubernetes apiserver-style `/healthz`, `/healthz/dra`, and `/healthz/nri`.
   - **Unit + in-process NRI restart + unprivileged Linux `userns` multi-netns integration tests (`internal/testutils/userns_linux.go`, `pkg/driver/lifecycle_test.go`, `pkg/driver/integration_linux_test.go`):** modeled on `dranet`'s `userns` harness (`CLONE_NEWUSER|CLONE_NEWNET|CLONE_NEWNS` + fresh `/run` tmpfs) and in-process `containerd/nri/pkg/adaptation` restart tests, exercising NRI-before-DRA startup, backoff/reset, claim gating, graceful drain, `AgentsNetPlumbingMissing` netlink/mount auditing, real dual-stack `veth` route flushing, pure-netlink `tc clsact` primary + secondary NIC ingress/egress drop blocking, `PodNetworkIsolated` netns rejection, full cross-netns `ExplicitProxy` HTTP/2 multiplexed `CONNECT` + RFC 9298 `connect-udp` + `StopPodSandbox` revocation, and mTLS host ingress via `socketat.DialAtPath` inside `go test -race ./...` without root privileges.
6. **`sandbox-router` Ingress Integration (`sandbox-router/`):**
   - Add opt-in `--agents-net-ingress-port` (default `0`, disabled) and optional `--agents-net-ingress-{ca,cert,key}-file` flags.
   - Admit Ready zero-PodIP `agents.net` Pods into `cache.Cache` when ingress bridge mode is enabled and isolate HTTP/gRPC connection pools per Pod UID via `<podUID>.agents-net.local:<port>`.
7. **End-to-End Verification (`test/e2e/dra_agents_net_test.go`, `test/e2e/images/dra-agents-net-test-upstream/`):**
   - `kind` E2E suite backed by a minimal stdlib Go PEP/destination fixture covering `DRAConsumableCapacity` shared device allocation (`shareID`, `consumedCapacity`, matching `status.devices`), default & custom `DeviceClass`-configured `ExplicitProxy` ports/`noProxy`, `Secret`/`ConfigMap`/`ClusterTrustBundle` `caTrust` (`AppendSystemRoots`, `Replace`, `MountOnly`, zero private-key leak), direct egress route-flush, CNI `NetworkPolicy` peer-Pod TCP/UDP isolation, standalone zero-`NetworkPolicy` `tc clsact` NIC blocking + `DeviceClass` `nicBlockMode: Disabled` opt-out, `PodNetworkIsolated` fail-closed rejection, DaemonSet restart recovery, HTTPS + plain HTTP + direct UDS + `403` `Boundary-Reason`/`Proxy-Status`, `MTLS` and `ServiceAccountToken` auth, suspend/resume capacity release, `SandboxWarmPool` -> `SandboxClaim` identity sync, `sandbox-router` -> `dra-agents-net` host ingress (allow/deny/revoke), multiplexed `HTTP/2` `CONNECT` + RFC 9298 `connect-udp`, and live `/healthz` + `/metrics` verification.

## Scalability

- **Zero extra CRDs and zero per-Pod `Sandbox` `GET`s:** Because `Sandbox.spec.network` is embedded as `SandboxNetworkConfiguration` inside the DRA `ResourceClaim` delivered by kubelet, `dra-agents-net` (or any other KND driver) requires no `Sandbox` CRD informers or `agents.x-k8s.io` RBAC. Its single watch is a node-scoped `core/v1` Pod informer (`fieldSelector: spec.nodeName=<node>`), scaling linearly with local Pod count only.
- **Constant-size `ResourceSlice` per node (1 device via `DRAConsumableCapacity`):** Publishing a single shared `agents-net` device (`allowMultipleAllocations: true`) with consumable `sandboxes` capacity sized to `node.Status.Allocatable.Pods()` produces **one** minimal `ResourceSlice` per node regardless of pod density (even on 500+ pod nodes), using `DRAConsumableCapacity` enabled by default since Kubernetes 1.36.
- **Zero CDI disk I/O on the Pod start path:** NRI `CreateContainer` injects mounts, CA bundles, and `/dev/net/tun` in memory, avoiding per-Pod CDI JSON file creation and fsync overhead at high Pod churn.
- **Multiplexed HTTP/2 PEP connections:** `MTLS`, `SPIFFE (Node)`, and `ServiceAccountToken` modes multiplex tunnels over persistent HTTP/2 TLS connections, keeping TLS handshake overhead negligible even under bursty agent tool calls.
- **WarmPool compatibility:** Pre-warmed Sandboxes remain ready with zero cold start; on `SandboxClaim` adoption, the node-scoped Pod informer detects `agents.x-k8s.io/claim-uid` and `agents.x-k8s.io/claim-name` updates, refreshes attested headers, and revokes pre-claim tunnels immediately.

## Alternatives

### Alternative 1: Standalone `SandboxNetworkPolicy` and `SandboxNetworkBinding` CRDs with embedded CEL engine

An earlier design proposed shipping a `network.agents.x-k8s.io/v1alpha1` API group with a node-local CEL policy engine and credential-injection proxy directly inside `agent-sandbox`. We rejected this because:
- It duplicates policy, L7 inspection, and secret-injection responsibilities already solved by specialized Policy Enforcement Points and networking stacks (`gke-labs/service-portals`, Envoy/Agentgateway, OVN-Kubernetes, Calico, Cilium, corporate egress gateways).
- It expands CRD surface area, controller RBAC, and API-server watch load (`SandboxNetworkBinding` per Sandbox).
- Decoupling the plumbing from policy/secrets promotes **`agents.net`** as a clean interoperability boundary that any PEP can implement.

### Alternative 2: Exposing `HTTP_PROXY=unix:///run/agents.net/egress.sock` in `ExplicitProxy` mode

Almost no mainstream HTTP client (Go `net/http`, Python `requests`/`urllib3`/`httpx`, Node `undici`, Rust `reqwest`, Java, `curl`, `git`, `pip`, `npm`) accepts `unix://` proxy URLs. Using `socketat.ListenAtPath` to bind `127.0.0.1:<port>` directly inside the Pod's loopback namespace gives unmodified HTTP libraries standard `http://127.0.0.1:<port>` proxy access even inside a loopback-only `PodNetworkIsolated` Pod with zero sidecar container.

### Alternative 3: Hardcoding a single PEP authentication mechanism

Choosing only mTLS or only ServiceAccount JWTs breaks real clusters: SPIRE environments expect SPIFFE X.509-SVIDs, Kubernetes 1.34+ clusters are adopting KEP-4317 `PodCertificateRequest`, `gke-labs/service-portals` uses node-attested `ServiceAccountToken` (`TokenReview`), and corporate proxies often use standard rotated mTLS certs. Supporting all four native Kubernetes auth modes behind a compact discriminated union covers every deployment environment cleanly.

### Alternative 4: Publishing per-pod exclusive slot devices (`slot-0`..`slot-<N-1>`)

An earlier revision published `N` discrete exclusive slot devices (`slot-0`..`slot-<N-1>`) per node to avoid relying on `DRAConsumableCapacity`. Because `DRAConsumableCapacity` reached Beta and is enabled by default starting in Kubernetes 1.36, publishing a single shared `agents-net` device (`allowMultipleAllocations: true`) with consumable `capacity.sandboxes` and `requestPolicy: {default: "1", validValues: ["1"]}` keeps each node's `ResourceSlice` constant-size (1 device instead of `N`, avoiding multi-slice chunking on >128-pod nodes) while requiring zero changes to `Sandbox` manifests, `DeviceClass`, or `ResourceClaim` specs.

### Alternative 5: Embedding the entire `Sandbox` CR or injecting driver sidecars in the `agent-sandbox` controller

We rejected both embedding the entire `Sandbox` CR in `Opaque.Parameters` and injecting `tun2connect` sidecars in `controllers/sandbox_network.go`:
- Kubernetes DRA enforces a strict **10 KiB** limit on `OpaqueDeviceConfiguration.Parameters`. Including `spec.podTemplate`, annotations (`kubectl.kubernetes.io/last-applied-configuration`), `managedFields`, and `status` risks breaking `ResourceClaim` creation and duplicates `PodSpec` that kubelet/NRI already supplies to the node driver. Embedding only the `Sandbox.spec.network` stanza inside `SandboxNetworkConfiguration` avoids any `Sandbox` `GET` while staying well under 10 KiB.
- Injecting `tun2connect` initContainers, `NET_ADMIN`/`SETPCAP`, and synthetic DNS (`100.127.255.253`) inside the core `agent-sandbox` controller leaks `dra-agents-net`-specific mechanics into `agent-sandbox` and breaks alternative KND drivers (such as OVN-Kubernetes, Calico, Cilium, or Antrea) that intercept traffic in their own OVS/OVN, nftables/iptables, or eBPF dataplanes without a TUN sidecar. Keeping sidecar injection and `adapterMode` strictly inside the driver and its `DeviceClass` keeps `agent-sandbox` vendor-neutral.

## References

- Antonio Ojea, *"The Kubernetes Network Driver Model: A Composable Architecture for High-Performance Networking,"* 2025 IEEE 50th Conference on Local Computer Networks (LCN), DOI: [10.1109/LCN65610.2025.11146291](https://doi.org/10.1109/LCN65610.2025.11146291) (preprint: [arXiv:2506.23628](https://arxiv.org/abs/2506.23628)).
- [DRANET (`kubernetes-sigs/dranet`)](https://github.com/kubernetes-sigs/dranet) — reference Kubernetes Network Driver implementation (`dra.net`).
- [`kube-network-policies` (`kubernetes-sigs/kube-network-policies`)](https://github.com/kubernetes-sigs/kube-network-policies) — CNI-agnostic Kubernetes reference implementation for `NetworkPolicy`, demonstrating how Kubernetes reference drivers solve the CNI dependency problem while letting existing CNIs assume enforcement natively.
- [`agents.net`](https://github.com/aojea/agents.net) — sandbox network boundary specification.
