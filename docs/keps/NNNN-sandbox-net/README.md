# KEP-NNNN: `sandbox-net` — Standardized `agents.net` Traffic Plumbing via DRA and NRI

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
    - [Story 2: Workload owner customizes upstream, Pod CA trust, or private metadata per <code>SandboxTemplate</code>](#story-2-workload-owner-customizes-upstream-pod-ca-trust-or-private-metadata-per-sandboxtemplate)
    - [Story 3: Standalone Kubernetes <code>Pod</code> user adopts <code>agents.net</code> plumbing directly](#story-3-standalone-kubernetes-pod-user-adopts-agentsnet-plumbing-directly)
    - [Story 4: Operator adopts isolated plumbing on an existing cluster without KEP-6313](#story-4-operator-adopts-isolated-plumbing-on-an-existing-cluster-without-kep-6313)
  - [High-Level Design](#high-level-design)
    - [Why DRA + NRI (Following DraNet)](#why-dra--nri-following-dranet)
    - [Pod Adapter Modes &amp; Multi-Language Proxy Environment Variables](#pod-adapter-modes--multi-language-proxy-environment-variables)
    - [Declarative Pod CA Certificates (<code>agents.net</code> + Language Trust Env Vars)](#declarative-pod-ca-certificates-agentsnet--language-trust-env-vars)
    - [Upstream Authentication Modes](#upstream-authentication-modes)
    - [Standardized <code>agents.net</code> Upstream Wire &amp; Attested Metadata](#standardized-agentsnet-upstream-wire--attested-metadata)
    - [API Changes](#api-changes)
    - [Implementation Guidance](#implementation-guidance)
- [Scalability](#scalability)
- [Alternatives](#alternatives)
  - [Alternative 1: Standalone <code>SandboxNetworkPolicy</code> and <code>SandboxNetworkBinding</code> CRDs with embedded CEL engine](#alternative-1-standalone-sandboxnetworkpolicy-and-sandboxnetworkbinding-crds-with-embedded-cel-engine)
  - [Alternative 2: Exposing <code>HTTP_PROXY=unix:///run/agents.net/egress.sock</code> in <code>ExplicitProxy</code> mode](#alternative-2-exposing-http_proxyunixrunagentsnetegresssock-in-explicitproxy-mode)
  - [Alternative 3: Hardcoding a single upstream authentication mechanism](#alternative-3-hardcoding-a-single-upstream-authentication-mechanism)
  - [Alternative 4: Requiring <code>DRAConsumableCapacity</code> (<code>allowMultipleAllocations: true</code>)](#alternative-4-requiring-draconsumablecapacity-allowmultipleallocations-true)
<!-- /toc -->

## Summary

This KEP defines `sandbox-net`, a minimal, node-local traffic plumbing layer for `agent-sandbox` (alongside `sandbox-router` and `sandboxd`) that isolates sandbox Pods from direct network egress and forwards all TCP, UDP, and DNS traffic over the **`agents.net`** wire protocol (`HTTP CONNECT`, RFC 9298 `connect-udp`, `Boundary-Reason`, RFC 9209 `Proxy-Status`) to an authenticated **upstream** proxy or portal.

Rather than introducing standalone network policy or credential-broker CRDs into `agent-sandbox`, `sandbox-net` configures traffic plumbing directly on `Sandbox` / `SandboxTemplate` (`SandboxBlueprint.network`) and standard Kubernetes `PodSpec` via **Dynamic Resource Allocation (DRA)** and the **Node Resource Interface (NRI)**, following the architecture proven by [DraNet](https://github.com/google/dranet). Policy enforcement (allowlists, CEL, L7 HTTP/MCP inspection, SSRF filtering) and secret/credential injection (such as `gke-labs/service-portals`, Envoy/Agentgateway, or corporate egress gateways) remain decoupled in the upstream. To let the upstream enforce per-sandbox policies and inject per-sandbox credentials without exposing secrets to untrusted agent code, `sandbox-net` supports all four Kubernetes-native upstream authentication modes (**mTLS**, **SPIFFE**, **KEP-4317 `PodCertificate`**, and **bound `ServiceAccountToken`**), declarative Pod CA trust bundles (`AGENT_CA_CERT` plus language-specific CA env vars), and goroutine-safe `socketat` Pod-loopback listeners with full language proxy env var injection for `ExplicitProxy` mode.

## Motivation

AI coding agents and autonomous workloads running inside `Sandbox` Pods execute untrusted code and need strict network confinement alongside authenticated access to external APIs, MCP servers, and package registries.

Existing approaches force painful trade-offs:

1. **CNI `NetworkPolicy` alone operates at L3/L4 only.** It cannot enforce hostname, HTTP, or MCP rules, cannot inject credentials transparently, and still attaches a cluster-routable interface (`eth0`) and Pod IP to every sandbox.
2. **In-container proxies and environment variables alone are bypassable and leak secrets.** Untrusted processes ignore `HTTP_PROXY`, open raw TCP/UDP sockets, or exfiltrate any credential or ServiceAccount token mounted inside the container.
3. **Baking a bespoke policy engine and secret broker into `agent-sandbox` CRDs fragments the ecosystem.** Cluster operators already deploy diverse egress gateways, portals (`gke-labs/service-portals`), service meshes, and corporate proxies. Duplicating policy schemas and secret-store integrations as new `agent-sandbox` CRDs creates maintenance burden and locks users into a single policy language.

### Goals

- **Promote `agents.net` as a vendor-neutral standard** for sandbox network interception (`CONNECT` + RFC 9298 `connect-udp` over per-Pod Unix domain sockets, `Boundary-Reason`, `AGENT_CA_CERT`) and upstream forwarding (`HTTP/1.1`, `HTTP/2`, or `HTTP/3` MASQUE + RFC 9209 `Proxy-Status` + attested `Agents-Net-*` identity headers).
- **Keep `agent-sandbox` strictly focused on plumbing** with zero new policy or binding CRDs. Expose configuration directly in `SandboxBlueprint.network` (shared by `Sandbox` and `SandboxTemplate`) and standard Kubernetes DRA `DeviceClass` / `ResourceClaim` `OpaqueDeviceConfiguration` (supporting raw `Pod` workloads as well).
- **Reuse simple GA Kubernetes DRA + NRI mechanics (DraNet pattern):** standard GA `resource.k8s.io/v1` per-pod slot devices auto-sized to `node.Status.Allocatable.Pods()` (zero alpha/beta DRA feature gates), slow-path DRA preparation with zero CDI files, and fast-path NRI hooks running synchronously during `RunPodSandbox` before any container starts.
- **Support both KEP-6313 and existing CNI clusters:** default to `PodNetworkIsolated` (loopback-only Pod network namespace with no CNI attachment or Pod IP), and provide backward-compatible `NetworkPolicyDenyAll` (controller-managed deny-all `NetworkPolicy` plus `NRI RunPodSandbox` non-loopback route flush).
- **Support all four native Kubernetes upstream authentication modes** (`MTLS`, `SPIFFE`, `PodCertificate`, and `ServiceAccountToken`) while keeping private keys and tokens completely inaccessible to untrusted workload containers.
- **Follow Kubernetes, `cert-manager`, `trust-manager`, and Gateway API certificate conventions:** support `ConfigMap`, `Secret` (strictly extracting `CERTIFICATE` PEM blocks only), `ClusterTrustBundle`, and `HostPath` uniformly on both `caTrust.sources` and `upstream.tls.caCertificateRefs`, with `AGENT_CA_CERT` + full multi-language CA/proxy env var injection and a parametrizable `socketat`-bound `127.0.0.1:<port>` (default `15001`) loopback listener for `ExplicitProxy`.
- **Preserve `SandboxWarmPool` sub-second adoption** by keeping attested Pod/Sandbox/Claim identity synchronized via a node-scoped `core/v1` Pod informer and revoking pre-claim tunnels on adoption.

### Non-Goals

- Defining a new network policy CRD (`SandboxNetworkPolicy`), binding CRD, or CEL policy evaluator inside `agent-sandbox`.
- Building a secret vault, OAuth broker, or TLS-terminating L7 inspection engine inside `sandbox-net` (those belong in the upstream proxy/portal).
- Creating per-container network interfaces (Linux network interfaces belong strictly to the Pod network namespace: at most one `tun2connect` / `tun0` per Pod or microVM).

## Proposal

### User Stories

#### Story 1: Platform operator standardizes on `agents.net` with an existing egress portal

A platform team runs an egress portal (such as `gke-labs/service-portals`, Envoy/Agentgateway, or a corporate proxy) that enforces egress allowlists and injects API keys. They deploy the `sandbox-net` DaemonSet and configure cluster-wide defaults (upstream URL, TLS trust bundle, Pod CA certs, auth mode) in the `sandbox-net.agents.x-k8s.io` DRA `DeviceClass`. Every `SandboxTemplate` enables `spec.network` and automatically receives loopback-only confinement and authenticated `agents.net` forwarding without introducing new policy CRDs.

#### Story 2: Workload owner customizes upstream, Pod CA trust, or private metadata per `SandboxTemplate`

A team overrides `spec.network.upstream` on its `SandboxTemplate` to target a tenant-specific portal, selects `PodCertificate`, `MTLS`, or `SPIFFE` authentication, declares its inspection CA via `spec.network.caTrust` (`ConfigMap`, `cert-manager` `kubernetes.io/tls` `Secret`, or KEP-3257 `ClusterTrustBundle`), and passes team-specific metadata via `spec.network.parameters` (propagated via DRA `OpaqueDeviceConfiguration` and `Agents-Net-Param-*` headers).

#### Story 3: Standalone Kubernetes `Pod` user adopts `agents.net` plumbing directly

A cluster user running workloads outside the `Sandbox` CRD attaches the `sandbox-net.agents.x-k8s.io` DRA `DeviceClass` via a standard `ResourceClaim` (the exact DraNet UX) and receives identical `agents.net` confinement, CA trust injection, and upstream forwarding.

#### Story 4: Operator adopts isolated plumbing on an existing cluster without KEP-6313

An operator on a Kubernetes cluster whose CNI does not yet support loopback-only `PodNetworkIsolated` sets `confinementMode: NetworkPolicyDenyAll`. The controller reconciles a strict deny-all `NetworkPolicy` (enforced synchronously by the CNI during `RunPodSandbox`), and `sandbox-net`'s `NRI RunPodSandbox` hook flushes `eth0` routes before any container starts so `tun0` owns `0.0.0.0/0` and `::/0` cleanly.

### High-Level Design

```text
+-------------------------------------------------------------------+
| Sandbox Pod (Network Namespace)                                   |
|                                                                   |
|  [Untrusted Agent Container]                                      |
|   - automountServiceAccountToken: false                           |
|   - capabilities.drop: ["ALL"] (zero NET_ADMIN, zero credentials) |
|   - Pod CA bundles mounted at /var/run/agent-ca.pem (+ extra-ca)  |
|     with AGENT_CA_CERT + language CA env vars                     |
|   - TunSidecar: dnsPolicy None -> VirtualDNS 100.127.255.253      |
|   - ExplicitProxy: 127.0.0.1:<port> (via socketat) + proxy envs   |
|             │  standard TCP / UDP / DNS                           |
|             ▼                                                     |
|  [sandbox-net-tun2connect] (TunSidecar: 1 per Pod netns)          |
|   - owns tun0 + VirtualDNS; drops NET_ADMIN/SETPCAP after setup   |
|   - mounts /run/agents.net/egress.sock (injected via NRI)         |
+-------------------------------------------------------------------+
              │  agents.net wire over per-Pod host UDS (or socketat loopback)
              │  HTTP/1.1 CONNECT + RFC 9298 connect-udp
              ▼
+-------------------------------------------------------------------+
| Node Plumbing DaemonSet: sandbox-net (DRA + NRI)                  |
|  - DRA slow path: GA ResourceSlice (slot-0..slot-<maxPods-1>),    |
|    PrepareResourceClaims decodes DeviceClass+Claim Opaque params, |
|    opens per-Pod egress.sock, materializes Pod CA bundles,        |
|    checkpoints to tmpfs BoltDB                                    |
|  - NRI fast path (zero CDI files):                                |
|    * RunPodSandbox: verify loopback-only OR flush eth0 routes;    |
|      for ExplicitProxy, bind 127.0.0.1:<port> via socketat        |
|    * CreateContainer: inject UDS + /dev/net/tun on tun2connect,   |
|      mount Pod CA bundles, inject CA + language proxy env vars    |
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
| Upstream Proxy / Portal (service-portals, Envoy, Corp Proxy...)   |
|  - Authenticates peer & verifies Sandbox/Pod identity             |
|  - Enforces egress policy, L7 inspection, SSRF protection         |
|  - Injects API credentials / secrets                              |
+-------------------------------------------------------------------+
```

#### Why DRA + NRI (Following DraNet)

[DraNet](https://github.com/google/dranet) demonstrates a clean separation of concerns in Kubernetes node networking that avoids CDI file churn and kubelet/runtime coupling:

1. **DRA Slow Path (`PrepareResourceClaims` / `UnprepareResourceClaims`):**
   - Each node advertises lightweight per-pod slot devices (`slot-0`..`slot-<N-1>`) in standard GA `resource.k8s.io/v1` `ResourceSlice`(s), where `N` auto-detects `node.Status.Allocatable.Pods()` (defaulting to `110`, fitting inside one `ResourceSlice` under `ResourceSliceMaxDevices = 128`, and automatically chunking if `N > 128`). Because node pod capacity already bounds concurrent sandboxes on a node, this avoids requiring `DRAConsumableCapacity`, `DRADeviceTaints`, or `DRAExtendedResource` feature gates.
   - If the node daemon becomes unhealthy, it withdraws its `ResourceSlice` entries cleanly (stopping new placements without disrupting running Pods and without requiring `DRADeviceTaints`).
   - `DeviceClass.spec.config[].opaque` carries cluster-wide defaults, while per-Pod `ResourceClaim.spec.devices.config[].opaque` overlays user upstream, CA trust, proxy, auth, and custom/private parameters.
   - `PrepareResourceClaims` decodes the layered parameters, creates `/run/sandbox-net/pods/<podUID>/egress/egress.sock`, resolves upstream auth, materializes any declarative Pod CA bundles, probes socket readiness, checkpoints state to memory-backed BoltDB, and returns **zero CDI devices**.
   - Device readiness is reported on `ResourceClaim.status.devices` via a targeted `MergePatch` on the `status` subresource using least-privilege `resourceclaims/driver` (`associated-node:patch`) RBAC so immutable `status.allocation` is never rewritten.
2. **NRI Fast Path (`RunPodSandbox` / `CreateContainer` / `StopPodSandbox` / `RemovePodSandbox` / `Synchronize`):**
   - `RunPodSandbox` executes synchronously **before any container is created or started**. Under `PodNetworkIsolated`, it verifies via `socketat.DoAtNSPath` + netlink that only loopback exists (rejecting `hostNetwork` or unexpected CNI interfaces). Under `NetworkPolicyDenyAll` (where enforcing CNIs also apply the `NetworkPolicy` during `RunPodSandbox`), it flushes routes on non-loopback interfaces so `tun0` cleanly owns default routes without conflict.
   - Under `ExplicitProxy`, `RunPodSandbox` also binds `127.0.0.1:<port>` inside the Pod's network namespace using the [`aojea/socketat`](https://github.com/aojea/socketat) mechanism (`runtime.LockOSThread()`, opening `/proc/<pid>/task/<tid>/ns/net`, `unix.Setns`, synchronous `net.Listen`, restoring the thread's original namespace) and attaches the resulting `net.Listener` to the Pod's tunnel pipeline. Once created, the listening FD lives in the Pod's loopback namespace while `Accept()` and forwarding run safely on host goroutines with zero namespace leakage.
   - `CreateContainer` injects `/run/agents.net` bind mount, `/dev/net/tun` device node, and `AGENTS_NET_*` env vars in memory via `ContainerAdjustment` **only on the Pod's single `sandbox-net-tun2connect` container** (in `TunSidecar` mode), plus Pod CA mounts and CA/proxy env vars on workload containers without clobbering user-defined environment variables.
   - `StopPodSandbox` immediately revokes both UDS and `socketat` loopback listeners and terminates all active upstream tunnels.
   - `Synchronize` restores live Pods' UDS and `socketat` loopback listeners across DaemonSet restarts and reaps orphans.

#### Pod Adapter Modes & Multi-Language Proxy Environment Variables

Because Linux network interfaces belong to the Pod network namespace (never to individual containers), `adapterMode` offers three strictly Pod-scoped options:

- **`TunSidecar` (default):** Injects one distroless native sidecar initContainer (`sandbox-net-tun2connect`, `restartPolicy: Always`) per Pod. It declares `NET_ADMIN` + `SETPCAP` solely to create `tun0` once and drop both capabilities before entering its packet loop. All workload containers stay at zero capabilities (`drop: ["ALL"]`) and receive zero `/dev/net/tun` or UDS mounts.
- **`TunVM`:** For hypervisor/microVM runtimes (Kata, gVisor, Firecracker) that attach one `tun2connect` per microVM over vsock or Unix socket.
- **`ExplicitProxy`:** Skips TUN creation and binds `127.0.0.1:<port>` (parametrizable, defaulting to fixed `15001` so clients have a predictable convention without ephemeral-port churn) directly inside the Pod's loopback namespace via `socketat`, working even in loopback-only `PodNetworkIsolated` Pods with zero sidecar container. Both HTTPS (`CONNECT`) and plain HTTP absolute-form `HTTP_PROXY` requests are tunneled over upstream `CONNECT`. Because standard HTTP clients do not accept `HTTP_PROXY=unix://...`, `NRI CreateContainer` mounts `/run/agents.net/egress.sock` and injects the complete matrix of language-specific proxy env vars (non-clobbering, appending safely to `JAVA_TOOL_OPTIONS`):
  - `AGENTS_NET_EGRESS_SOCKET=/run/agents.net/egress.sock`, `AGENTS_NET_PROXY_URL=http://127.0.0.1:<port>`
  - Uppercase & lowercase: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `http_proxy`, `https_proxy`, `all_proxy`, `no_proxy` (`localhost,127.0.0.1,::1` + user `noProxy`)
  - Node.js 22+ & npm: `NODE_USE_ENV_PROXY=1`, `npm_config_proxy`, `npm_config_https_proxy`
  - gRPC: `GRPC_PROXY_EXP`
  - JVM: `JAVA_TOOL_OPTIONS` (`-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=<port> -Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=<port> -Dhttp.nonProxyHosts=localhost|127.0.0.1|...`)

#### Declarative Pod CA Certificates (`agents.net` + Language Trust Env Vars)

When an upstream performs TLS inspection or uses private internal CAs, `spec.network.caTrust` (and DRA `DeviceClass` defaults) declaratively defines Pod CA certificates using standard Kubernetes, `cert-manager`, `trust-manager`, and Gateway API conventions (`SandboxCASource`: `ConfigMap`, `Secret`, KEP-3257 `ClusterTrustBundle`, or `HostPath`, with `ca.crt` as the default key):

- **Safe `Secret` support (`cert-manager` compatible):** Because `cert-manager` writes `ca.crt` alongside `tls.crt`/`tls.key` inside `kubernetes.io/tls` Secrets (and `trust-manager` can target Secrets), `SandboxCASource` accepts `Secret` references scoped strictly to the Sandbox's namespace. `sandbox-net` parses PEM blocks and extracts **only valid X.509 `CERTIFICATE` blocks**, ensuring private keys are never written to `/var/run/agent-ca.pem` or mounted into the Pod. The same `SandboxCASource` list is reused on `upstream.tls.caCertificateRefs` (matching Gateway API `BackendTLSPolicy`).

- **`AppendSystemRoots` (default) vs `Replace`:** Because `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `AWS_CA_BUNDLE`, `CARGO_HTTP_CAINFO`, and `DENO_CERT` replace the runtime's trust store while `NODE_EXTRA_CA_CERTS` appends, `sandbox-net` writes two PEM files per Pod and mounts them read-only into every workload container:
  - `/var/run/agent-ca.pem` (standard system roots + custom CAs in `AppendSystemRoots` mode, or custom-only in `Replace` mode — matching `agents.net` Section 2.3.B)
  - `/var/run/agent-extra-ca.pem` (custom CAs only, targeted by `NODE_EXTRA_CA_CERTS`)
- When `mode: InjectEnv` (default when `caTrust` is set), `NRI CreateContainer` injects: `AGENT_CA_CERT`, `AGENTS_NET_CA_BUNDLE`, `AGENTS_NET_EXTRA_CA_BUNDLE`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `NPM_CONFIG_CAFILE`, `DENO_CERT`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE`, and `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`.
- *(Future enhancement / TODO):* Generate a PKCS#12 truststore from the merged PEM bundle and append `-Djavax.net.ssl.trustStore` / `-Djavax.net.ssl.trustStoreType=PKCS12` to `JAVA_TOOL_OPTIONS` for JVM runtimes.

#### Upstream Authentication Modes

`sandbox-net` terminates the per-Pod channel outside the untrusted workload container, allowing all four Kubernetes-native authentication modes to operate without exposing private keys or tokens to agent code (`automountServiceAccountToken: false` remains enforced):

| Mode | Mechanism | Credential Location | Best Fit |
| :--- | :--- | :--- | :--- |
| **`MTLS`** | Hot-reloaded PEM client cert/key (`certDir` or `Secret`) + CA/SPIFFE server verification + attested `Agents-Net-*` headers. | Node host dir or K8s `Secret` (never in Pod). | Works on any K8s cluster; enables shared node-level H2/H3 multiplexing and instant WarmPool claim transitions. |
| **`SPIFFE` (`Node`)** | Official SPIFFE Workload API (`go-spiffe/v2`) X.509-SVID + auto-rotating Trust Bundle + strict server SPIFFE ID/TrustDomain authorizer + attested `Agents-Net-*` headers. | Local SPIRE Agent UDS (never in Pod). | Clusters with SPIRE seeking shared node-level H2/H3 multiplexing with zero static secrets. |
| **`SPIFFE` (`DelegatedPod`)** | Streaming SPIRE Delegated Identity v1 API (`SubscribeToX509SVIDs` with selector `k8s:pod-uid:<uid>` + `SubscribeToX509Bundles`). | Fetched in memory by `sandbox-net` (never in Pod). | Strongest cryptographic per-Pod workload identity with SPIRE; zero header trust. |
| **`PodCertificate` (KEP-4317)** | Controller adds a `podCertificate` projected volume (`credential-bundle.pem`, PKCS#8 + cert chain) mounted read-only **only** on `sandbox-net-tun2connect`. `sandbox-net` reads and hot-reloads `<kubeletRoot>/pods/<uid>/volumes/kubernetes.io~projected/sandbox-net-pod-cert/credential-bundle.pem`. | Kubelet projected volume isolated from workload containers. | Kubernetes 1.34+ clusters with a native KEP-4317 signer (cert-manager, GKE Workload Identity, SPIRE signer). |
| **`ServiceAccountToken` (`Node`)** | `sandbox-net` reads its own audience-bound projected SA token and sends `Proxy-Authorization: Bearer <jwt>` + attested `Agents-Net-*` headers over TLS. | DaemonSet projected volume (never in Pod). | Matches `gke-labs/service-portals` (`TokenReview` `authentication.kubernetes.io/node-name` verification); zero PKI required. |
| **`ServiceAccountToken` (`Pod`)** | Controller adds an audience-bound `serviceAccountToken` projected volume mounted read-only **only** on `sandbox-net-tun2connect`. `sandbox-net` reads and hot-reloads `<kubeletRoot>/pods/<uid>/volumes/kubernetes.io~projected/sandbox-net-sa-token/token` and sends `Proxy-Authorization: Bearer <jwt>`. | Kubelet projected volume isolated from workload containers. | External or out-of-cluster upstreams verifying per-Pod tokens via cluster OIDC JWKS without API server access. |

**Security invariant for Pod-projected credentials:** CEL validation enforces that `PodCertificate` and Pod-mode `ServiceAccountToken` require `adapterMode: TunSidecar`, guaranteeing kubelet-projected credentials are mounted only on the trusted `sandbox-net-tun2connect` sidecar and never inside untrusted workload containers.

#### Standardized `agents.net` Upstream Wire & Attested Metadata

- **TCP egress:** Standard `CONNECT host:port` over HTTP/2 (default, multiplexed over persistent TLS/mTLS connections) or HTTP/1.1.
- **UDP egress:** Standard RFC 9298 `connect-udp` (`GET /.well-known/masque/udp/{host}/{port}/`, `Upgrade: connect-udp`, `Capsule-Protocol: ?1`, RFC 9297/9298 `DATAGRAM` capsules).
- **Denials and diagnostics:** Upstream HTTP status codes (`403`, `407`, `502`), `agents.net` `Boundary-Reason`, and RFC 9209 `Proxy-Status` headers propagate transparently back to the sandbox. Unconfigured upstreams or auth failures fail closed (`503` / `502`).
- **Attested workload metadata:** `sandbox-net` attaches sanitized, unforgeable headers from kubelet/DRA/NRI/Pod watch:
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
    deviceClassName: sandbox-net.agents.x-k8s.io # optional default
    confinementMode: PodNetworkIsolated          # PodNetworkIsolated | NetworkPolicyDenyAll
    adapterMode: TunSidecar                      # TunSidecar | TunVM | ExplicitProxy
    caTrust:
      mode: InjectEnv                            # None | MountOnly | InjectEnv
      bundleMode: AppendSystemRoots              # AppendSystemRoots | Replace
      sources:
        - type: Secret                           # ConfigMap | Secret | ClusterTrustBundle | HostPath
          secretRef:
            name: corp-proxy-ca                  # cert-manager kubernetes.io/tls Secret
            key: ca.crt
    proxy:                                       # used when adapterMode is ExplicitProxy
      port: 15001
      noProxy:
        - .internal.corp
    upstream:                                    # optional if DeviceClass provides default
      address: https://egress-portal.sandbox-system.svc:8443
      protocol: HTTP2                            # HTTP1 | HTTP2 | HTTP3
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

Validation rules (CEL `XValidation`):
- `Sandbox` and `SandboxTemplate`: forbid `spec.service: true` when `spec.network.confinementMode` is `PodNetworkIsolated` (default).
- `SandboxTemplate`: forbid setting both `spec.network` and legacy `spec.networkPolicy`.
- `SandboxUpstreamAuth` & `SandboxCASource`: enforce strict discriminated unions matching `type`.
- `SandboxNetworkSpec`: require `adapterMode: TunSidecar` for `PodCertificate` and Pod-mode `ServiceAccountToken`.

#### Implementation Guidance

1. **Core API (`api/v1beta1/sandbox_network_types.go`, `api/v1beta1/sandbox_types.go`, `extensions/api/v1beta1/sandboxtemplate_types.go`):**
   - Add `SandboxNetworkSpec` to `SandboxBlueprint` and register nested apply-configuration externals in `dev/tools/client-gen-go.sh`.
   - Keep all API fields KAL-compliant (enums over booleans, slices over maps, explicit `+optional`/`+required`).
2. **Controllers (`controllers/sandbox_network.go`, `controllers/sandbox_controller.go`, `extensions/controllers/`):**
   - When `sandbox.Spec.Network != nil` and `OperatingMode == Running`, reconcile a controller-owned standard Kubernetes `resource.k8s.io/v1` `ResourceClaim` carrying JSON `NetworkParameters` in `OpaqueDeviceConfiguration`. Delete the claim on suspension or expiry to release the node DRA slot.
   - Inject `ApplySandboxNetworkPodSpec` defaults (`enableServiceLinks: false`, `dnsPolicy: None` with `100.127.255.253` for `TunSidecar` or `127.0.0.1` for `ExplicitProxy`, single `sandbox-net-tun2connect` sidecar, isolated projected volumes for `PodCertificate`/`ServiceAccountToken(Pod)`, and `pod.Spec.ResourceClaims`).
   - Allow `PodNetworkIsolated` Sandboxes to become `Ready=True` and be adopted from `SandboxWarmPool` based on `NodeName` without requiring `PodIPs`.
   - Update `compareSandboxBlueprint` in `extensions/controllers/sandboxwarmpool_controller.go` to track `Network` drift.
   - Under `SandboxTemplate` with `NetworkPolicyDenyAll`, reconcile a strict empty-ingress/empty-egress deny-all `NetworkPolicy`. Under `PodNetworkIsolated`, skip/clean owned `NetworkPolicy`.
3. **Node Plumbing DaemonSet (`packages/sandbox-net`):**
   - `pkg/params`: layered `DeviceClass` + `ResourceClaim` `OpaqueDeviceConfiguration` decoder with `custom` and arbitrary `opaque` JSON blocks.
   - `pkg/socketat`: goroutine-safe cross-netns execution and `ListenAt` / `ListenAtPath` following `github.com/aojea/socketat`.
   - `pkg/catrust`: shared CA bundle resolver (`ConfigMap`, `Secret`, `ClusterTrustBundle`, `HostPath`) extracting strictly `CERTIFICATE` PEM blocks for both Pod `caTrust` (`AppendSystemRoots` / `Replace`) and `upstream.tls.caCertificateRefs`, plus the `agents.net` and multi-language CA env map.
   - `pkg/proxyenv`: full language magic proxy env var generator and non-clobbering container env merge (including `JAVA_TOOL_OPTIONS` append).
   - `pkg/auth`: all four native auth modes (`mtls.go`, `spiffe.go` using `github.com/spiffe/go-spiffe/v2` + streaming SPIRE Delegated Identity v1 client, `podcert.go` atomic KEP-4317 PEM bundle reader, `satoken.go` hot-reloading Node/Pod JWT reader).
   - `pkg/tunnel`: per-Pod UDS + attached `socketat` loopback listener manager, strict RFC 9110/9112/9209/9298 parser (including plain HTTP `HTTP_PROXY` tunneling over upstream `CONNECT`), stdlib multiplexed HTTP/2 + HTTP/1.1 upstream dialer, immediate revocation, and structured `agents.net` JSONL audit logging.
   - `pkg/store`: schema-versioned BoltDB tmpfs checkpoint store.
   - `pkg/driver`: DraNet-style standard GA DRA `kubeletplugin.DRAPlugin` (node pod-capacity slots, `MergePatch` `status.devices` via `resourceclaims/driver`) + NRI plugin + node-scoped `core/v1` Pod informer for `ServiceAccount` and warm-pool claim sync.
   - `pkg/metrics`: bounded-cardinality Prometheus counters/gauges/histograms.
4. **End-to-End Verification (`test/e2e/sandbox_net_test.go`):**
   - Multi-test `kind` E2E suite covering default & custom `ExplicitProxy` ports, `Secret`/`ConfigMap` `caTrust` (`AppendSystemRoots` and `Replace`, zero private-key leak), direct egress route-flush isolation, HTTPS + plain HTTP + direct UDS + `403` `Boundary-Reason`/`Proxy-Status`, `MTLS` (`kubernetes.io/tls` `Secret`), `ServiceAccountToken` (`Node` JWT), suspend/resume `ResourceClaim` release, `SandboxWarmPool` -> `SandboxClaim` identity sync, and `DeviceClass` opaque defaults/overrides.

## Scalability

- **Zero extra CRDs and zero per-Pod policy watches:** Because configuration flows through standard Kubernetes DRA `ResourceClaim` allocations delivered by kubelet, `sandbox-net` requires no custom CRD informers. Its single watch is a node-scoped `core/v1` Pod informer (`fieldSelector: spec.nodeName=<node>`), scaling linearly with local Pod count only.
- **Single GA `ResourceSlice` for standard nodes:** Publishing per-pod slot devices sized to `node.Status.Allocatable.Pods()` (typically `110`, below `ResourceSliceMaxDevices = 128`) produces **one** `ResourceSlice` object per node (chunking cleanly for higher-density nodes) using 100% GA `resource.k8s.io/v1` with zero alpha/beta feature gates.
- **Zero CDI disk I/O on the Pod start path:** NRI `CreateContainer` injects mounts, CA bundles, and `/dev/net/tun` in memory, avoiding per-Pod CDI JSON file creation and fsync overhead at high Pod churn.
- **Multiplexed HTTP/2 upstream connections:** `MTLS`, `SPIFFE (Node)`, and `ServiceAccountToken` modes multiplex tunnels over persistent HTTP/2 TLS connections, keeping TLS handshake overhead negligible even under bursty agent tool calls.
- **WarmPool compatibility:** Pre-warmed Sandboxes remain ready with zero cold start; on `SandboxClaim` adoption, the node-scoped Pod informer detects `agents.x-k8s.io/sandbox-id` and `agents.x-k8s.io/sandbox-claim-name` updates, refreshes attested headers, and revokes pre-claim tunnels immediately.

## Alternatives

### Alternative 1: Standalone `SandboxNetworkPolicy` and `SandboxNetworkBinding` CRDs with embedded CEL engine

An earlier design proposed shipping a `network.agents.x-k8s.io/v1alpha1` API group with a node-local CEL policy engine and credential-injection proxy directly inside `agent-sandbox`. We rejected this because:
- It duplicates policy, L7 inspection, and secret-injection responsibilities already solved by specialized upstreams (`gke-labs/service-portals`, Envoy/Agentgateway, Cilium, corporate egress gateways).
- It expands CRD surface area, controller RBAC, and API-server watch load (`SandboxNetworkBinding` per Sandbox).
- Decoupling the plumbing from policy/secrets promotes **`agents.net`** as a clean interoperability boundary that any upstream can implement.

### Alternative 2: Exposing `HTTP_PROXY=unix:///run/agents.net/egress.sock` in `ExplicitProxy` mode

Almost no mainstream HTTP client (Go `net/http`, Python `requests`/`urllib3`/`httpx`, Node `undici`, Rust `reqwest`, Java, `curl`, `git`, `pip`, `npm`) accepts `unix://` proxy URLs. Using `socketat.ListenAtPath` to bind `127.0.0.1:<port>` directly inside the Pod's loopback namespace gives unmodified HTTP libraries standard `http://127.0.0.1:<port>` proxy access even inside a loopback-only `PodNetworkIsolated` Pod with zero sidecar container.

### Alternative 3: Hardcoding a single upstream authentication mechanism

Choosing only mTLS or only ServiceAccount JWTs breaks real clusters: SPIRE environments expect SPIFFE X.509-SVIDs, Kubernetes 1.34+ clusters are adopting KEP-4317 `PodCertificateRequest`, `gke-labs/service-portals` uses node-attested `ServiceAccountToken` (`TokenReview`), and corporate proxies often use standard rotated mTLS certs. Supporting all four native Kubernetes auth modes behind a compact discriminated union covers every deployment environment cleanly.

### Alternative 4: Requiring `DRAConsumableCapacity` (`allowMultipleAllocations: true`)

An earlier revision modeled each node as a single shared device with `allowMultipleAllocations: true` and consumable `capacity.sandboxes`. Because `DRAConsumableCapacity` (and `DRADeviceTaints` / `DRAExtendedResource`) remain feature-gated while a node's Pod capacity (`node.Status.Allocatable.Pods()`, typically `110`) already bounds concurrent sandboxes and fits inside a single GA `ResourceSlice` (`<= 128` devices), publishing simple per-pod slot devices runs on every Kubernetes 1.34+ cluster out of the box with zero alpha/beta feature gates.
