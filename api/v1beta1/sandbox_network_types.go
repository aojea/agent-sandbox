// Copyright 2026 The Kubernetes Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1beta1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// SandboxNetDriverName is the Kubernetes DRA driver name and NRI plugin name
	// for the sandbox-net node plumbing DaemonSet.
	SandboxNetDriverName = "sandbox-net.agents.x-k8s.io"

	// DefaultSandboxNetDeviceClassName is the default DRA DeviceClass referenced
	// when spec.network.deviceClassName is omitted.
	DefaultSandboxNetDeviceClassName = SandboxNetDriverName

	// SandboxNetExtendedResourceName is the DRA extended resource name that schedules
	// a Pod onto nodes with available sandbox-net capacity.
	SandboxNetExtendedResourceName = "agents.x-k8s.io/sandbox-net"

	// SandboxNetPodCertVolumeName is the projected volume name used for KEP-4317
	// PodCertificate authentication when isolated on the tun2connect native sidecar.
	SandboxNetPodCertVolumeName = "sandbox-net-pod-cert"

	// SandboxNetPodCertBundleFile is the credential bundle filename written by kubelet
	// inside SandboxNetPodCertVolumeName.
	SandboxNetPodCertBundleFile = "credential-bundle.pem"

	// SandboxNetSATokenVolumeName is the projected volume name used for Pod-mode
	// ServiceAccountToken authentication when isolated on the tun2connect native sidecar.
	SandboxNetSATokenVolumeName = "sandbox-net-sa-token"

	// SandboxNetSATokenFile is the token filename written by kubelet inside
	// SandboxNetSATokenVolumeName.
	SandboxNetSATokenFile = "token"

	// DefaultSandboxNetProxyPort is the default Pod loopback port (127.0.0.1:15001)
	// bound via socketat when adapterMode is ExplicitProxy.
	DefaultSandboxNetProxyPort int32 = 15001
)

// SandboxConfinementMode defines how the backing Pod is isolated from direct cluster and
// internet network egress so that all traffic traverses the agents.net plumbing.
// +kubebuilder:validation:Enum=PodNetworkIsolated;NetworkPolicyDenyAll
type SandboxConfinementMode string

const (
	// SandboxConfinementModePodNetworkIsolated places the Pod in a loopback-only network
	// namespace (KEP-6313) with no CNI attachment and no Pod IP. The NRI RunPodSandbox
	// hook verifies that only loopback exists before any container starts.
	SandboxConfinementModePodNetworkIsolated SandboxConfinementMode = "PodNetworkIsolated"

	// SandboxConfinementModeNetworkPolicyDenyAll runs on standard CNI clusters without
	// KEP-6313. The controller applies a deny-all NetworkPolicy and the NRI RunPodSandbox
	// hook flushes routes on non-loopback interfaces before any container starts.
	SandboxConfinementModeNetworkPolicyDenyAll SandboxConfinementMode = "NetworkPolicyDenyAll"
)

// SandboxAdapterMode defines how the Pod's network namespace connects to the per-Pod
// agents.net egress channel managed by sandbox-net.
// +kubebuilder:validation:Enum=TunSidecar;TunVM;ExplicitProxy
type SandboxAdapterMode string

const (
	// SandboxAdapterModeTunSidecar injects one per-Pod tun2connect native sidecar container
	// that owns tun0 and VirtualDNS (100.127.255.253) for the Pod network namespace.
	SandboxAdapterModeTunSidecar SandboxAdapterMode = "TunSidecar"

	// SandboxAdapterModeTunVM delegates TUN creation to a hypervisor or microVM adapter
	// (one tun2connect per microVM) connected over vsock or Unix socket.
	SandboxAdapterModeTunVM SandboxAdapterMode = "TunVM"

	// SandboxAdapterModeExplicitProxy skips TUN creation, binds a Pod-loopback HTTP proxy
	// listener (127.0.0.1:<port>) inside the Pod network namespace via socketat, mounts
	// /run/agents.net/egress.sock, and injects language-specific proxy environment variables.
	SandboxAdapterModeExplicitProxy SandboxAdapterMode = "ExplicitProxy"
)

// SandboxUpstreamProtocol defines the HTTP transport used between sandbox-net and
// the upstream agents.net proxy.
// +kubebuilder:validation:Enum=HTTP1;HTTP2;HTTP3
type SandboxUpstreamProtocol string

const (
	// SandboxUpstreamProtocolHTTP1 forwards CONNECT and RFC 9298 connect-udp over HTTP/1.1.
	SandboxUpstreamProtocolHTTP1 SandboxUpstreamProtocol = "HTTP1"

	// SandboxUpstreamProtocolHTTP2 multiplexes CONNECT and Extended CONNECT (RFC 9298) over HTTP/2.
	SandboxUpstreamProtocolHTTP2 SandboxUpstreamProtocol = "HTTP2"

	// SandboxUpstreamProtocolHTTP3 multiplexes CONNECT and connect-udp (MASQUE) over HTTP/3.
	SandboxUpstreamProtocolHTTP3 SandboxUpstreamProtocol = "HTTP3"
)

// SandboxUpstreamAuthType selects the authentication mechanism used between sandbox-net
// and the upstream proxy or portal.
// +kubebuilder:validation:Enum=MTLS;SPIFFE;PodCertificate;ServiceAccountToken
type SandboxUpstreamAuthType string

const (
	// SandboxUpstreamAuthTypeMTLS authenticates using a rotated PEM client certificate and key.
	SandboxUpstreamAuthTypeMTLS SandboxUpstreamAuthType = "MTLS"

	// SandboxUpstreamAuthTypeSPIFFE authenticates using X.509-SVIDs from the SPIFFE Workload API
	// or SPIRE Delegated Identity API.
	SandboxUpstreamAuthTypeSPIFFE SandboxUpstreamAuthType = "SPIFFE"

	// SandboxUpstreamAuthTypePodCertificate authenticates using a per-Pod X.509 certificate
	// minted by kubelet via KEP-4317 PodCertificateRequest.
	SandboxUpstreamAuthTypePodCertificate SandboxUpstreamAuthType = "PodCertificate"

	// SandboxUpstreamAuthTypeServiceAccountToken authenticates using an audience-bound Kubernetes
	// ServiceAccount JWT sent in Proxy-Authorization.
	SandboxUpstreamAuthTypeServiceAccountToken SandboxUpstreamAuthType = "ServiceAccountToken"
)

// SandboxSPIFFEMode defines whether SPIFFE authentication uses the node DaemonSet SVID
// or a per-Pod SVID obtained via the SPIRE Delegated Identity API.
// +kubebuilder:validation:Enum=Node;DelegatedPod
type SandboxSPIFFEMode string

const (
	// SandboxSPIFFEModeNode authenticates sandbox-net with its own SPIFFE X.509-SVID
	// and attaches attested Pod and Sandbox identity metadata to upstream requests.
	SandboxSPIFFEModeNode SandboxSPIFFEMode = "Node"

	// SandboxSPIFFEModeDelegatedPod obtains a per-Pod X.509-SVID in memory from the local
	// SPIRE Agent Delegated Identity API so private keys never enter the Pod.
	SandboxSPIFFEModeDelegatedPod SandboxSPIFFEMode = "DelegatedPod"
)

// SandboxPodCertificateKeyType defines the keypair algorithm kubelet generates for
// KEP-4317 PodCertificate projections.
// +kubebuilder:validation:Enum=RSA3072;RSA4096;ECDSAP256;ECDSAP384;ECDSAP521;ED25519
type SandboxPodCertificateKeyType string

const (
	// SandboxPodCertificateKeyTypeRSA3072 generates a 3072-bit RSA keypair.
	SandboxPodCertificateKeyTypeRSA3072 SandboxPodCertificateKeyType = "RSA3072"

	// SandboxPodCertificateKeyTypeRSA4096 generates a 4096-bit RSA keypair.
	SandboxPodCertificateKeyTypeRSA4096 SandboxPodCertificateKeyType = "RSA4096"

	// SandboxPodCertificateKeyTypeECDSAP256 generates a P-256 ECDSA keypair.
	SandboxPodCertificateKeyTypeECDSAP256 SandboxPodCertificateKeyType = "ECDSAP256"

	// SandboxPodCertificateKeyTypeECDSAP384 generates a P-384 ECDSA keypair.
	SandboxPodCertificateKeyTypeECDSAP384 SandboxPodCertificateKeyType = "ECDSAP384"

	// SandboxPodCertificateKeyTypeECDSAP521 generates a P-521 ECDSA keypair.
	SandboxPodCertificateKeyTypeECDSAP521 SandboxPodCertificateKeyType = "ECDSAP521"

	// SandboxPodCertificateKeyTypeED25519 generates an Ed25519 keypair.
	SandboxPodCertificateKeyTypeED25519 SandboxPodCertificateKeyType = "ED25519"
)

// SandboxServiceAccountTokenMode defines whether ServiceAccountToken authentication uses
// the node DaemonSet's projected token or a kubelet-projected per-Pod token.
// +kubebuilder:validation:Enum=Node;Pod
type SandboxServiceAccountTokenMode string

const (
	// SandboxServiceAccountTokenModeNode sends the node DaemonSet's audience-bound JWT
	// together with attested Pod metadata (compatible with TokenReview node-name verification).
	SandboxServiceAccountTokenModeNode SandboxServiceAccountTokenMode = "Node"

	// SandboxServiceAccountTokenModePod sends a kubelet-projected, audience-bound JWT for the
	// Pod's ServiceAccount, mounted only on the trusted tun2connect sidecar and read by
	// sandbox-net on the host so the untrusted workload container never accesses the token.
	SandboxServiceAccountTokenModePod SandboxServiceAccountTokenMode = "Pod"
)

// SandboxCATrustMode controls how Pod CA certificates are exposed to workload containers.
// +kubebuilder:validation:Enum=None;MountOnly;InjectEnv
type SandboxCATrustMode string

const (
	// SandboxCATrustModeNone disables mounting custom CA certificates into workload containers.
	SandboxCATrustModeNone SandboxCATrustMode = "None"

	// SandboxCATrustModeMountOnly mounts the CA bundle files read-only at /var/run/agent-ca.pem
	// and /var/run/agent-extra-ca.pem without setting runtime environment variables.
	SandboxCATrustModeMountOnly SandboxCATrustMode = "MountOnly"

	// SandboxCATrustModeInjectEnv mounts the CA bundle files and injects AGENT_CA_CERT plus
	// language-specific CA trust environment variables (SSL_CERT_FILE, REQUESTS_CA_BUNDLE,
	// PIP_CERT, CURL_CA_BUNDLE, GIT_SSL_CAINFO, NODE_EXTRA_CA_CERTS, NPM_CONFIG_CAFILE,
	// DENO_CERT, CARGO_HTTP_CAINFO, AWS_CA_BUNDLE, CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE).
	SandboxCATrustModeInjectEnv SandboxCATrustMode = "InjectEnv"
)

// SandboxCABundleMode defines whether Pod CA certificates are merged with system root CAs
// or replace the root trust store completely.
// +kubebuilder:validation:Enum=AppendSystemRoots;Replace
type SandboxCABundleMode string

const (
	// SandboxCABundleModeAppendSystemRoots merges standard system root CAs with the configured
	// custom CA certificates in /var/run/agent-ca.pem so pass-through HTTPS destinations remain
	// trusted while NODE_EXTRA_CA_CERTS receives the custom-only /var/run/agent-extra-ca.pem.
	SandboxCABundleModeAppendSystemRoots SandboxCABundleMode = "AppendSystemRoots"

	// SandboxCABundleModeReplace writes only the configured custom CA certificates to
	// /var/run/agent-ca.pem without appending system root CAs.
	SandboxCABundleModeReplace SandboxCABundleMode = "Replace"
)

// SandboxCASourceType selects the source of a PEM CA certificate bundle.
// +kubebuilder:validation:Enum=ConfigMap;Secret;ClusterTrustBundle;HostPath
type SandboxCASourceType string

const (
	// SandboxCASourceTypeConfigMap reads PEM CA certificates from a ConfigMap in the Sandbox namespace
	// (for example, kube-root-ca.crt or a trust-manager Bundle ConfigMap).
	SandboxCASourceTypeConfigMap SandboxCASourceType = "ConfigMap"

	// SandboxCASourceTypeSecret reads PEM CA certificates from a Secret in the Sandbox namespace
	// (for example, ca.crt in a cert-manager kubernetes.io/tls Secret or trust-manager Bundle Secret).
	// Only valid CERTIFICATE PEM blocks are extracted; private keys are never mounted into the Pod.
	SandboxCASourceTypeSecret SandboxCASourceType = "Secret"

	// SandboxCASourceTypeClusterTrustBundle reads PEM CA certificates from Kubernetes
	// certificates.k8s.io/v1beta1 ClusterTrustBundle objects (KEP-3257).
	SandboxCASourceTypeClusterTrustBundle SandboxCASourceType = "ClusterTrustBundle"

	// SandboxCASourceTypeHostPath reads PEM CA certificates from a node-local filesystem path.
	SandboxCASourceTypeHostPath SandboxCASourceType = "HostPath"
)

// SandboxIngressProtocol defines the transport protocol for an explicit ingress port.
// +kubebuilder:validation:Enum=TCP;UDP
type SandboxIngressProtocol string

const (
	// SandboxIngressProtocolTCP forwards TCP ingress traffic.
	SandboxIngressProtocolTCP SandboxIngressProtocol = "TCP"

	// SandboxIngressProtocolUDP forwards UDP ingress traffic.
	SandboxIngressProtocolUDP SandboxIngressProtocol = "UDP"
)

// SandboxConfigMapKeyRef selects a key inside a ConfigMap in the Sandbox namespace.
type SandboxConfigMapKeyRef struct {
	// name is the ConfigMap name in the Sandbox namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`

	// key is the ConfigMap data key containing PEM-encoded certificates. Defaults to ca.crt.
	// +kubebuilder:default="ca.crt"
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Key string `json:"key,omitempty"`
}

// SandboxSecretKeyRef selects a key inside a Secret in the Sandbox namespace.
// Compatible with cert-manager kubernetes.io/tls Secrets (default key ca.crt, or tls.crt)
// and trust-manager Secret bundles. Only CERTIFICATE PEM blocks are read.
type SandboxSecretKeyRef struct {
	// name is the Secret name in the Sandbox namespace.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`

	// key is the Secret data key containing PEM-encoded certificates. Defaults to ca.crt.
	// +kubebuilder:default="ca.crt"
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Key string `json:"key,omitempty"`
}

// SandboxClusterTrustBundleRef selects one or more Kubernetes ClusterTrustBundle objects
// by exact name or by signerName and optional labelSelector.
// +kubebuilder:validation:XValidation:rule="(has(self.name) && size(self.name) > 0) != (has(self.signerName) && size(self.signerName) > 0)",message="exactly one of name or signerName must be set"
type SandboxClusterTrustBundleRef struct {
	// name selects a single ClusterTrustBundle object by name.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Name string `json:"name,omitempty"`

	// signerName selects all ClusterTrustBundle objects issued for this signerName
	// matching labelSelector.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	SignerName string `json:"signerName,omitempty"`

	// labelSelector optionally filters ClusterTrustBundle objects when signerName is set.
	// +optional
	LabelSelector *metav1.LabelSelector `json:"labelSelector,omitempty"`
}

// SandboxCASource defines one CA certificate bundle source following Kubernetes,
// cert-manager, trust-manager, and Gateway API conventions.
// +kubebuilder:validation:XValidation:rule="self.type == 'ConfigMap' ? (has(self.configMapRef) && !has(self.secretRef) && !has(self.clusterTrustBundle) && !has(self.hostPath)) : true",message="configMapRef must be set and other source fields omitted when type is ConfigMap"
// +kubebuilder:validation:XValidation:rule="self.type == 'Secret' ? (has(self.secretRef) && !has(self.configMapRef) && !has(self.clusterTrustBundle) && !has(self.hostPath)) : true",message="secretRef must be set and other source fields omitted when type is Secret"
// +kubebuilder:validation:XValidation:rule="self.type == 'ClusterTrustBundle' ? (has(self.clusterTrustBundle) && !has(self.configMapRef) && !has(self.secretRef) && !has(self.hostPath)) : true",message="clusterTrustBundle must be set and other source fields omitted when type is ClusterTrustBundle"
// +kubebuilder:validation:XValidation:rule="self.type == 'HostPath' ? (has(self.hostPath) && size(self.hostPath) > 0 && !has(self.configMapRef) && !has(self.secretRef) && !has(self.clusterTrustBundle)) : true",message="hostPath must be set and other source fields omitted when type is HostPath"
type SandboxCASource struct {
	// type selects the CA bundle source: ConfigMap, Secret, ClusterTrustBundle, or HostPath.
	// +required
	Type SandboxCASourceType `json:"type"`

	// configMapRef references a ConfigMap key containing PEM CA certificates.
	// +optional
	ConfigMapRef *SandboxConfigMapKeyRef `json:"configMapRef,omitempty"`

	// secretRef references a Secret key containing PEM CA certificates (for example,
	// ca.crt on a cert-manager kubernetes.io/tls Secret).
	// +optional
	SecretRef *SandboxSecretKeyRef `json:"secretRef,omitempty"`

	// clusterTrustBundle references Kubernetes ClusterTrustBundle object(s).
	// +optional
	ClusterTrustBundle *SandboxClusterTrustBundleRef `json:"clusterTrustBundle,omitempty"`

	// hostPath references a PEM CA bundle file on the node filesystem.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	HostPath string `json:"hostPath,omitempty"`
}

// SandboxCATrustSpec defines Pod-scoped CA certificates mounted into workload containers
// per the agents.net specification (AGENT_CA_CERT) along with language runtime trust env vars.
type SandboxCATrustSpec struct {
	// mode controls whether CA bundles are ignored, mounted only, or mounted with language
	// trust environment variables injected. Defaults to InjectEnv when caTrust is configured.
	// +kubebuilder:default=InjectEnv
	// +optional
	Mode SandboxCATrustMode `json:"mode,omitempty"`

	// bundleMode controls whether custom CA certificates are appended to system root CAs
	// (AppendSystemRoots, default) or replace the root trust store (Replace).
	// +kubebuilder:default=AppendSystemRoots
	// +optional
	BundleMode SandboxCABundleMode `json:"bundleMode,omitempty"`

	// sources lists one or more PEM CA bundle sources to merge into the Pod's CA bundle.
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	// +optional
	Sources []SandboxCASource `json:"sources,omitempty"`
}

// SandboxExplicitProxyConfig configures the loopback HTTP proxy listener bound inside the
// Pod network namespace via socketat and the language proxy environment variables injected
// when adapterMode is ExplicitProxy.
type SandboxExplicitProxyConfig struct {
	// port is the loopback TCP port (127.0.0.1:<port>) bound inside the Pod network namespace.
	// Defaults to 15001.
	// +kubebuilder:default=15001
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port *int32 `json:"port,omitempty"`

	// noProxy lists additional hostnames, domain suffixes, or CIDRs appended to
	// localhost,127.0.0.1,::1 in NO_PROXY, no_proxy, and JAVA_TOOL_OPTIONS.
	// +kubebuilder:validation:MaxItems=64
	// +listType=atomic
	// +optional
	NoProxy []string `json:"noProxy,omitempty"`
}

// SandboxIngressPort declares a container port exposed over the agents.net ingress tunnel.
type SandboxIngressPort struct {
	// port is the TCP or UDP port number inside the sandbox Pod.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +required
	Port int32 `json:"port"`

	// protocol is the transport protocol for this port. Defaults to TCP.
	// +kubebuilder:default=TCP
	// +optional
	Protocol SandboxIngressProtocol `json:"protocol,omitempty"`
}

// SandboxNetworkParameter represents a custom key-value parameter passed through DRA
// OpaqueDeviceConfiguration to sandbox-net and the upstream proxy.
type SandboxNetworkParameter struct {
	// name is the unique key of the custom parameter.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +required
	Name string `json:"name"`

	// value is the string value associated with name.
	// +kubebuilder:validation:MaxLength=1024
	// +required
	Value string `json:"value"`
}

// SandboxUpstreamTLS configures TLS verification of the upstream agents.net proxy.
type SandboxUpstreamTLS struct {
	// serverName overrides the TLS Server Name Indication (SNI) and hostname verification target.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	ServerName string `json:"serverName,omitempty"`

	// caCertificateRefs lists one or more CA certificate sources (ConfigMap, Secret,
	// ClusterTrustBundle, or HostPath) used to verify the upstream server certificate.
	// Follows Kubernetes Gateway API BackendTLSPolicy and cert-manager conventions (default key ca.crt).
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	// +optional
	CACertificateRefs []SandboxCASource `json:"caCertificateRefs,omitempty"`

	// trustDomain specifies the SPIFFE trust domain accepted when verifying an upstream X.509-SVID.
	// +kubebuilder:validation:MaxLength=255
	// +optional
	TrustDomain string `json:"trustDomain,omitempty"`

	// acceptedSPIFFEIDs restricts the upstream server certificate to one of these exact SPIFFE IDs.
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	// +optional
	AcceptedSPIFFEIDs []string `json:"acceptedSPIFFEIDs,omitempty"`
}

// SandboxMTLSAuth configures client certificate mTLS authentication to the upstream proxy.
// +kubebuilder:validation:XValidation:rule="has(self.secretRef) || (has(self.certDir) && size(self.certDir) > 0)",message="either secretRef or certDir must be set for MTLS auth"
type SandboxMTLSAuth struct {
	// secretRef references a kubernetes.io/tls Secret (tls.crt and tls.key) in the Sandbox namespace.
	// +optional
	SecretRef *corev1.LocalObjectReference `json:"secretRef,omitempty"`

	// certDir is a node-local directory containing hot-reloaded tls.crt and tls.key files.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	CertDir string `json:"certDir,omitempty"`
}

// SandboxSPIFFEAuth configures SPIFFE X.509-SVID authentication to the upstream proxy.
type SandboxSPIFFEAuth struct {
	// mode selects Node SVID (Workload API) or DelegatedPod SVID (SPIRE Delegated Identity API).
	// Defaults to Node.
	// +kubebuilder:default=Node
	// +optional
	Mode SandboxSPIFFEMode `json:"mode,omitempty"`

	// workloadSocketPath overrides the node's SPIFFE Workload API Unix domain socket path.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	WorkloadSocketPath string `json:"workloadSocketPath,omitempty"`

	// delegatedSocketPath overrides the SPIRE Agent Delegated Identity Unix domain socket path
	// used when mode is DelegatedPod.
	// +kubebuilder:validation:MaxLength=512
	// +optional
	DelegatedSocketPath string `json:"delegatedSocketPath,omitempty"`
}

// SandboxPodCertificateAuth configures KEP-4317 Kubernetes native PodCertificate mTLS.
type SandboxPodCertificateAuth struct {
	// signerName is the Kubernetes PodCertificateRequest signer name (for example,
	// spiffe.io/workload-identity or a cert-manager signer).
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	SignerName string `json:"signerName"`

	// keyType is the private key algorithm kubelet generates for the Pod certificate.
	// Defaults to ECDSAP256.
	// +kubebuilder:default=ECDSAP256
	// +optional
	KeyType SandboxPodCertificateKeyType `json:"keyType,omitempty"`

	// maxExpirationSeconds requests the maximum certificate lifetime in seconds (3600..7862400).
	// +kubebuilder:validation:Minimum=3600
	// +kubebuilder:validation:Maximum=7862400
	// +optional
	MaxExpirationSeconds *int32 `json:"maxExpirationSeconds,omitempty"`
}

// SandboxServiceAccountTokenAuth configures Kubernetes bound ServiceAccount JWT authentication
// sent over TLS in Proxy-Authorization.
type SandboxServiceAccountTokenAuth struct {
	// audience is the required target audience for the projected ServiceAccount JWT.
	// Setting a dedicated audience prevents replay against the Kubernetes API server.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	// +required
	Audience string `json:"audience"`

	// mode selects Node (DaemonSet token with node-name attestation) or Pod (kubelet-projected
	// per-Pod token isolated on the tun2connect sidecar). Defaults to Node.
	// +kubebuilder:default=Node
	// +optional
	Mode SandboxServiceAccountTokenMode `json:"mode,omitempty"`

	// expirationSeconds controls the projected token lifetime in seconds (600..86400).
	// Defaults to 3600.
	// +kubebuilder:default=3600
	// +kubebuilder:validation:Minimum=600
	// +kubebuilder:validation:Maximum=86400
	// +optional
	ExpirationSeconds *int32 `json:"expirationSeconds,omitempty"`
}

// SandboxUpstreamAuth is a discriminated union selecting how sandbox-net authenticates
// to the upstream agents.net proxy or portal.
// +kubebuilder:validation:XValidation:rule="self.type == 'MTLS' ? (has(self.mtls) && !has(self.spiffe) && !has(self.podCertificate) && !has(self.serviceAccountToken)) : true",message="mtls must be set and other auth fields omitted when type is MTLS"
// +kubebuilder:validation:XValidation:rule="self.type == 'SPIFFE' ? (!has(self.mtls) && !has(self.podCertificate) && !has(self.serviceAccountToken)) : true",message="only spiffe may be set when type is SPIFFE"
// +kubebuilder:validation:XValidation:rule="self.type == 'PodCertificate' ? (has(self.podCertificate) && !has(self.mtls) && !has(self.spiffe) && !has(self.serviceAccountToken)) : true",message="podCertificate must be set and other auth fields omitted when type is PodCertificate"
// +kubebuilder:validation:XValidation:rule="self.type == 'ServiceAccountToken' ? (has(self.serviceAccountToken) && !has(self.mtls) && !has(self.spiffe) && !has(self.podCertificate)) : true",message="serviceAccountToken must be set and other auth fields omitted when type is ServiceAccountToken"
type SandboxUpstreamAuth struct {
	// type selects the authentication mechanism: MTLS, SPIFFE, PodCertificate, or ServiceAccountToken.
	// +required
	Type SandboxUpstreamAuthType `json:"type"`

	// mtls configures rotated PEM client certificate authentication.
	// +optional
	MTLS *SandboxMTLSAuth `json:"mtls,omitempty"`

	// spiffe configures SPIFFE Workload API or SPIRE Delegated Identity authentication.
	// +optional
	SPIFFE *SandboxSPIFFEAuth `json:"spiffe,omitempty"`

	// podCertificate configures KEP-4317 kubelet-minted per-Pod certificate authentication.
	// +optional
	PodCertificate *SandboxPodCertificateAuth `json:"podCertificate,omitempty"`

	// serviceAccountToken configures audience-bound Kubernetes ServiceAccount JWT authentication.
	// +optional
	ServiceAccountToken *SandboxServiceAccountTokenAuth `json:"serviceAccountToken,omitempty"`
}

// SandboxNetworkUpstream defines the upstream agents.net proxy or portal that receives
// intercepted sandbox traffic, enforces network policies, and injects credentials.
type SandboxNetworkUpstream struct {
	// address is the upstream agents.net proxy endpoint URL (for example,
	// https://egress-portal.sandbox-system.svc:8443).
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=512
	// +required
	Address string `json:"address"`

	// protocol selects HTTP1, HTTP2, or HTTP3 (MASQUE) for forwarding CONNECT and connect-udp.
	// Defaults to HTTP2.
	// +kubebuilder:default=HTTP2
	// +optional
	Protocol SandboxUpstreamProtocol `json:"protocol,omitempty"`

	// tls configures server certificate verification for the upstream connection.
	// +optional
	TLS *SandboxUpstreamTLS `json:"tls,omitempty"`

	// auth configures client authentication and workload identity attestation to the upstream.
	// +optional
	Auth *SandboxUpstreamAuth `json:"auth,omitempty"`
}

// SandboxNetworkSpec configures DRA + NRI agents.net network plumbing on a Sandbox or
// SandboxTemplate without introducing standalone network policy CRDs. Policy enforcement
// and secret injection remain the responsibility of the configured upstream.
// +kubebuilder:validation:XValidation:rule="!has(self.upstream) || !has(self.upstream.auth) || !(self.upstream.auth.type == 'PodCertificate' || (self.upstream.auth.type == 'ServiceAccountToken' && has(self.upstream.auth.serviceAccountToken) && has(self.upstream.auth.serviceAccountToken.mode) && self.upstream.auth.serviceAccountToken.mode == 'Pod')) || (!has(self.adapterMode) || self.adapterMode == 'TunSidecar')",message="PodCertificate and Pod-mode ServiceAccountToken require adapterMode=TunSidecar to keep credentials out of workload containers"
type SandboxNetworkSpec struct {
	// deviceClassName names the Kubernetes DRA DeviceClass that provides sandbox-net
	// node plumbing and optional cluster-wide default parameters.
	// Defaults to sandbox-net.agents.x-k8s.io.
	// +kubebuilder:default="sandbox-net.agents.x-k8s.io"
	// +kubebuilder:validation:MaxLength=253
	// +optional
	DeviceClassName string `json:"deviceClassName,omitempty"`

	// confinementMode selects how the backing Pod is isolated from direct network egress.
	// Defaults to PodNetworkIsolated.
	// +kubebuilder:default=PodNetworkIsolated
	// +optional
	ConfinementMode SandboxConfinementMode `json:"confinementMode,omitempty"`

	// adapterMode selects how the Pod network namespace connects to sandbox-net.
	// Defaults to TunSidecar.
	// +kubebuilder:default=TunSidecar
	// +optional
	AdapterMode SandboxAdapterMode `json:"adapterMode,omitempty"`

	// upstream defines the external or in-cluster agents.net proxy that enforces policy and
	// injects credentials. May be omitted when the referenced DeviceClass configures a default.
	// +optional
	Upstream *SandboxNetworkUpstream `json:"upstream,omitempty"`

	// caTrust defines Pod-scoped CA certificates mounted per agents.net (AGENT_CA_CERT)
	// and mapped into language-specific TLS trust environment variables.
	// +optional
	CATrust *SandboxCATrustSpec `json:"caTrust,omitempty"`

	// proxy configures the Pod loopback HTTP proxy listener and language proxy environment
	// variables when adapterMode is ExplicitProxy.
	// +optional
	Proxy *SandboxExplicitProxyConfig `json:"proxy,omitempty"`

	// ingressPorts exposes specific container ports through the agents.net ingress tunnel.
	// +kubebuilder:validation:MaxItems=32
	// +listType=map
	// +listMapKey=port
	// +optional
	IngressPorts []SandboxIngressPort `json:"ingressPorts,omitempty"`

	// parameters passes custom key-value metadata and driver-specific settings through DRA
	// OpaqueDeviceConfiguration to sandbox-net and the upstream.
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	// +optional
	Parameters []SandboxNetworkParameter `json:"parameters,omitempty"`
}
