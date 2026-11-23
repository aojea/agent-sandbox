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

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
)

const (
	// Tun2ConnectSidecarName is the container name of the single per-Pod tun2connect
	// native sidecar injected when AdapterMode is TunSidecar.
	Tun2ConnectSidecarName = "sandbox-net-tun2connect"

	// Tun2ConnectVirtualDNSAddr is the synthetic IPv4 resolver address served by
	// tun2connect's VirtualDNS inside the isolated Pod network namespace.
	Tun2ConnectVirtualDNSAddr = "100.127.255.253"

	// DefaultTun2ConnectImage is the default distroless tun2connect sidecar image.
	// Templates may override the image by including an initContainer named Tun2ConnectSidecarName.
	DefaultTun2ConnectImage = "registry.k8s.io/agent-sandbox/tun2connect:latest"

	// sandboxNetClaimRefName is the pod-local name used in pod.Spec.ResourceClaims.
	sandboxNetClaimRefName = "sandbox-net"

	podCertSidecarMountPath = "/var/run/secrets/sandbox-net/pod-cert"
	saTokenSidecarMountPath = "/var/run/secrets/sandbox-net/sa-token"
)

// draOpaqueNetworkParameters is the JSON payload embedded inside
// ResourceClaim.spec.devices.config[].opaque.parameters for the sandbox-net DRA driver.
// It mirrors packages/sandbox-net/pkg/params.NetworkParameters.
type draOpaqueNetworkParameters struct {
	ConfinementMode   sandboxv1beta1.SandboxConfinementMode      `json:"confinementMode,omitempty"`
	AdapterMode       sandboxv1beta1.SandboxAdapterMode          `json:"adapterMode,omitempty"`
	Upstream          *sandboxv1beta1.SandboxNetworkUpstream     `json:"upstream,omitempty"`
	CATrust           *sandboxv1beta1.SandboxCATrustSpec         `json:"caTrust,omitempty"`
	Proxy             *sandboxv1beta1.SandboxExplicitProxyConfig `json:"proxy,omitempty"`
	IngressPorts      []sandboxv1beta1.SandboxIngressPort        `json:"ingressPorts,omitempty"`
	PodCertVolumeName string                                     `json:"podCertVolumeName,omitempty"`
	SATokenVolumeName string                                     `json:"saTokenVolumeName,omitempty"`
	Custom            map[string]string                          `json:"custom,omitempty"`
}

// sandboxIsPodNetworkIsolated reports whether the Sandbox uses KEP-6313 PodNetworkIsolated
// confinement (loopback-only Pod netns with no CNI attachment or PodIPs).
func sandboxIsPodNetworkIsolated(sandbox *sandboxv1beta1.Sandbox) bool {
	if sandbox == nil || sandbox.Spec.Network == nil {
		return false
	}
	mode := sandbox.Spec.Network.ConfinementMode
	return mode == "" || mode == sandboxv1beta1.SandboxConfinementModePodNetworkIsolated
}

// networkResourceClaimName returns a deterministic DNS-1123 ResourceClaim name <= 63 chars.
func networkResourceClaimName(sandboxName string) string {
	const suffix = "-network"
	if len(sandboxName)+len(suffix) <= 63 {
		return sandboxName + suffix
	}
	hash := NameHash(sandboxName)
	maxPrefix := 63 - len(suffix) - 1 - len(hash)
	if maxPrefix < 1 {
		return "sb-" + hash + suffix
	}
	return sandboxName[:maxPrefix] + "-" + hash + suffix
}

func validateSandboxNetworkSpec(sandbox *sandboxv1beta1.Sandbox) error {
	net := sandbox.Spec.Network
	if net == nil {
		return nil
	}
	var errs field.ErrorList
	if sandboxIsPodNetworkIsolated(sandbox) && sandbox.Spec.Service != nil && *sandbox.Spec.Service {
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "service"),
			*sandbox.Spec.Service,
			"spec.service cannot be true when spec.network uses PodNetworkIsolated confinement",
		))
	}
	adapterMode := net.AdapterMode
	if adapterMode == "" {
		adapterMode = sandboxv1beta1.SandboxAdapterModeTunSidecar
	}
	if usesPodProjectedCredential(net) && adapterMode != sandboxv1beta1.SandboxAdapterModeTunSidecar {
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "network", "adapterMode"),
			adapterMode,
			"PodCertificate and Pod-mode ServiceAccountToken require adapterMode=TunSidecar to keep credentials out of workload containers",
		))
	}
	if len(errs) == 0 {
		return nil
	}
	return k8serrors.NewInvalid(
		schema.GroupKind{Group: sandboxv1beta1.GroupVersion.Group, Kind: "Sandbox"},
		sandbox.Name,
		errs,
	)
}

func usesPodCertificateAuth(net *sandboxv1beta1.SandboxNetworkSpec) bool {
	return net != nil && net.Upstream != nil && net.Upstream.Auth != nil &&
		net.Upstream.Auth.Type == sandboxv1beta1.SandboxUpstreamAuthTypePodCertificate &&
		net.Upstream.Auth.PodCertificate != nil
}

func usesPodSATokenAuth(net *sandboxv1beta1.SandboxNetworkSpec) bool {
	return net != nil && net.Upstream != nil && net.Upstream.Auth != nil &&
		net.Upstream.Auth.Type == sandboxv1beta1.SandboxUpstreamAuthTypeServiceAccountToken &&
		net.Upstream.Auth.ServiceAccountToken != nil &&
		net.Upstream.Auth.ServiceAccountToken.Mode == sandboxv1beta1.SandboxServiceAccountTokenModePod
}

func usesPodProjectedCredential(net *sandboxv1beta1.SandboxNetworkSpec) bool {
	return usesPodCertificateAuth(net) || usesPodSATokenAuth(net)
}

// ApplySandboxNetworkPodSpec idempotently applies agents.net PodSpec defaults, the per-Pod
// tun2connect native sidecar, kubelet-projected credential volumes (isolated strictly to
// tun2connect), and (when claimName is non-empty) the DRA ResourceClaim reference.
func ApplySandboxNetworkPodSpec(net *sandboxv1beta1.SandboxNetworkSpec, spec *corev1.PodSpec, claimName string) {
	if net == nil || spec == nil {
		return
	}

	if spec.EnableServiceLinks == nil {
		spec.EnableServiceLinks = new(false)
	}

	adapterMode := net.AdapterMode
	if adapterMode == "" {
		adapterMode = sandboxv1beta1.SandboxAdapterModeTunSidecar
	}

	if spec.DNSPolicy == "" {
		spec.DNSPolicy = corev1.DNSNone
		switch adapterMode {
		case sandboxv1beta1.SandboxAdapterModeExplicitProxy:
			// Kubernetes API validation requires at least one nameserver when dnsPolicy is None.
			// Loopback 127.0.0.1 fails raw UDP/53 queries immediately without leaking DNS to
			// CoreDNS or external resolvers while proxy-aware clients resolve hostnames upstream.
			spec.DNSConfig = &corev1.PodDNSConfig{
				Nameservers: []string{"127.0.0.1"},
			}
		default:
			spec.DNSConfig = &corev1.PodDNSConfig{
				Nameservers: []string{Tun2ConnectVirtualDNSAddr},
			}
		}
	}

	var claimTarget *corev1.Container
	switch adapterMode {
	case sandboxv1beta1.SandboxAdapterModeTunSidecar:
		claimTarget = ensureTun2ConnectSidecar(spec)
		ensureIsolatedPodCredentialVolumes(net, spec, claimTarget)
	default:
		if len(spec.Containers) > 0 {
			claimTarget = &spec.Containers[0]
		}
	}

	if claimName != "" {
		ensurePodResourceClaim(spec, claimName, claimTarget)
	}
}

func ensureTun2ConnectSidecar(spec *corev1.PodSpec) *corev1.Container {
	restartAlways := corev1.ContainerRestartPolicyAlways
	for i := range spec.InitContainers {
		if spec.InitContainers[i].Name != Tun2ConnectSidecarName {
			continue
		}
		c := &spec.InitContainers[i]
		if c.RestartPolicy == nil {
			c.RestartPolicy = &restartAlways
		}
		if c.Image == "" {
			c.Image = DefaultTun2ConnectImage
		}
		return c
	}

	sidecar := corev1.Container{
		Name:          Tun2ConnectSidecarName,
		Image:         DefaultTun2ConnectImage,
		RestartPolicy: &restartAlways,
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: new(false),
			ReadOnlyRootFilesystem:   new(true),
			Capabilities: &corev1.Capabilities{
				Drop: []corev1.Capability{"ALL"},
				// tun2connect creates tun0 once for the Pod network namespace and immediately
				// drops NET_ADMIN from all threads and the bounding set (requiring SETPCAP).
				// Workload containers in the Pod stay at zero capabilities.
				Add: []corev1.Capability{"NET_ADMIN", "SETPCAP"},
			},
		},
	}
	spec.InitContainers = append([]corev1.Container{sidecar}, spec.InitContainers...)
	return &spec.InitContainers[0]
}

// ensureIsolatedPodCredentialVolumes adds kubelet-managed projected volumes for KEP-4317
// PodCertificate or Pod-mode ServiceAccountToken auth and mounts them read-only ONLY on
// the trusted tun2connect sidecar so kubelet materializes and rotates the files while
// workload containers never gain access to them.
func ensureIsolatedPodCredentialVolumes(net *sandboxv1beta1.SandboxNetworkSpec, spec *corev1.PodSpec, sidecar *corev1.Container) {
	if sidecar == nil {
		return
	}
	if usesPodCertificateAuth(net) {
		pc := net.Upstream.Auth.PodCertificate
		keyType := string(pc.KeyType)
		if keyType == "" {
			keyType = string(sandboxv1beta1.SandboxPodCertificateKeyTypeECDSAP256)
		}
		vol := corev1.Volume{
			Name: sandboxv1beta1.SandboxNetPodCertVolumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							PodCertificate: &corev1.PodCertificateProjection{
								SignerName:           pc.SignerName,
								KeyType:              keyType,
								MaxExpirationSeconds: pc.MaxExpirationSeconds,
								CredentialBundlePath: sandboxv1beta1.SandboxNetPodCertBundleFile,
							},
						},
					},
				},
			},
		}
		upsertVolume(spec, vol)
		upsertVolumeMount(sidecar, corev1.VolumeMount{
			Name:      sandboxv1beta1.SandboxNetPodCertVolumeName,
			MountPath: podCertSidecarMountPath,
			ReadOnly:  true,
		})
	}

	if usesPodSATokenAuth(net) {
		sa := net.Upstream.Auth.ServiceAccountToken
		var expSecs *int64
		if sa.ExpirationSeconds != nil {
			v := int64(*sa.ExpirationSeconds)
			expSecs = &v
		} else {
			v := int64(3600)
			expSecs = &v
		}
		vol := corev1.Volume{
			Name: sandboxv1beta1.SandboxNetSATokenVolumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
								Audience:          sa.Audience,
								ExpirationSeconds: expSecs,
								Path:              sandboxv1beta1.SandboxNetSATokenFile,
							},
						},
					},
				},
			},
		}
		upsertVolume(spec, vol)
		upsertVolumeMount(sidecar, corev1.VolumeMount{
			Name:      sandboxv1beta1.SandboxNetSATokenVolumeName,
			MountPath: saTokenSidecarMountPath,
			ReadOnly:  true,
		})
	}
}

func upsertVolume(spec *corev1.PodSpec, vol corev1.Volume) {
	for i := range spec.Volumes {
		if spec.Volumes[i].Name == vol.Name {
			spec.Volumes[i] = vol
			return
		}
	}
	spec.Volumes = append(spec.Volumes, vol)
}

func upsertVolumeMount(c *corev1.Container, mount corev1.VolumeMount) {
	for i := range c.VolumeMounts {
		if c.VolumeMounts[i].Name == mount.Name {
			c.VolumeMounts[i] = mount
			return
		}
	}
	c.VolumeMounts = append(c.VolumeMounts, mount)
}

func ensurePodResourceClaim(spec *corev1.PodSpec, claimName string, target *corev1.Container) {
	foundPodClaim := false
	for i := range spec.ResourceClaims {
		if spec.ResourceClaims[i].Name == sandboxNetClaimRefName {
			spec.ResourceClaims[i].ResourceClaimName = new(claimName)
			foundPodClaim = true
			break
		}
	}
	if !foundPodClaim {
		spec.ResourceClaims = append(spec.ResourceClaims, corev1.PodResourceClaim{
			Name:              sandboxNetClaimRefName,
			ResourceClaimName: new(claimName),
		})
	}
	if target == nil {
		return
	}
	for _, c := range target.Resources.Claims {
		if c.Name == sandboxNetClaimRefName {
			return
		}
	}
	target.Resources.Claims = append(target.Resources.Claims, corev1.ResourceClaim{
		Name: sandboxNetClaimRefName,
	})
}

func buildDRAOpaqueParameters(net *sandboxv1beta1.SandboxNetworkSpec) ([]byte, error) {
	confinement := net.ConfinementMode
	if confinement == "" {
		confinement = sandboxv1beta1.SandboxConfinementModePodNetworkIsolated
	}
	adapter := net.AdapterMode
	if adapter == "" {
		adapter = sandboxv1beta1.SandboxAdapterModeTunSidecar
	}
	params := draOpaqueNetworkParameters{
		ConfinementMode: confinement,
		AdapterMode:     adapter,
		Upstream:        net.Upstream.DeepCopy(),
		CATrust:         net.CATrust.DeepCopy(),
		Proxy:           net.Proxy.DeepCopy(),
		IngressPorts:    slices.Clone(net.IngressPorts),
	}
	if usesPodCertificateAuth(net) {
		params.PodCertVolumeName = sandboxv1beta1.SandboxNetPodCertVolumeName
	}
	if usesPodSATokenAuth(net) {
		params.SATokenVolumeName = sandboxv1beta1.SandboxNetSATokenVolumeName
	}
	if len(net.Parameters) > 0 {
		params.Custom = make(map[string]string, len(net.Parameters))
		for _, kv := range net.Parameters {
			params.Custom[kv.Name] = kv.Value
		}
	}
	return json.Marshal(params)
}

// reconcileNetworkResourceClaim ensures a controller-owned Kubernetes DRA ResourceClaim exists
// when sandbox.Spec.Network is configured and the Sandbox is Running. It deletes the owned
// claim while Suspended so node consumable sandbox capacity is released.
func (r *SandboxReconciler) reconcileNetworkResourceClaim(ctx context.Context, sandbox *sandboxv1beta1.Sandbox, nameHash string) (string, error) {
	if sandbox.Spec.Network == nil {
		return "", nil
	}
	if err := validateSandboxNetworkSpec(sandbox); err != nil {
		return "", err
	}

	if sandbox.Spec.OperatingMode == sandboxv1beta1.SandboxOperatingModeSuspended {
		return "", r.deleteNetworkResourceClaim(ctx, sandbox)
	}

	claimName := networkResourceClaimName(sandbox.Name)
	key := types.NamespacedName{Name: claimName, Namespace: sandbox.Namespace}
	existing := &resourcev1.ResourceClaim{}
	err := r.Get(ctx, key, existing)
	if err == nil {
		ownership, controllerRef := checkOwnership(existing, sandbox)
		if ownership != resourceOwnedBySandbox {
			ownerInfo := "unowned"
			if controllerRef != nil {
				ownerInfo = fmt.Sprintf("%s/%s", controllerRef.Kind, controllerRef.Name)
			}
			return "", fmt.Errorf("refusing to use ResourceClaim %q owned by %s", claimName, ownerInfo)
		}
		return existing.Name, nil
	}
	if !k8serrors.IsNotFound(err) {
		return "", fmt.Errorf("failed to get network ResourceClaim %q: %w", claimName, err)
	}

	rawParams, err := buildDRAOpaqueParameters(sandbox.Spec.Network)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DRA opaque network parameters: %w", err)
	}

	deviceClassName := sandbox.Spec.Network.DeviceClassName
	if deviceClassName == "" {
		deviceClassName = sandboxv1beta1.DefaultSandboxNetDeviceClassName
	}

	claim := &resourcev1.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      claimName,
			Namespace: sandbox.Namespace,
			Labels: map[string]string{
				sandboxv1beta1.SandboxNameHashLabel: nameHash,
			},
		},
		Spec: resourcev1.ResourceClaimSpec{
			Devices: resourcev1.DeviceClaim{
				Requests: []resourcev1.DeviceRequest{
					{
						Name: "sandbox-net",
						Exactly: &resourcev1.ExactDeviceRequest{
							DeviceClassName: deviceClassName,
							AllocationMode:  resourcev1.DeviceAllocationModeExactCount,
							Count:           1,
						},
					},
				},
				Config: []resourcev1.DeviceClaimConfiguration{
					{
						Requests: []string{"sandbox-net"},
						DeviceConfiguration: resourcev1.DeviceConfiguration{
							Opaque: &resourcev1.OpaqueDeviceConfiguration{
								Driver:     sandboxv1beta1.SandboxNetDriverName,
								Parameters: runtime.RawExtension{Raw: rawParams},
							},
						},
					},
				},
			},
		},
	}
	if err := ctrl.SetControllerReference(sandbox, claim, r.Scheme); err != nil {
		return "", fmt.Errorf("SetControllerReference for ResourceClaim failed: %w", err)
	}
	if err := r.Create(ctx, claim, client.FieldOwner(sandboxControllerFieldOwner)); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			return claimName, nil
		}
		return "", fmt.Errorf("failed to create network ResourceClaim %q: %w", claimName, err)
	}
	log.FromContext(ctx).Info("Created DRA network ResourceClaim",
		"ResourceClaim.Namespace", claim.Namespace,
		"ResourceClaim.Name", claim.Name,
		"DeviceClass", deviceClassName,
	)
	return claim.Name, nil
}

func (r *SandboxReconciler) deleteNetworkResourceClaim(ctx context.Context, sandbox *sandboxv1beta1.Sandbox) error {
	if sandbox.Spec.Network == nil {
		return nil
	}
	claimName := networkResourceClaimName(sandbox.Name)
	claim := &resourcev1.ResourceClaim{}
	if err := r.Get(ctx, types.NamespacedName{Name: claimName, Namespace: sandbox.Namespace}, claim); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get network ResourceClaim %q: %w", claimName, err)
	}
	if ownership, _ := checkOwnership(claim, sandbox); ownership != resourceOwnedBySandbox {
		return nil
	}
	if err := r.Delete(ctx, claim); err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete network ResourceClaim %q: %w", claimName, err)
	}
	return nil
}
