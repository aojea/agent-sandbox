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
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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
	// agentsNetClaimRefName is the pod-local name used in pod.Spec.ResourceClaims.
	agentsNetClaimRefName = sandboxv1beta1.AgentsNetPodClaimName

	// maxDRAOpaqueParametersBytes mirrors Kubernetes resource.k8s.io/v1
	// OpaqueDeviceConfiguration.Parameters' 10 KiB raw payload limit.
	maxDRAOpaqueParametersBytes = 10 * 1024
)

// effectiveNetworkDriverAndClass resolves the DRA driverName (defaulting to dra.agents.net)
// and DeviceClassName (defaulting to driverName when omitted).
func effectiveNetworkDriverAndClass(net *sandboxv1beta1.SandboxNetworkSpec) (string, string) {
	driverName := sandboxv1beta1.AgentsNetDriverName
	if net != nil && net.DriverName != "" {
		driverName = net.DriverName
	}
	deviceClassName := driverName
	if net != nil && net.DeviceClassName != "" {
		deviceClassName = net.DeviceClassName
	}
	return driverName, deviceClassName
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

// sandboxNeedsDenyAllNetworkPolicy reports whether the core Sandbox controller should
// reconcile a per-Sandbox deny-all NetworkPolicy. Template-backed Sandboxes owned by an
// extension controller carry SandboxTemplateRefHashLabel (which computeExtensionPodLabels
// propagates to the Pod) and share the single deny-all NetworkPolicy owned by their
// SandboxTemplate instead. Standalone Sandboxes without an extension owner always get a
// per-Sandbox deny-all NetworkPolicy even if a user manually sets SandboxTemplateRefHashLabel.
func sandboxNeedsDenyAllNetworkPolicy(sandbox *sandboxv1beta1.Sandbox) bool {
	if sandbox == nil || sandbox.Spec.Network == nil {
		return false
	}
	if sandbox.Spec.Network.ConfinementMode != sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll {
		return false
	}
	ref, _ := extensionOwner(sandbox)
	return ref == nil || sandbox.Labels[sandboxv1beta1.SandboxTemplateRefHashLabel] == ""
}

// networkResourceClaimName returns a deterministic DNS-1123 ResourceClaim name <= 63 chars.
func networkResourceClaimName(sandboxName string) string {
	return sandboxChildResourceName(sandboxName, "-network")
}

// networkPolicyName returns a deterministic DNS-1123 NetworkPolicy name <= 63 chars.
func networkPolicyName(sandboxName string) string {
	return sandboxChildResourceName(sandboxName, "-network-policy")
}

func sandboxChildResourceName(sandboxName, suffix string) string {
	if len(sandboxName)+len(suffix) <= 63 {
		return sandboxName + suffix
	}
	hash := NameHash(sandboxName)
	maxPrefix := 63 - len(suffix) - 1 - len(hash)
	if maxPrefix < 1 {
		return "sb-" + hash + suffix
	}
	prefix := strings.TrimRight(sandboxName[:maxPrefix], ".-")
	if prefix == "" {
		return "sb-" + hash + suffix
	}
	return prefix + "-" + hash + suffix
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
	if sandbox.Spec.PodTemplate.Spec.HostNetwork {
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "podTemplate", "spec", "hostNetwork"),
			true,
			"spec.podTemplate.spec.hostNetwork cannot be true when spec.network is configured",
		))
	}
	if strings.TrimSpace(net.PolicyEnforcementPoint.URL) == "" {
		errs = append(errs, field.Required(
			field.NewPath("spec", "network", "policyEnforcementPoint", "url"),
			"policyEnforcementPoint.url is required when spec.network is set",
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

// ApplySandboxNetworkPodSpec idempotently applies driver-agnostic PodSpec defaults
// (disabling legacy Kubernetes service link env vars and ServiceAccount token automounting)
// and, when claimName is non-empty, attaches the DRA ResourceClaim to the Pod and all
// containers (including initContainers). Driver-specific Pod mutations (such as sidecars,
// custom DNS, or projected credential volumes) belong to the network driver rather than
// the Sandbox controller.
func ApplySandboxNetworkPodSpec(net *sandboxv1beta1.SandboxNetworkSpec, spec *corev1.PodSpec, claimName string) {
	if net == nil || spec == nil {
		return
	}

	if spec.EnableServiceLinks == nil {
		spec.EnableServiceLinks = new(false)
	}
	if spec.AutomountServiceAccountToken == nil {
		spec.AutomountServiceAccountToken = new(false)
	}

	if claimName != "" {
		ensurePodResourceClaim(spec, claimName)
	}
}

func ensurePodResourceClaim(spec *corev1.PodSpec, claimName string) {
	foundPodClaim := false
	for i := range spec.ResourceClaims {
		if spec.ResourceClaims[i].Name == agentsNetClaimRefName {
			spec.ResourceClaims[i].ResourceClaimName = new(claimName)
			spec.ResourceClaims[i].ResourceClaimTemplateName = nil
			foundPodClaim = true
			break
		}
	}
	if !foundPodClaim {
		spec.ResourceClaims = append(spec.ResourceClaims, corev1.PodResourceClaim{
			Name:              agentsNetClaimRefName,
			ResourceClaimName: new(claimName),
		})
	}
	attachContainerClaim := func(containers []corev1.Container) {
		for i := range containers {
			hasClaim := false
			for _, c := range containers[i].Resources.Claims {
				if c.Name == agentsNetClaimRefName {
					hasClaim = true
					break
				}
			}
			if !hasClaim {
				containers[i].Resources.Claims = append(containers[i].Resources.Claims, corev1.ResourceClaim{
					Name: agentsNetClaimRefName,
				})
			}
		}
	}
	attachContainerClaim(spec.InitContainers)
	attachContainerClaim(spec.Containers)
}

// buildDRAOpaqueParameters embeds the Sandbox.spec.network stanza inside a versioned
// SandboxNetworkConfiguration JSON envelope so any Kubernetes Network Driver receives the
// portable specification directly in NodePrepareResources without GETting the Sandbox CR.
func buildDRAOpaqueParameters(sandbox *sandboxv1beta1.Sandbox) ([]byte, error) {
	netCopy := sandbox.Spec.Network.DeepCopy()
	driverName, deviceClassName := effectiveNetworkDriverAndClass(netCopy)
	netCopy.DriverName = driverName
	netCopy.DeviceClassName = deviceClassName
	if netCopy.ConfinementMode == "" {
		netCopy.ConfinementMode = sandboxv1beta1.SandboxConfinementModePodNetworkIsolated
	}

	payload := sandboxv1beta1.SandboxNetworkConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: sandboxv1beta1.GroupVersion.String(),
			Kind:       sandboxv1beta1.SandboxNetworkConfigurationKind,
		},
		Network: *netCopy,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDRAOpaqueParametersBytes {
		return nil, k8serrors.NewInvalid(
			schema.GroupKind{Group: sandboxv1beta1.GroupVersion.Group, Kind: "Sandbox"},
			sandbox.Name,
			field.ErrorList{
				field.TooLong(
					field.NewPath("spec", "network"),
					fmt.Sprintf("%d bytes", len(raw)),
					maxDRAOpaqueParametersBytes,
				),
			},
		)
	}
	return raw, nil
}

// reconcileNetworkResourceClaim ensures a controller-owned Kubernetes DRA ResourceClaim exists
// when sandbox.Spec.Network is configured and the Sandbox is Running. It deletes the owned
// claim while Suspended so the node DRA capacity share is released immediately.
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
		if !existing.DeletionTimestamp.IsZero() {
			return "", fmt.Errorf("waiting for terminating ResourceClaim %q to finish deletion before creating Pod", claimName)
		}
		return existing.Name, nil
	}
	if !k8serrors.IsNotFound(err) {
		return "", fmt.Errorf("failed to get network ResourceClaim %q: %w", claimName, err)
	}

	rawParams, err := buildDRAOpaqueParameters(sandbox)
	if err != nil {
		return "", err
	}

	driverName, deviceClassName := effectiveNetworkDriverAndClass(sandbox.Spec.Network)

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
						Name: agentsNetClaimRefName,
						Exactly: &resourcev1.ExactDeviceRequest{
							DeviceClassName: deviceClassName,
							AllocationMode:  resourcev1.DeviceAllocationModeExactCount,
							Count:           1,
						},
					},
				},
				Config: []resourcev1.DeviceClaimConfiguration{
					{
						Requests: []string{agentsNetClaimRefName},
						DeviceConfiguration: resourcev1.DeviceConfiguration{
							Opaque: &resourcev1.OpaqueDeviceConfiguration{
								Driver:     driverName,
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
		return "", fmt.Errorf("failed to create network ResourceClaim %q: %w", claimName, err)
	}
	log.FromContext(ctx).Info("Created DRA network ResourceClaim",
		"ResourceClaim.Namespace", claim.Namespace,
		"ResourceClaim.Name", claim.Name,
		"Driver", driverName,
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

// reconcileNetworkPolicy ensures a controller-owned deny-all NetworkPolicy exists before
// Pod creation for standalone Sandboxes using NetworkPolicyDenyAll confinement.
func (r *SandboxReconciler) reconcileNetworkPolicy(ctx context.Context, sandbox *sandboxv1beta1.Sandbox, nameHash string) error {
	if !sandboxNeedsDenyAllNetworkPolicy(sandbox) || sandbox.Spec.OperatingMode == sandboxv1beta1.SandboxOperatingModeSuspended {
		return nil
	}

	npName := networkPolicyName(sandbox.Name)
	desiredSpec := networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{
			MatchLabels: map[string]string{
				sandboxv1beta1.SandboxNameHashLabel: nameHash,
			},
		},
		PolicyTypes: []networkingv1.PolicyType{
			networkingv1.PolicyTypeIngress,
			networkingv1.PolicyTypeEgress,
		},
	}

	key := types.NamespacedName{Name: npName, Namespace: sandbox.Namespace}
	existing := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, key, existing)
	if err == nil {
		ownership, controllerRef := checkOwnership(existing, sandbox)
		if ownership != resourceOwnedBySandbox {
			ownerInfo := "unowned"
			if controllerRef != nil {
				ownerInfo = fmt.Sprintf("%s/%s", controllerRef.Kind, controllerRef.Name)
			}
			return fmt.Errorf("refusing to use NetworkPolicy %q owned by %s", npName, ownerInfo)
		}
		if !existing.DeletionTimestamp.IsZero() {
			return fmt.Errorf("waiting for terminating NetworkPolicy %q to finish deletion before creating Pod", npName)
		}
		needsUpdate := !equality.Semantic.DeepEqual(existing.Spec, desiredSpec)
		if existing.Labels[sandboxv1beta1.SandboxNameHashLabel] != nameHash {
			if existing.Labels == nil {
				existing.Labels = map[string]string{}
			}
			existing.Labels[sandboxv1beta1.SandboxNameHashLabel] = nameHash
			needsUpdate = true
		}
		if needsUpdate {
			existing.Spec = desiredSpec
			if err := r.Update(ctx, existing, client.FieldOwner(sandboxControllerFieldOwner)); err != nil {
				return fmt.Errorf("failed to update deny-all NetworkPolicy %q: %w", npName, err)
			}
			log.FromContext(ctx).Info("Updated deny-all NetworkPolicy",
				"NetworkPolicy.Namespace", existing.Namespace,
				"NetworkPolicy.Name", existing.Name,
			)
		}
		return nil
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed to get deny-all NetworkPolicy %q: %w", npName, err)
	}

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      npName,
			Namespace: sandbox.Namespace,
			Labels: map[string]string{
				sandboxv1beta1.SandboxNameHashLabel: nameHash,
			},
		},
		Spec: desiredSpec,
	}
	if err := ctrl.SetControllerReference(sandbox, np, r.Scheme); err != nil {
		return fmt.Errorf("SetControllerReference for NetworkPolicy failed: %w", err)
	}
	if err := r.Create(ctx, np, client.FieldOwner(sandboxControllerFieldOwner)); err != nil {
		return fmt.Errorf("failed to create deny-all NetworkPolicy %q: %w", npName, err)
	}
	log.FromContext(ctx).Info("Created deny-all NetworkPolicy",
		"NetworkPolicy.Namespace", np.Namespace,
		"NetworkPolicy.Name", np.Name,
	)
	return nil
}

func (r *SandboxReconciler) deleteNetworkPolicy(ctx context.Context, sandbox *sandboxv1beta1.Sandbox) error {
	if sandbox.Spec.Network == nil {
		return nil
	}
	npName := networkPolicyName(sandbox.Name)
	np := &networkingv1.NetworkPolicy{}
	if err := r.Get(ctx, types.NamespacedName{Name: npName, Namespace: sandbox.Namespace}, np); err != nil {
		if k8serrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get deny-all NetworkPolicy %q: %w", npName, err)
	}
	if ownership, _ := checkOwnership(np, sandbox); ownership != resourceOwnedBySandbox {
		return nil
	}
	if err := r.Delete(ctx, np); err != nil && !k8serrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete deny-all NetworkPolicy %q: %w", npName, err)
	}
	return nil
}
