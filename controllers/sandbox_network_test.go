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
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
	resourcev1 "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	asmetrics "sigs.k8s.io/agent-sandbox/internal/metrics"
)

func TestSandboxReconcilerNetworkResourceClaimAndPodPlumbing(t *testing.T) {
	ctx := t.Context()
	const ns = "agents"

	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "agent-net",
			Namespace: ns,
			UID:       "sb-uid-1",
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: sandboxv1beta1.PodTemplate{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{
							{Name: "agent", Image: "example.com/agent:v1"},
						},
					},
				},
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeTunSidecar,
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						Address:  "https://portal.sandbox-system.svc:8443",
						Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP2,
						Auth: &sandboxv1beta1.SandboxUpstreamAuth{
							Type: sandboxv1beta1.SandboxUpstreamAuthTypePodCertificate,
							PodCertificate: &sandboxv1beta1.SandboxPodCertificateAuth{
								SignerName: "spiffe.io/workload-identity",
								KeyType:    sandboxv1beta1.SandboxPodCertificateKeyTypeECDSAP256,
							},
						},
					},
					Parameters: []sandboxv1beta1.SandboxNetworkParameter{
						{Name: "tenant", Value: "team-a"},
					},
				},
			},
			OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithIndex(&corev1.Pod{}, podSandboxNameHashIndex, podSandboxNameHashIndexer).
		WithObjects(sb).
		WithStatusSubresource(&sandboxv1beta1.Sandbox{}).
		Build()

	r := &SandboxReconciler{
		Client: cli,
		Scheme: Scheme,
		Tracer: asmetrics.NewNoOp(),
	}

	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile running: %v", err)
	}

	// 1. Verify standard Kubernetes DRA ResourceClaim created with Opaque parameters.
	claim := &resourcev1.ResourceClaim{}
	claimKey := types.NamespacedName{Name: networkResourceClaimName(sb.Name), Namespace: ns}
	if err := cli.Get(ctx, claimKey, claim); err != nil {
		t.Fatalf("get ResourceClaim: %v", err)
	}
	if !metav1.IsControlledBy(claim, sb) {
		t.Fatalf("ResourceClaim not controlled by Sandbox")
	}
	if len(claim.Spec.Devices.Requests) != 1 || claim.Spec.Devices.Requests[0].Exactly == nil {
		t.Fatalf("unexpected device requests: %+v", claim.Spec.Devices.Requests)
	}
	if got := claim.Spec.Devices.Requests[0].Exactly.DeviceClassName; got != sandboxv1beta1.DefaultSandboxNetDeviceClassName {
		t.Fatalf("deviceClassName = %q, want %q", got, sandboxv1beta1.DefaultSandboxNetDeviceClassName)
	}
	if len(claim.Spec.Devices.Config) != 1 || claim.Spec.Devices.Config[0].Opaque == nil {
		t.Fatalf("expected OpaqueDeviceConfiguration in ResourceClaim")
	}
	var decoded draOpaqueNetworkParameters
	if err := json.Unmarshal(claim.Spec.Devices.Config[0].Opaque.Parameters.Raw, &decoded); err != nil {
		t.Fatalf("unmarshal opaque parameters: %v", err)
	}
	if decoded.Upstream == nil || decoded.Upstream.Address != "https://portal.sandbox-system.svc:8443" {
		t.Fatalf("unexpected decoded upstream: %+v", decoded.Upstream)
	}
	if decoded.PodCertVolumeName != sandboxv1beta1.SandboxNetPodCertVolumeName {
		t.Fatalf("podCertVolumeName = %q, want %q", decoded.PodCertVolumeName, sandboxv1beta1.SandboxNetPodCertVolumeName)
	}
	if decoded.Custom["tenant"] != "team-a" {
		t.Fatalf("custom[tenant] = %q, want team-a", decoded.Custom["tenant"])
	}

	// 2. Verify Pod has tun2connect sidecar, ResourceClaim ref, and isolated PodCertificate volume.
	pod := &corev1.Pod{}
	if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
		t.Fatalf("get Pod: %v", err)
	}
	if pod.Spec.DNSPolicy != corev1.DNSNone || pod.Spec.DNSConfig == nil || len(pod.Spec.DNSConfig.Nameservers) != 1 || pod.Spec.DNSConfig.Nameservers[0] != Tun2ConnectVirtualDNSAddr {
		t.Fatalf("unexpected Pod DNS config: policy=%q cfg=%+v", pod.Spec.DNSPolicy, pod.Spec.DNSConfig)
	}
	if len(pod.Spec.ResourceClaims) != 1 || pod.Spec.ResourceClaims[0].ResourceClaimName == nil || *pod.Spec.ResourceClaims[0].ResourceClaimName != claim.Name {
		t.Fatalf("unexpected Pod ResourceClaims: %+v", pod.Spec.ResourceClaims)
	}
	if len(pod.Spec.InitContainers) != 1 || pod.Spec.InitContainers[0].Name != Tun2ConnectSidecarName {
		t.Fatalf("expected single tun2connect native sidecar, got %+v", pod.Spec.InitContainers)
	}
	sidecar := pod.Spec.InitContainers[0]
	if len(sidecar.VolumeMounts) != 1 || sidecar.VolumeMounts[0].Name != sandboxv1beta1.SandboxNetPodCertVolumeName {
		t.Fatalf("expected PodCertificate volume mounted on tun2connect sidecar, got %+v", sidecar.VolumeMounts)
	}
	// Critical security invariant: untrusted workload container MUST NOT mount the credential volume.
	if len(pod.Spec.Containers[0].VolumeMounts) != 0 {
		t.Fatalf("workload container must not receive PodCertificate mount, got %+v", pod.Spec.Containers[0].VolumeMounts)
	}

	// 3. Simulate Pod Running+Ready with NodeName and empty PodIPs (PodNetworkIsolated).
	pod.Spec.NodeName = "node-1"
	if err := cli.Update(ctx, pod); err != nil {
		t.Fatalf("update Pod spec: %v", err)
	}
	pod.Status.Phase = corev1.PodRunning
	pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	if err := cli.Status().Update(ctx, pod); err != nil {
		t.Fatalf("update Pod status: %v", err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile ready: %v", err)
	}

	updated := &sandboxv1beta1.Sandbox{}
	if err := cli.Get(ctx, req.NamespacedName, updated); err != nil {
		t.Fatalf("get Sandbox: %v", err)
	}
	ready := meta.FindStatusCondition(updated.Status.Conditions, string(sandboxv1beta1.SandboxConditionReady))
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Fatalf("expected PodNetworkIsolated Sandbox Ready=True without PodIPs, got %+v", ready)
	}

	// 4. Suspending Sandbox releases its DRA ResourceClaim cleanly.
	updated.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeSuspended
	if err := cli.Update(ctx, updated); err != nil {
		t.Fatalf("suspend Sandbox: %v", err)
	}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("Reconcile suspended: %v", err)
	}
	if err := cli.Get(ctx, claimKey, &resourcev1.ResourceClaim{}); err == nil {
		t.Fatalf("expected DRA ResourceClaim to be deleted while Sandbox is suspended")
	}
}

func TestSandboxReconcilerRejectsServiceUnderPodNetworkIsolated(t *testing.T) {
	ctx := t.Context()
	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "bad-svc",
			Namespace: "default",
			UID:       "sb-uid-bad",
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				Service: new(true),
				PodTemplate: sandboxv1beta1.PodTemplate{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
					},
				},
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
				},
			},
			OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(Scheme).
		WithIndex(&corev1.Pod{}, podSandboxNameHashIndex, podSandboxNameHashIndexer).
		WithObjects(sb).
		WithStatusSubresource(&sandboxv1beta1.Sandbox{}).
		Build()

	r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
	req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: sb.Namespace}}
	if _, err := r.Reconcile(ctx, req); err != nil {
		t.Fatalf("expected InvalidConfiguration not to requeue with error, got %v", err)
	}

	updated := &sandboxv1beta1.Sandbox{}
	if err := cli.Get(ctx, req.NamespacedName, updated); err != nil {
		t.Fatalf("get Sandbox: %v", err)
	}
	ready := meta.FindStatusCondition(updated.Status.Conditions, string(sandboxv1beta1.SandboxConditionReady))
	if ready == nil || ready.Status != metav1.ConditionFalse || ready.Reason != sandboxv1beta1.SandboxReasonInvalidConfiguration {
		t.Fatalf("expected Ready=False/InvalidConfiguration, got %+v", ready)
	}
}

func TestApplySandboxNetworkPodSpecSATokenPodModeIsolation(t *testing.T) {
	netSpec := &sandboxv1beta1.SandboxNetworkSpec{
		AdapterMode: sandboxv1beta1.SandboxAdapterModeTunSidecar,
		Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
			Address: "https://portal.corp:8443",
			Auth: &sandboxv1beta1.SandboxUpstreamAuth{
				Type: sandboxv1beta1.SandboxUpstreamAuthTypeServiceAccountToken,
				ServiceAccountToken: &sandboxv1beta1.SandboxServiceAccountTokenAuth{
					Audience: "https://portal.corp",
					Mode:     sandboxv1beta1.SandboxServiceAccountTokenModePod,
				},
			},
		},
	}
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
	}

	// Call twice to assert idempotency (ApplySandboxSecureDefaults + SandboxReconciler).
	ApplySandboxNetworkPodSpec(netSpec, podSpec, "")
	ApplySandboxNetworkPodSpec(netSpec, podSpec, "sb-1-network")

	if len(podSpec.InitContainers) != 1 {
		t.Fatalf("expected 1 initContainer after idempotent apply, got %d", len(podSpec.InitContainers))
	}
	if len(podSpec.Volumes) != 1 || podSpec.Volumes[0].Name != sandboxv1beta1.SandboxNetSATokenVolumeName {
		t.Fatalf("expected 1 projected SA token volume, got %+v", podSpec.Volumes)
	}
	if len(podSpec.InitContainers[0].VolumeMounts) != 1 {
		t.Fatalf("expected SA token mounted on tun2connect sidecar")
	}
	if len(podSpec.Containers[0].VolumeMounts) != 0 {
		t.Fatalf("workload container must never mount SA token volume")
	}
}

func TestApplySandboxNetworkPodSpecExplicitProxyDNSConfig(t *testing.T) {
	netSpec := &sandboxv1beta1.SandboxNetworkSpec{
		ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
		AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
	}
	podSpec := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
	}

	ApplySandboxNetworkPodSpec(netSpec, podSpec, "sb-proxy-network")

	if podSpec.DNSPolicy != corev1.DNSNone {
		t.Fatalf("DNSPolicy = %q, want %q", podSpec.DNSPolicy, corev1.DNSNone)
	}
	if podSpec.DNSConfig == nil || len(podSpec.DNSConfig.Nameservers) == 0 || podSpec.DNSConfig.Nameservers[0] != "127.0.0.1" {
		t.Fatalf("DNSConfig.Nameservers = %+v, want [127.0.0.1] for Kubernetes dnsPolicy=None validation", podSpec.DNSConfig)
	}
	if len(podSpec.InitContainers) != 0 {
		t.Fatalf("ExplicitProxy must not inject tun2connect sidecar, got %d initContainers", len(podSpec.InitContainers))
	}
	if len(podSpec.ResourceClaims) != 1 || *podSpec.ResourceClaims[0].ResourceClaimName != "sb-proxy-network" {
		t.Fatalf("unexpected ResourceClaims: %+v", podSpec.ResourceClaims)
	}
}
