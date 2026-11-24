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
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	resourcev1 "k8s.io/api/resource/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

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
					PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
						URL: "https://portal.sandbox-system.svc:8443",
						Auth: &sandboxv1beta1.SandboxPEPAuth{
							Type: sandboxv1beta1.SandboxPEPAuthTypePodCertificate,
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

	// 1. Verify standard Kubernetes DRA ResourceClaim created with versioned SandboxNetworkConfiguration.
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
	if got := claim.Spec.Devices.Requests[0].Exactly.DeviceClassName; got != sandboxv1beta1.AgentsNetDriverName {
		t.Fatalf("deviceClassName = %q, want %q", got, sandboxv1beta1.AgentsNetDriverName)
	}
	if len(claim.Spec.Devices.Config) != 1 || claim.Spec.Devices.Config[0].Opaque == nil {
		t.Fatalf("expected OpaqueDeviceConfiguration in ResourceClaim")
	}
	if got := claim.Spec.Devices.Config[0].Opaque.Driver; got != sandboxv1beta1.AgentsNetDriverName {
		t.Fatalf("opaque driver = %q, want %q", got, sandboxv1beta1.AgentsNetDriverName)
	}
	var decoded sandboxv1beta1.SandboxNetworkConfiguration
	if err := json.Unmarshal(claim.Spec.Devices.Config[0].Opaque.Parameters.Raw, &decoded); err != nil {
		t.Fatalf("unmarshal SandboxNetworkConfiguration: %v", err)
	}
	if decoded.APIVersion != sandboxv1beta1.GroupVersion.String() || decoded.Kind != sandboxv1beta1.SandboxNetworkConfigurationKind {
		t.Fatalf("unexpected TypeMeta: apiVersion=%q kind=%q", decoded.APIVersion, decoded.Kind)
	}
	if decoded.Network.PolicyEnforcementPoint.URL != "https://portal.sandbox-system.svc:8443" {
		t.Fatalf("unexpected decoded PEP: %+v", decoded.Network.PolicyEnforcementPoint)
	}
	if len(decoded.Network.Parameters) != 1 || decoded.Network.Parameters[0].Name != "tenant" || decoded.Network.Parameters[0].Value != "team-a" {
		t.Fatalf("unexpected decoded parameters: %+v", decoded.Network.Parameters)
	}

	// 2. Verify Pod has ResourceClaim ref and EnableServiceLinks=false, with NO driver sidecar/DNS/volume leaks.
	pod := &corev1.Pod{}
	if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
		t.Fatalf("get Pod: %v", err)
	}
	if pod.Spec.EnableServiceLinks == nil || *pod.Spec.EnableServiceLinks {
		t.Fatalf("expected EnableServiceLinks=false, got %v", pod.Spec.EnableServiceLinks)
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		t.Fatalf("expected AutomountServiceAccountToken=false, got %v", pod.Spec.AutomountServiceAccountToken)
	}
	if pod.Spec.DNSPolicy != "" || pod.Spec.DNSConfig != nil {
		t.Fatalf("controller must not inject driver-specific DNSConfig: policy=%q cfg=%+v", pod.Spec.DNSPolicy, pod.Spec.DNSConfig)
	}
	if len(pod.Spec.InitContainers) != 0 {
		t.Fatalf("controller must not inject driver sidecars, got %+v", pod.Spec.InitContainers)
	}
	if len(pod.Spec.Volumes) != 0 {
		t.Fatalf("controller must not inject driver projected volumes, got %+v", pod.Spec.Volumes)
	}
	if len(pod.Spec.ResourceClaims) != 1 || pod.Spec.ResourceClaims[0].ResourceClaimName == nil || *pod.Spec.ResourceClaims[0].ResourceClaimName != claim.Name {
		t.Fatalf("unexpected Pod ResourceClaims: %+v", pod.Spec.ResourceClaims)
	}
	if len(pod.Spec.Containers[0].Resources.Claims) != 1 || pod.Spec.Containers[0].Resources.Claims[0].Name != agentsNetClaimRefName {
		t.Fatalf("unexpected container claims: %+v", pod.Spec.Containers[0].Resources.Claims)
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

func TestSandboxReconcilerThirdPartyDriverAndDeviceClass(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		driverName  string
		className   string
		wantDriver  string
		wantClass   string
		sandboxName string
	}{
		{
			name:        "driverName only defaults deviceClassName to driverName",
			sandboxName: "sb-cni-default",
			driverName:  "dra.cni.example",
			wantDriver:  "dra.cni.example",
			wantClass:   "dra.cni.example",
		},
		{
			name:        "driverName with explicit deviceClassName profile",
			sandboxName: "sb-cni-strict",
			driverName:  "dra.cni.example",
			className:   "cni-strict-egress",
			wantDriver:  "dra.cni.example",
			wantClass:   "cni-strict-egress",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sb := &sandboxv1beta1.Sandbox{
				ObjectMeta: metav1.ObjectMeta{
					Name:      tc.sandboxName,
					Namespace: "default",
					UID:       types.UID("uid-" + tc.sandboxName),
				},
				Spec: sandboxv1beta1.SandboxSpec{
					SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
						PodTemplate: sandboxv1beta1.PodTemplate{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
							},
						},
						Network: &sandboxv1beta1.SandboxNetworkSpec{
							DriverName:      tc.driverName,
							DeviceClassName: tc.className,
							PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
								URL: "https://pep.corp:8443",
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

			r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: "default"}}
			if _, err := r.Reconcile(ctx, req); err != nil {
				t.Fatalf("Reconcile: %v", err)
			}

			claim := &resourcev1.ResourceClaim{}
			claimKey := types.NamespacedName{Name: networkResourceClaimName(sb.Name), Namespace: "default"}
			if err := cli.Get(ctx, claimKey, claim); err != nil {
				t.Fatalf("get ResourceClaim: %v", err)
			}
			if got := claim.Spec.Devices.Requests[0].Exactly.DeviceClassName; got != tc.wantClass {
				t.Fatalf("DeviceClassName = %q, want %q", got, tc.wantClass)
			}
			if got := claim.Spec.Devices.Config[0].Opaque.Driver; got != tc.wantDriver {
				t.Fatalf("Opaque.Driver = %q, want %q", got, tc.wantDriver)
			}

			var decoded sandboxv1beta1.SandboxNetworkConfiguration
			if err := json.Unmarshal(claim.Spec.Devices.Config[0].Opaque.Parameters.Raw, &decoded); err != nil {
				t.Fatalf("unmarshal SandboxNetworkConfiguration: %v", err)
			}
			if decoded.Network.DriverName != tc.wantDriver || decoded.Network.DeviceClassName != tc.wantClass {
				t.Fatalf("decoded driver/class = (%q, %q), want (%q, %q)",
					decoded.Network.DriverName, decoded.Network.DeviceClassName, tc.wantDriver, tc.wantClass)
			}
		})
	}
}

func TestSandboxReconcilerRejectsInvalidNetworkConfig(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name string
		sb   *sandboxv1beta1.Sandbox
	}{
		{
			name: "service=true under PodNetworkIsolated",
			sb: &sandboxv1beta1.Sandbox{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-svc", Namespace: "default", UID: "sb-uid-bad-svc"},
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
							PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
								URL: "https://pep.corp:8443",
							},
						},
					},
					OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
				},
			},
		},
		{
			name: "hostNetwork=true when spec.network is configured",
			sb: &sandboxv1beta1.Sandbox{
				ObjectMeta: metav1.ObjectMeta{Name: "bad-hostnet", Namespace: "default", UID: "sb-uid-bad-hostnet"},
				Spec: sandboxv1beta1.SandboxSpec{
					SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
						PodTemplate: sandboxv1beta1.PodTemplate{
							Spec: corev1.PodSpec{
								HostNetwork: true,
								Containers:  []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
							},
						},
						Network: &sandboxv1beta1.SandboxNetworkSpec{
							ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
							PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
								URL: "https://pep.corp:8443",
							},
						},
					},
					OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
				},
			},
		},
		{
			name: "missing required policyEnforcementPoint.url",
			sb: &sandboxv1beta1.Sandbox{
				ObjectMeta: metav1.ObjectMeta{Name: "missing-pep", Namespace: "default", UID: "sb-uid-missing-pep"},
				Spec: sandboxv1beta1.SandboxSpec{
					SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
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
			},
		},
		{
			name: "opaque parameters exceed DRA 10 KiB limit",
			sb: &sandboxv1beta1.Sandbox{
				ObjectMeta: metav1.ObjectMeta{Name: "oversize-net", Namespace: "default", UID: "sb-uid-oversize"},
				Spec: sandboxv1beta1.SandboxSpec{
					SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
						PodTemplate: sandboxv1beta1.PodTemplate{
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
							},
						},
						Network: &sandboxv1beta1.SandboxNetworkSpec{
							PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
								URL: "https://pep.corp:8443",
							},
							Parameters: func() []sandboxv1beta1.SandboxNetworkParameter {
								out := make([]sandboxv1beta1.SandboxNetworkParameter, 20)
								for i := range out {
									out[i] = sandboxv1beta1.SandboxNetworkParameter{
										Name:  strings.Repeat("k", 20) + string(rune('a'+i)),
										Value: strings.Repeat("v", 800),
									}
								}
								return out
							}(),
						},
					},
					OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cli := fake.NewClientBuilder().
				WithScheme(Scheme).
				WithIndex(&corev1.Pod{}, podSandboxNameHashIndex, podSandboxNameHashIndexer).
				WithObjects(tc.sb).
				WithStatusSubresource(&sandboxv1beta1.Sandbox{}).
				Build()

			r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
			req := ctrl.Request{NamespacedName: types.NamespacedName{Name: tc.sb.Name, Namespace: tc.sb.Namespace}}
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
		})
	}
}

func TestApplySandboxNetworkPodSpecIdempotentMultiContainer(t *testing.T) {
	netSpec := &sandboxv1beta1.SandboxNetworkSpec{
		ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
		PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
			URL: "https://pep.corp:8443",
		},
	}
	podSpec := &corev1.PodSpec{
		InitContainers: []corev1.Container{
			{Name: "init-setup", Image: "example.com/init:v1"},
		},
		Containers: []corev1.Container{
			{Name: "agent", Image: "example.com/agent:v1"},
			{Name: "helper", Image: "example.com/helper:v1"},
		},
		ResourceClaims: []corev1.PodResourceClaim{
			{Name: agentsNetClaimRefName, ResourceClaimTemplateName: new("stale-template")},
		},
	}

	// Call twice to assert idempotency (ApplySandboxSecureDefaults + SandboxReconciler).
	ApplySandboxNetworkPodSpec(netSpec, podSpec, "")
	ApplySandboxNetworkPodSpec(netSpec, podSpec, "sb-1-network")
	ApplySandboxNetworkPodSpec(netSpec, podSpec, "sb-1-network")

	if podSpec.EnableServiceLinks == nil || *podSpec.EnableServiceLinks {
		t.Fatalf("expected EnableServiceLinks=false")
	}
	if podSpec.AutomountServiceAccountToken == nil || *podSpec.AutomountServiceAccountToken {
		t.Fatalf("expected AutomountServiceAccountToken=false")
	}
	if len(podSpec.InitContainers) != 1 {
		t.Fatalf("must not inject extra initContainers, got %d", len(podSpec.InitContainers))
	}
	if len(podSpec.InitContainers[0].Resources.Claims) != 1 || podSpec.InitContainers[0].Resources.Claims[0].Name != agentsNetClaimRefName {
		t.Fatalf("initContainer claims = %+v, want single %q", podSpec.InitContainers[0].Resources.Claims, agentsNetClaimRefName)
	}
	if len(podSpec.ResourceClaims) != 1 || podSpec.ResourceClaims[0].ResourceClaimName == nil || *podSpec.ResourceClaims[0].ResourceClaimName != "sb-1-network" || podSpec.ResourceClaims[0].ResourceClaimTemplateName != nil {
		t.Fatalf("unexpected ResourceClaims: %+v", podSpec.ResourceClaims)
	}
	for _, c := range podSpec.Containers {
		if len(c.Resources.Claims) != 1 || c.Resources.Claims[0].Name != agentsNetClaimRefName {
			t.Fatalf("container %q claims = %+v, want single %q", c.Name, c.Resources.Claims, agentsNetClaimRefName)
		}
	}
}

func TestSandboxReconcilerDenyAllNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	const ns = "default"

	t.Run("standalone Sandbox creates, heals, retains while terminating, and cleans up deny-all NetworkPolicy", func(t *testing.T) {
		sb := &sandboxv1beta1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sb-deny-all",
				Namespace: ns,
				UID:       types.UID("uid-sb-deny-all"),
			},
			Spec: sandboxv1beta1.SandboxSpec{
				SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
					PodTemplate: sandboxv1beta1.PodTemplate{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
						},
					},
					Network: &sandboxv1beta1.SandboxNetworkSpec{
						ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
						PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
							URL: "https://pep.corp:8443",
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

		r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile initial: %v", err)
		}

		npKey := types.NamespacedName{Name: networkPolicyName(sb.Name), Namespace: ns}
		np := &networkingv1.NetworkPolicy{}
		if err := cli.Get(ctx, npKey, np); err != nil {
			t.Fatalf("expected deny-all NetworkPolicy: %v", err)
		}
		if !metav1.IsControlledBy(np, sb) {
			t.Fatalf("NetworkPolicy not controlled by Sandbox")
		}
		wantHash := NameHash(sb.Name)
		if got := np.Spec.PodSelector.MatchLabels[sandboxv1beta1.SandboxNameHashLabel]; got != wantHash {
			t.Fatalf("PodSelector hash = %q, want %q", got, wantHash)
		}
		if len(np.Spec.PolicyTypes) != 2 || len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 {
			t.Fatalf("expected strict deny-all PolicyTypes=[Ingress,Egress] with empty rules, got %+v", np.Spec)
		}

		// Drift healing: tampered rules and stripped tracking label are both restored.
		np.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{}}
		delete(np.Labels, sandboxv1beta1.SandboxNameHashLabel)
		if err := cli.Update(ctx, np); err != nil {
			t.Fatalf("tamper NetworkPolicy: %v", err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile drift heal: %v", err)
		}
		healed := &networkingv1.NetworkPolicy{}
		if err := cli.Get(ctx, npKey, healed); err != nil {
			t.Fatalf("get healed NetworkPolicy: %v", err)
		}
		if len(healed.Spec.Egress) != 0 || len(healed.Spec.Ingress) != 0 {
			t.Fatalf("expected drifted NetworkPolicy rules to be reverted, got %+v", healed.Spec)
		}
		if got := healed.Labels[sandboxv1beta1.SandboxNameHashLabel]; got != wantHash {
			t.Fatalf("expected stripped tracking label to be healed to %q, got %q", wantHash, got)
		}

		// Add a finalizer on the Pod so suspending leaves it Terminating; NetworkPolicy must stay until Pod is gone.
		pod := &corev1.Pod{}
		if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
			t.Fatalf("get Pod: %v", err)
		}
		pod.Finalizers = []string{"test.example/hold-termination"}
		if err := cli.Update(ctx, pod); err != nil {
			t.Fatalf("add Pod finalizer: %v", err)
		}

		updated := &sandboxv1beta1.Sandbox{}
		if err := cli.Get(ctx, req.NamespacedName, updated); err != nil {
			t.Fatalf("get Sandbox: %v", err)
		}
		updated.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeSuspended
		if err := cli.Update(ctx, updated); err != nil {
			t.Fatalf("suspend Sandbox: %v", err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile suspended while Pod terminating: %v", err)
		}
		if err := cli.Get(ctx, npKey, &networkingv1.NetworkPolicy{}); err != nil {
			t.Fatalf("expected NetworkPolicy to remain while Pod is still terminating, got %v", err)
		}

		// Finish Pod termination and reconcile again; NetworkPolicy should now be deleted.
		if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
			t.Fatalf("get terminating Pod: %v", err)
		}
		pod.Finalizers = nil
		if err := cli.Update(ctx, pod); err != nil {
			t.Fatalf("clear Pod finalizer: %v", err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile suspended after Pod gone: %v", err)
		}
		if err := cli.Get(ctx, npKey, &networkingv1.NetworkPolicy{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("expected NetworkPolicy deleted once Pod terminated, got err=%v", err)
		}
	})

	t.Run("template-backed Sandbox skips per-Sandbox NetworkPolicy", func(t *testing.T) {
		sb := &sandboxv1beta1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sb-from-template",
				Namespace: ns,
				UID:       types.UID("uid-sb-from-template"),
				Labels: map[string]string{
					sandboxv1beta1.SandboxTemplateRefHashLabel: "deadbeef",
				},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: "extensions.agents.x-k8s.io/v1beta1",
						Kind:       "SandboxClaim",
						Name:       "claim-1",
						UID:        types.UID("claim-uid-1"),
						Controller: new(true),
					},
				},
			},
			Spec: sandboxv1beta1.SandboxSpec{
				SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
					PodTemplate: sandboxv1beta1.PodTemplate{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
						},
					},
					Network: &sandboxv1beta1.SandboxNetworkSpec{
						ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
						PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
							URL: "https://pep.corp:8443",
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

		r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile template-backed Sandbox: %v", err)
		}
		npKey := types.NamespacedName{Name: networkPolicyName(sb.Name), Namespace: ns}
		if err := cli.Get(ctx, npKey, &networkingv1.NetworkPolicy{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("template-backed Sandbox must not create duplicate per-Sandbox NetworkPolicy, got err=%v", err)
		}
	})

	t.Run("standalone Sandbox with spoofed template label still creates deny-all NetworkPolicy", func(t *testing.T) {
		sb := &sandboxv1beta1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sb-spoofed-label",
				Namespace: ns,
				UID:       types.UID("uid-sb-spoofed-label"),
				Labels: map[string]string{
					sandboxv1beta1.SandboxTemplateRefHashLabel: "spoofed",
				},
			},
			Spec: sandboxv1beta1.SandboxSpec{
				SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
					PodTemplate: sandboxv1beta1.PodTemplate{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
						},
					},
					Network: &sandboxv1beta1.SandboxNetworkSpec{
						ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
						PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
							URL: "https://pep.corp:8443",
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

		r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile standalone Sandbox with spoofed label: %v", err)
		}
		npKey := types.NamespacedName{Name: networkPolicyName(sb.Name), Namespace: ns}
		if err := cli.Get(ctx, npKey, &networkingv1.NetworkPolicy{}); err != nil {
			t.Fatalf("standalone Sandbox with spoofed template label must still create deny-all NetworkPolicy, got %v", err)
		}
	})

	t.Run("transient ResourceClaim error during Suspend still deletes Pod and retains NetworkPolicy", func(t *testing.T) {
		sb := &sandboxv1beta1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sb-suspend-err",
				Namespace: ns,
				UID:       types.UID("uid-sb-suspend-err"),
			},
			Spec: sandboxv1beta1.SandboxSpec{
				SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
					PodTemplate: sandboxv1beta1.PodTemplate{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
						},
					},
					Network: &sandboxv1beta1.SandboxNetworkSpec{
						ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
						PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
							URL: "https://pep.corp:8443",
						},
					},
				},
				OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
			},
		}

		failClaimDelete := false
		cli := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithIndex(&corev1.Pod{}, podSandboxNameHashIndex, podSandboxNameHashIndexer).
			WithObjects(sb).
			WithStatusSubresource(&sandboxv1beta1.Sandbox{}).
			WithInterceptorFuncs(interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					if failClaimDelete {
						if _, ok := obj.(*resourcev1.ResourceClaim); ok {
							return errors.New("injected transient ResourceClaim delete error")
						}
					}
					return c.Delete(ctx, obj, opts...)
				},
			}).
			Build()

		r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("initial Reconcile: %v", err)
		}

		// Hold Pod termination with a finalizer so it stays alive while suspending.
		pod := &corev1.Pod{}
		if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
			t.Fatalf("get Pod: %v", err)
		}
		pod.Finalizers = []string{"test.example/hold"}
		if err := cli.Update(ctx, pod); err != nil {
			t.Fatalf("add Pod finalizer: %v", err)
		}

		updated := &sandboxv1beta1.Sandbox{}
		if err := cli.Get(ctx, req.NamespacedName, updated); err != nil {
			t.Fatalf("get Sandbox: %v", err)
		}
		updated.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeSuspended
		if err := cli.Update(ctx, updated); err != nil {
			t.Fatalf("suspend Sandbox: %v", err)
		}

		failClaimDelete = true
		if _, err := r.Reconcile(ctx, req); err == nil {
			t.Fatalf("expected transient ResourceClaim delete error")
		}

		// Pod must still be observed & terminating, NetworkPolicy must remain, and Suspended must NOT be True.
		if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
			t.Fatalf("get Pod after failed suspend claim delete: %v", err)
		}
		if pod.DeletionTimestamp.IsZero() {
			t.Fatalf("expected Pod deletion to be initiated despite ResourceClaim delete error")
		}
		npKey := types.NamespacedName{Name: networkPolicyName(sb.Name), Namespace: ns}
		if err := cli.Get(ctx, npKey, &networkingv1.NetworkPolicy{}); err != nil {
			t.Fatalf("expected deny-all NetworkPolicy to remain while Pod is terminating, got %v", err)
		}
		if err := cli.Get(ctx, req.NamespacedName, updated); err != nil {
			t.Fatalf("get updated Sandbox: %v", err)
		}
		suspCond := meta.FindStatusCondition(updated.Status.Conditions, string(sandboxv1beta1.SandboxConditionSuspended))
		if suspCond == nil || suspCond.Status == metav1.ConditionTrue {
			t.Fatalf("expected Suspended!=True while Pod is terminating, got %+v", suspCond)
		}
	})

	t.Run("terminating ResourceClaim blocks new Pod creation on resume", func(t *testing.T) {
		sb := &sandboxv1beta1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sb-terminating-claim",
				Namespace: ns,
				UID:       types.UID("uid-sb-terminating-claim"),
			},
			Spec: sandboxv1beta1.SandboxSpec{
				SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
					PodTemplate: sandboxv1beta1.PodTemplate{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
						},
					},
					Network: &sandboxv1beta1.SandboxNetworkSpec{
						ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
						PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
							URL: "https://pep.corp:8443",
						},
					},
				},
				OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
			},
		}
		now := metav1.Now()
		termClaim := &resourcev1.ResourceClaim{
			ObjectMeta: metav1.ObjectMeta{
				Name:              networkResourceClaimName(sb.Name),
				Namespace:         ns,
				DeletionTimestamp: &now,
				Finalizers:        []string{"resource.kubernetes.io/delete-protection"},
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: sandboxv1beta1.GroupVersion.String(),
						Kind:       "Sandbox",
						Name:       sb.Name,
						UID:        sb.UID,
						Controller: new(true),
					},
				},
			},
		}

		cli := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithIndex(&corev1.Pod{}, podSandboxNameHashIndex, podSandboxNameHashIndexer).
			WithObjects(sb, termClaim).
			WithStatusSubresource(&sandboxv1beta1.Sandbox{}).
			Build()

		r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
		if _, err := r.Reconcile(ctx, req); err == nil {
			t.Fatalf("expected error waiting for terminating ResourceClaim")
		}
		if err := cli.Get(ctx, req.NamespacedName, &corev1.Pod{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("Pod must not be created against a terminating ResourceClaim, got err=%v", err)
		}
	})

	t.Run("expired standalone Sandbox with ShutdownPolicyDelete waits for Pod termination", func(t *testing.T) {
		past := metav1.NewTime(time.Now().Add(-time.Minute))
		delPolicy := sandboxv1beta1.ShutdownPolicyDelete
		sb := &sandboxv1beta1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sb-expiry-delete",
				Namespace: ns,
				UID:       types.UID("uid-sb-expiry-delete"),
			},
			Spec: sandboxv1beta1.SandboxSpec{
				SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
					PodTemplate: sandboxv1beta1.PodTemplate{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
						},
					},
					Network: &sandboxv1beta1.SandboxNetworkSpec{
						ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
						PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
							URL: "https://pep.corp:8443",
						},
					},
				},
				OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
				Lifecycle: sandboxv1beta1.Lifecycle{
					ShutdownPolicy: &delPolicy,
				},
			},
		}

		cli := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithIndex(&corev1.Pod{}, podSandboxNameHashIndex, podSandboxNameHashIndexer).
			WithObjects(sb).
			WithStatusSubresource(&sandboxv1beta1.Sandbox{}).
			Build()

		r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("initial Reconcile: %v", err)
		}

		pod := &corev1.Pod{}
		if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
			t.Fatalf("get Pod: %v", err)
		}
		pod.Finalizers = []string{"test.example/hold-expiry"}
		if err := cli.Update(ctx, pod); err != nil {
			t.Fatalf("add Pod finalizer: %v", err)
		}

		// Expire the Sandbox.
		updated := &sandboxv1beta1.Sandbox{}
		if err := cli.Get(ctx, req.NamespacedName, updated); err != nil {
			t.Fatalf("get Sandbox: %v", err)
		}
		updated.Spec.ShutdownTime = &past
		if err := cli.Update(ctx, updated); err != nil {
			t.Fatalf("set ShutdownTime: %v", err)
		}

		// Pass 1 marks SandboxExpired; Pass 2 runs handleSandboxExpiry.
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile mark expired: %v", err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile expiry while Pod terminating: %v", err)
		}

		// Sandbox and deny-all NetworkPolicy must still exist while Pod holds finalizer.
		if err := cli.Get(ctx, req.NamespacedName, &sandboxv1beta1.Sandbox{}); err != nil {
			t.Fatalf("expected Sandbox to wait for Pod termination before deleting, got %v", err)
		}
		npKey := types.NamespacedName{Name: networkPolicyName(sb.Name), Namespace: ns}
		if err := cli.Get(ctx, npKey, &networkingv1.NetworkPolicy{}); err != nil {
			t.Fatalf("expected deny-all NetworkPolicy to remain during Pod termination, got %v", err)
		}

		// Release Pod finalizer; next reconcile deletes Sandbox cleanly.
		if err := cli.Get(ctx, req.NamespacedName, pod); err != nil {
			t.Fatalf("get terminating Pod: %v", err)
		}
		pod.Finalizers = nil
		if err := cli.Update(ctx, pod); err != nil {
			t.Fatalf("clear Pod finalizer: %v", err)
		}
		if _, err := r.Reconcile(ctx, req); err != nil {
			t.Fatalf("Reconcile expiry after Pod gone: %v", err)
		}
		if err := cli.Get(ctx, req.NamespacedName, &sandboxv1beta1.Sandbox{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("expected Sandbox deleted once Pod terminated, got err=%v", err)
		}
	})

	t.Run("unowned NetworkPolicy blocks Pod creation", func(t *testing.T) {
		sb := &sandboxv1beta1.Sandbox{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "sb-np-conflict",
				Namespace: ns,
				UID:       types.UID("uid-sb-np-conflict"),
			},
			Spec: sandboxv1beta1.SandboxSpec{
				SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
					PodTemplate: sandboxv1beta1.PodTemplate{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
						},
					},
					Network: &sandboxv1beta1.SandboxNetworkSpec{
						ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
						PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
							URL: "https://pep.corp:8443",
						},
					},
				},
				OperatingMode: sandboxv1beta1.SandboxOperatingModeRunning,
			},
		}
		unownedNP := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      networkPolicyName(sb.Name),
				Namespace: ns,
			},
		}

		cli := fake.NewClientBuilder().
			WithScheme(Scheme).
			WithIndex(&corev1.Pod{}, podSandboxNameHashIndex, podSandboxNameHashIndexer).
			WithObjects(sb, unownedNP).
			WithStatusSubresource(&sandboxv1beta1.Sandbox{}).
			Build()

		r := &SandboxReconciler{Client: cli, Scheme: Scheme, Tracer: asmetrics.NewNoOp()}
		req := ctrl.Request{NamespacedName: types.NamespacedName{Name: sb.Name, Namespace: ns}}
		if _, err := r.Reconcile(ctx, req); err == nil {
			t.Fatalf("expected ownership conflict error for unowned NetworkPolicy")
		}
		if err := cli.Get(ctx, req.NamespacedName, &corev1.Pod{}); !k8serrors.IsNotFound(err) {
			t.Fatalf("Pod must not be created when deny-all NetworkPolicy conflicts, got err=%v", err)
		}
	})
}

func TestSandboxChildResourceNameDottedTruncation(t *testing.T) {
	// Place a dot right at the truncation boundary (maxPrefix = 63 - 8 - 1 - 8 = 46 for "-network",
	// and 63 - 15 - 1 - 8 = 39 for "-network-policy").
	dottedName := strings.Repeat("a", 38) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 20)
	for _, name := range []string{
		networkResourceClaimName(dottedName),
		networkPolicyName(dottedName),
	} {
		if len(name) > 63 {
			t.Fatalf("child resource name %q exceeds 63 chars (%d)", name, len(name))
		}
		if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
			t.Fatalf("child resource name %q is not a valid DNS-1123 subdomain: %v", name, errs)
		}
		if strings.Contains(name, ".-") || strings.Contains(name, "-.") {
			t.Fatalf("child resource name %q contains invalid dot-hyphen sequence", name)
		}
	}
}
