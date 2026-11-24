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
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsv1beta1 "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
	asmetrics "sigs.k8s.io/agent-sandbox/internal/metrics"
)

func TestSandboxTemplateNetworkPolicyConfinementModes(t *testing.T) {
	ctx := t.Context()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add core scheme: %v", err)
	}
	if err := sandboxv1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("add sandbox scheme: %v", err)
	}
	if err := extensionsv1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("add extensions scheme: %v", err)
	}

	tmplCompat := &extensionsv1beta1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "compat-tmpl", Namespace: "default", UID: "tmpl-1"},
		Spec: extensionsv1beta1.SandboxTemplateSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: sandboxv1beta1.PodTemplate{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
					},
				},
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
						URL: "https://portal.sandbox-system.svc:8443",
					},
				},
			},
		},
	}

	tmplIsolated := &extensionsv1beta1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "iso-tmpl", Namespace: "default", UID: "tmpl-2"},
		Spec: extensionsv1beta1.SandboxTemplateSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: sandboxv1beta1.PodTemplate{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
					},
				},
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
					PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
						URL: "https://portal.sandbox-system.svc:8443",
					},
				},
			},
		},
	}

	tmplCompatUnmanaged := &extensionsv1beta1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "compat-unmanaged-tmpl", Namespace: "default", UID: "tmpl-3"},
		Spec: extensionsv1beta1.SandboxTemplateSpec{
			NetworkPolicyManagement: extensionsv1beta1.NetworkPolicyManagementUnmanaged,
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: sandboxv1beta1.PodTemplate{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: "agent", Image: "example.com/agent:v1"}},
					},
				},
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
						URL: "https://portal.sandbox-system.svc:8443",
					},
				},
			},
		},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tmplCompat, tmplIsolated, tmplCompatUnmanaged).Build()
	r := &SandboxTemplateReconciler{Client: cli, Scheme: scheme, Tracer: asmetrics.NewNoOp()}

	// 1. NetworkPolicyDenyAll creates a strict deny-all NetworkPolicy (empty ingress & egress).
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: tmplCompat.Name, Namespace: "default"}}); err != nil {
		t.Fatalf("reconcile compat template: %v", err)
	}
	np := &networkingv1.NetworkPolicy{}
	if err := cli.Get(ctx, types.NamespacedName{Name: tmplCompat.Name + "-network-policy", Namespace: "default"}, np); err != nil {
		t.Fatalf("expected deny-all NetworkPolicy: %v", err)
	}
	if len(np.Spec.Ingress) != 0 || len(np.Spec.Egress) != 0 || len(np.Spec.PolicyTypes) != 2 {
		t.Fatalf("expected empty ingress/egress deny-all policy, got %+v", np.Spec)
	}

	// 1b. NetworkPolicyDenyAll enforces deny-all even if networkPolicyManagement=Unmanaged is set.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: tmplCompatUnmanaged.Name, Namespace: "default"}}); err != nil {
		t.Fatalf("reconcile compat-unmanaged template: %v", err)
	}
	npUnmanaged := &networkingv1.NetworkPolicy{}
	if err := cli.Get(ctx, types.NamespacedName{Name: tmplCompatUnmanaged.Name + "-network-policy", Namespace: "default"}, npUnmanaged); err != nil {
		t.Fatalf("expected deny-all NetworkPolicy despite Unmanaged setting: %v", err)
	}
	if len(npUnmanaged.Spec.Ingress) != 0 || len(npUnmanaged.Spec.Egress) != 0 || len(npUnmanaged.Spec.PolicyTypes) != 2 {
		t.Fatalf("expected empty ingress/egress deny-all policy, got %+v", npUnmanaged.Spec)
	}

	// 2. PodNetworkIsolated skips NetworkPolicy creation completely.
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: tmplIsolated.Name, Namespace: "default"}}); err != nil {
		t.Fatalf("reconcile isolated template: %v", err)
	}
	if err := cli.Get(ctx, types.NamespacedName{Name: tmplIsolated.Name + "-network-policy", Namespace: "default"}, &networkingv1.NetworkPolicy{}); err == nil {
		t.Fatalf("expected no NetworkPolicy for PodNetworkIsolated template")
	}

	// 3. ApplySandboxSecureDefaults disables automount/serviceLinks and skips legacy 8.8.8.8 DNS override
	// without injecting driver-specific sidecars or DNSConfig.
	podSpec := tmplIsolated.Spec.PodTemplate.Spec.DeepCopy()
	ApplySandboxSecureDefaults(tmplIsolated, podSpec)
	if podSpec.AutomountServiceAccountToken == nil || *podSpec.AutomountServiceAccountToken {
		t.Fatalf("expected automountServiceAccountToken=false")
	}
	if podSpec.EnableServiceLinks == nil || *podSpec.EnableServiceLinks {
		t.Fatalf("expected enableServiceLinks=false")
	}
	if podSpec.DNSConfig != nil || len(podSpec.InitContainers) != 0 {
		t.Fatalf("expected no driver-specific DNSConfig or sidecars, got dns=%+v init=%+v", podSpec.DNSConfig, podSpec.InitContainers)
	}
}

func TestSandboxMissingNetworkPlacement(t *testing.T) {
	iso := &sandboxv1beta1.Sandbox{
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
					PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
						URL: "https://portal.sandbox-system.svc:8443",
					},
				},
			},
		},
	}
	if !sandboxMissingNetworkPlacement(iso) {
		t.Fatalf("expected PodNetworkIsolated sandbox without NodeName to be pending placement")
	}
	iso.Status.NodeName = "worker-1"
	if sandboxMissingNetworkPlacement(iso) {
		t.Fatalf("expected PodNetworkIsolated sandbox with NodeName to be ready for adoption without PodIPs")
	}

	regular := &sandboxv1beta1.Sandbox{
		Status: sandboxv1beta1.SandboxStatus{NodeName: "worker-1"},
	}
	if !sandboxMissingNetworkPlacement(regular) {
		t.Fatalf("expected regular sandbox without PodIPs to still wait for PodIPs")
	}
}

func TestNormalizeSandboxNetworkDefaults(t *testing.T) {
	omitted := &sandboxv1beta1.SandboxNetworkSpec{
		PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
			URL: "https://pep.corp:8443",
			TLS: &sandboxv1beta1.SandboxPEPTLS{
				CACertificateRefs: []sandboxv1beta1.SandboxCASource{
					{Type: sandboxv1beta1.SandboxCASourceTypeConfigMap, ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: "pep-ca"}},
					{Type: sandboxv1beta1.SandboxCASourceTypeSecret, SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: "pep-sec"}},
				},
			},
			Auth: &sandboxv1beta1.SandboxPEPAuth{
				Type: sandboxv1beta1.SandboxPEPAuthTypeServiceAccountToken,
				ServiceAccountToken: &sandboxv1beta1.SandboxServiceAccountTokenAuth{
					Audience: "pep",
				},
			},
		},
		CATrust: &sandboxv1beta1.SandboxCATrustSpec{
			Sources: []sandboxv1beta1.SandboxCASource{
				{Type: sandboxv1beta1.SandboxCASourceTypeConfigMap, ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: "pod-ca"}},
				{Type: sandboxv1beta1.SandboxCASourceTypeSecret, SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: "pod-sec"}},
			},
		},
		IngressPorts: []sandboxv1beta1.SandboxIngressPort{{Port: 8888}},
	}
	explicit := &sandboxv1beta1.SandboxNetworkSpec{
		DriverName:      sandboxv1beta1.AgentsNetDriverName,
		DeviceClassName: sandboxv1beta1.AgentsNetDriverName,
		ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
		PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
			URL: "https://pep.corp:8443",
			TLS: &sandboxv1beta1.SandboxPEPTLS{
				CACertificateRefs: []sandboxv1beta1.SandboxCASource{
					{Type: sandboxv1beta1.SandboxCASourceTypeConfigMap, ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: "pep-ca", Key: "ca.crt"}},
					{Type: sandboxv1beta1.SandboxCASourceTypeSecret, SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: "pep-sec", Key: "ca.crt"}},
				},
			},
			Auth: &sandboxv1beta1.SandboxPEPAuth{
				Type: sandboxv1beta1.SandboxPEPAuthTypeServiceAccountToken,
				ServiceAccountToken: &sandboxv1beta1.SandboxServiceAccountTokenAuth{
					Audience:          "pep",
					Mode:              sandboxv1beta1.SandboxServiceAccountTokenModeNode,
					ExpirationSeconds: new(int32(3600)),
				},
			},
		},
		CATrust: &sandboxv1beta1.SandboxCATrustSpec{
			Mode:       sandboxv1beta1.SandboxCATrustModeInjectEnv,
			BundleMode: sandboxv1beta1.SandboxCABundleModeAppendSystemRoots,
			Sources: []sandboxv1beta1.SandboxCASource{
				{Type: sandboxv1beta1.SandboxCASourceTypeConfigMap, ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: "pod-ca", Key: "ca.crt"}},
				{Type: sandboxv1beta1.SandboxCASourceTypeSecret, SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: "pod-sec", Key: "ca.crt"}},
			},
		},
		IngressPorts: []sandboxv1beta1.SandboxIngressPort{{Port: 8888, Protocol: sandboxv1beta1.SandboxIngressProtocolTCP}},
	}

	tmpl := &extensionsv1beta1.SandboxTemplate{
		Spec: extensionsv1beta1.SandboxTemplateSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{Network: omitted},
		},
	}
	actual := &sandboxv1beta1.SandboxBlueprint{Network: explicit}
	ApplySandboxSecureDefaults(tmpl, &actual.PodTemplate.Spec)
	if !compareSandboxBlueprint(tmpl, actual) {
		t.Fatalf("expected omitted and explicitly defaulted SandboxNetworkSpec to compare equal")
	}

	// Verify SPIFFE nil vs explicit Mode=Node and PodCertificate omitted vs ECDSAP256.
	spiffeOmitted := &sandboxv1beta1.SandboxNetworkSpec{
		PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
			URL:  "https://pep.corp:8443",
			Auth: &sandboxv1beta1.SandboxPEPAuth{Type: sandboxv1beta1.SandboxPEPAuthTypeSPIFFE},
		},
	}
	spiffeExplicit := &sandboxv1beta1.SandboxNetworkSpec{
		PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
			URL: "https://pep.corp:8443",
			Auth: &sandboxv1beta1.SandboxPEPAuth{
				Type:   sandboxv1beta1.SandboxPEPAuthTypeSPIFFE,
				SPIFFE: &sandboxv1beta1.SandboxSPIFFEAuth{Mode: sandboxv1beta1.SandboxSPIFFEModeNode},
			},
		},
	}
	tmpl.Spec.Network = spiffeOmitted
	actual.Network = spiffeExplicit
	if !compareSandboxBlueprint(tmpl, actual) {
		t.Fatalf("expected omitted and defaulted SPIFFE auth to compare equal")
	}

	podCertOmitted := &sandboxv1beta1.SandboxNetworkSpec{
		PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
			URL: "https://pep.corp:8443",
			Auth: &sandboxv1beta1.SandboxPEPAuth{
				Type:           sandboxv1beta1.SandboxPEPAuthTypePodCertificate,
				PodCertificate: &sandboxv1beta1.SandboxPodCertificateAuth{SignerName: "spiffe.io/id"},
			},
		},
	}
	podCertExplicit := &sandboxv1beta1.SandboxNetworkSpec{
		PolicyEnforcementPoint: sandboxv1beta1.SandboxPolicyEnforcementPoint{
			URL: "https://pep.corp:8443",
			Auth: &sandboxv1beta1.SandboxPEPAuth{
				Type: sandboxv1beta1.SandboxPEPAuthTypePodCertificate,
				PodCertificate: &sandboxv1beta1.SandboxPodCertificateAuth{
					SignerName: "spiffe.io/id",
					KeyType:    sandboxv1beta1.SandboxPodCertificateKeyTypeECDSAP256,
				},
			},
		},
	}
	tmpl.Spec.Network = podCertOmitted
	actual.Network = podCertExplicit
	if !compareSandboxBlueprint(tmpl, actual) {
		t.Fatalf("expected omitted and defaulted PodCertificate auth to compare equal")
	}
}
