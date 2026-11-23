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

package params

import (
	"testing"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/runtime"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
)

func TestDecodeLayersDeviceClassAndClaimOverrides(t *testing.T) {
	configs := []resourceapi.DeviceAllocationConfiguration{
		{
			Source: resourceapi.AllocationConfigSourceClass,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: sandboxv1beta1.SandboxNetDriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{
						"confinementMode": "PodNetworkIsolated",
						"upstream": {
							"address": "https://default-portal.sandbox-system.svc:8443",
							"protocol": "HTTP2",
							"tls": {"trustDomain": "cluster.local"},
							"auth": {"type": "SPIFFE", "spiffe": {"mode": "Node"}}
						},
						"caTrust": {
							"mode": "InjectEnv",
							"sources": [{"type": "HostPath", "hostPath": "/etc/corp/ca.crt"}]
						},
						"custom": {"env": "prod", "region": "us-central1"},
						"opaque": {"vendorFlag": {"tier": "gold"}}
					}`)},
				},
			},
		},
		{
			Source: resourceapi.AllocationConfigSourceClaim,
			DeviceConfiguration: resourceapi.DeviceConfiguration{
				Opaque: &resourceapi.OpaqueDeviceConfiguration{
					Driver: sandboxv1beta1.SandboxNetDriverName,
					Parameters: runtime.RawExtension{Raw: []byte(`{
						"upstream": {
							"address": "https://tenant-portal.team-a.svc:8443"
						},
						"caTrust": {
							"sources": [{"type": "ConfigMap", "configMapRef": {"name": "team-ca"}}]
						},
						"proxy": {"port": 18080, "noProxy": [".internal.corp"]},
						"custom": {"tenant": "team-a"},
						"maxConnections": 128
					}`)},
				},
			},
		},
	}

	got, err := Decode(configs, sandboxv1beta1.SandboxNetDriverName)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.CATrust == nil || len(got.CATrust.Sources) != 2 {
		t.Fatalf("expected merged 2 CA sources from class+claim, got %+v", got.CATrust)
	}
	if got.EffectiveProxyPort() != 18080 {
		t.Fatalf("EffectiveProxyPort = %d, want 18080", got.EffectiveProxyPort())
	}
	if got.Upstream == nil || got.Upstream.Address != "https://tenant-portal.team-a.svc:8443" {
		t.Fatalf("upstream address = %+v, want tenant override", got.Upstream)
	}
	if got.Upstream.TLS == nil || got.Upstream.TLS.TrustDomain != "cluster.local" {
		t.Fatalf("expected DeviceClass TLS trustDomain preserved, got %+v", got.Upstream.TLS)
	}
	if got.Upstream.Auth == nil || got.Upstream.Auth.Type != sandboxv1beta1.SandboxUpstreamAuthTypeSPIFFE {
		t.Fatalf("expected DeviceClass auth preserved, got %+v", got.Upstream.Auth)
	}
	if got.Custom["env"] != "prod" || got.Custom["tenant"] != "team-a" {
		t.Fatalf("unexpected merged custom params: %+v", got.Custom)
	}
	if string(got.Opaque["vendorFlag"]) != `{"tier": "gold"}` {
		t.Fatalf("unexpected opaque field: %s", string(got.Opaque["vendorFlag"]))
	}
	if got.MaxConnections == nil || *got.MaxConnections != 128 {
		t.Fatalf("maxConnections = %v, want 128", got.MaxConnections)
	}
}
