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

package store

import (
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/params"
)

func TestBoltStoreCheckpointAndReload(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "state.db")

	b1, err := OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt 1: %v", err)
	}
	s1, err := New(b1)
	if err != nil {
		t.Fatalf("New 1: %v", err)
	}

	podUID := types.UID("pod-uid-1")
	claimUID := types.UID("claim-uid-1")
	cfg := PodConfig{
		PodUID:         podUID,
		PodName:        "sb-1",
		PodNamespace:   "agents",
		ClaimUID:       claimUID,
		ClaimNamespace: "agents",
		ClaimName:      "sb-1-network",
		DeviceName:     "sandbox-net",
		PoolName:       "node-1",
		Parameters: params.NetworkParameters{
			ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
			AdapterMode:     sandboxv1beta1.SandboxAdapterModeTunSidecar,
			Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
				Address:  "https://portal.sandbox-system.svc:8443",
				Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP2,
			},
			Custom: map[string]string{"tenant": "alpha"},
		},
		SocketPaths: SocketPaths{
			PodRootDir:       "/run/sandbox-net/pod-uid-1",
			EgressDir:        "/run/sandbox-net/pod-uid-1/egress",
			EgressSocketPath: "/run/sandbox-net/pod-uid-1/egress/egress.sock",
		},
	}
	if err := s1.Upsert(cfg); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := s1.UpdateNetNS(podUID, "/var/run/netns/cni-1", time.Now().UTC()); err != nil {
		t.Fatalf("UpdateNetNS: %v", err)
	}
	if err := s1.UpdateIdentity(podUID, "sb-1", "agents", "coding-sa", "sb-1", "sc-uid-1", "claim-alpha"); err != nil {
		t.Fatalf("UpdateIdentity: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}

	b2, err := OpenBolt(dbPath)
	if err != nil {
		t.Fatalf("OpenBolt 2: %v", err)
	}
	defer func() { _ = b2.Close() }()
	s2, err := New(b2)
	if err != nil {
		t.Fatalf("New 2: %v", err)
	}

	got, ok := s2.Get(podUID)
	if !ok {
		t.Fatalf("expected pod %s after reload", podUID)
	}
	if got.ServiceAccount != "coding-sa" || got.SandboxClaimName != "claim-alpha" {
		t.Fatalf("identity lost after reload: %+v", got)
	}
	if got.Parameters.Upstream == nil || got.Parameters.Upstream.Address != "https://portal.sandbox-system.svc:8443" {
		t.Fatalf("upstream lost after reload: %+v", got.Parameters.Upstream)
	}
	if got.Parameters.Custom["tenant"] != "alpha" {
		t.Fatalf("custom param lost after reload: %+v", got.Parameters.Custom)
	}
	if byClaim, ok := s2.GetByClaimUID(claimUID); !ok || byClaim.PodUID != podUID {
		t.Fatalf("GetByClaimUID failed after reload: ok=%v got=%+v", ok, byClaim)
	}

	if err := s2.Delete(podUID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := s2.Get(podUID); ok {
		t.Fatalf("expected pod deleted")
	}
}
