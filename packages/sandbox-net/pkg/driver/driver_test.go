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

package driver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsv1beta1 "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/auth"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/catrust"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/params"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/store"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/tunnel"
)

type fakeNetNS struct {
	verifiedPaths []string
	flushedPaths  []string
	listenedAddrs []string
	verifyErr     error
	flushErr      error
	listenErr     error
}

func (f *fakeNetNS) VerifyLoopbackOnly(path string) error {
	f.verifiedPaths = append(f.verifiedPaths, path)
	return f.verifyErr
}

func (f *fakeNetNS) FlushNonLoopbackRoutes(path string) error {
	f.flushedPaths = append(f.flushedPaths, path)
	return f.flushErr
}

func (f *fakeNetNS) ListenAt(path, network, address string) (net.Listener, error) {
	f.listenedAddrs = append(f.listenedAddrs, path+"@"+address)
	if f.listenErr != nil {
		return nil, f.listenErr
	}
	// Bind an ephemeral host loopback listener in offline unit tests.
	return net.Listen(network, "127.0.0.1:0")
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "snet-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func writeTestCAPEM(t *testing.T, path, cn string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA cert: %v", err)
	}
}

func makeTestClaim(podUID, claimUID types.UID, p params.NetworkParameters) *resourceapi.ResourceClaim {
	raw, _ := json.Marshal(p)
	return &resourceapi.ResourceClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "claim-1",
			Namespace: "agents",
			UID:       claimUID,
		},
		Status: resourceapi.ResourceClaimStatus{
			ReservedFor: []resourceapi.ResourceClaimConsumerReference{
				{Resource: "pods", Name: "sb-1", UID: podUID},
			},
			Allocation: &resourceapi.AllocationResult{
				Devices: resourceapi.DeviceAllocationResult{
					Results: []resourceapi.DeviceRequestAllocationResult{
						{
							Request: "sandbox-net",
							Driver:  sandboxv1beta1.SandboxNetDriverName,
							Pool:    "worker-1",
							Device:  DefaultDeviceNamePrefix + "0",
						},
					},
					Config: []resourceapi.DeviceAllocationConfiguration{
						{
							DeviceConfiguration: resourceapi.DeviceConfiguration{
								Opaque: &resourceapi.OpaqueDeviceConfiguration{
									Driver:     sandboxv1beta1.SandboxNetDriverName,
									Parameters: runtime.RawExtension{Raw: raw},
								},
							},
						},
					},
				},
			},
		},
	}
}

func envMap(kvList []*nriapi.KeyValue) map[string]string {
	out := make(map[string]string, len(kvList))
	for _, kv := range kvList {
		out[kv.Key] = kv.Value
	}
	return out
}

func TestBuildResourceSliceSimpleGASlotsAndHealth(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, _ := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	defer tm.Close()

	// Auto-detect slot count from Node.Status.Allocatable.Pods() (> ResourceSliceMaxDevices
	// to verify automatic chunking across multiple GA ResourceSlices).
	fakeClient := fake.NewClientset(&corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourcePods: resource.MustParse("200"),
			},
		},
	})

	drv, err := New(Config{
		NodeName:   "worker-1",
		KubeClient: fakeClient,
		Store:      st,
		Tunnel:     tm,
		NetNS:      &fakeNetNS{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	drv.resolveSlotCount(ctx)

	res := drv.BuildResourceSlice()
	pool := res.Pools["worker-1"]
	if len(pool.Slices) != 2 {
		t.Fatalf("expected 2 slices for 200 slots (128+72), got %d", len(pool.Slices))
	}
	if len(pool.Slices[0].Devices) != resourceapi.ResourceSliceMaxDevices {
		t.Fatalf("slice[0] devices = %d, want %d", len(pool.Slices[0].Devices), resourceapi.ResourceSliceMaxDevices)
	}
	if len(pool.Slices[1].Devices) != 72 {
		t.Fatalf("slice[1] devices = %d, want 72", len(pool.Slices[1].Devices))
	}

	// Verify pure GA device fields only (no DRAConsumableCapacity or DRADeviceTaints).
	first := pool.Slices[0].Devices[0]
	last := pool.Slices[1].Devices[71]
	if first.Name != "slot-0" || last.Name != "slot-199" {
		t.Fatalf("unexpected slot names: first=%q last=%q", first.Name, last.Name)
	}
	if first.AllowMultipleAllocations != nil || len(first.Capacity) != 0 || len(first.Taints) != 0 {
		t.Fatalf("expected pure GA device without feature-gated fields, got %+v", first)
	}

	// Marking unhealthy withdraws all slices cleanly without DRADeviceTaints.
	if err := drv.SetHealthy(ctx, false); err != nil {
		t.Fatalf("SetHealthy(false): %v", err)
	}
	if got := len(drv.BuildResourceSlice().Pools["worker-1"].Slices); got != 0 {
		t.Fatalf("expected 0 slices when unhealthy, got %d", got)
	}
}

func TestPrepareRunCreateStopRemoveCATrustAndPodSync(t *testing.T) {
	ctx := t.Context()
	tmp := shortTempDir(t)
	sysCAPath := filepath.Join(tmp, "sys-ca.pem")
	customCAPath := filepath.Join(tmp, "custom-ca.pem")
	writeTestCAPEM(t, sysCAPath, "sys-root")
	writeTestCAPEM(t, customCAPath, "corp-proxy-ca")

	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(filepath.Join(tmp, "s"), auth.NewResolver(auth.ResolverConfig{KubeletRootDir: tmp}), tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	netns := &fakeNetNS{}
	drv, err := New(Config{
		NodeName:       "worker-1",
		Store:          st,
		Tunnel:         tm,
		CAMaterializer: catrust.NewMaterializer(nil, sysCAPath),
		NetNS:          netns,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	podUID := types.UID("pod-uid-abc")
	claimUID := types.UID("claim-uid-abc")
	claim := makeTestClaim(podUID, claimUID, params.NetworkParameters{
		ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
		AdapterMode:     sandboxv1beta1.SandboxAdapterModeTunSidecar,
		CATrust: &sandboxv1beta1.SandboxCATrustSpec{
			Mode:       sandboxv1beta1.SandboxCATrustModeInjectEnv,
			BundleMode: sandboxv1beta1.SandboxCABundleModeAppendSystemRoots,
			Sources: []sandboxv1beta1.SandboxCASource{
				{Type: sandboxv1beta1.SandboxCASourceTypeHostPath, HostPath: customCAPath},
			},
		},
		IngressPorts: []sandboxv1beta1.SandboxIngressPort{{Port: 8080}},
		Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
			Address:  "https://portal.sandbox-system.svc:8443",
			Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP2,
		},
		Custom: map[string]string{"tenant": "team-a"},
	})

	// 1. DRA PrepareResourceClaims returns zero CDI devices, opens egress.sock, and materializes Pod CAs.
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil {
		t.Fatalf("PrepareResourceClaims: %v", err)
	}
	if res := prepRes[claimUID]; res.Err != nil || len(res.Devices) != 0 {
		t.Fatalf("PrepareResult = %+v, want Err=nil and 0 CDI devices", res)
	}

	// 2. NRI RunPodSandbox verifies loopback-only netns before any container starts.
	pod := &nriapi.PodSandbox{
		Uid:       string(podUID),
		Name:      "sb-1",
		Namespace: "agents",
		Linux: &nriapi.LinuxPodSandbox{
			Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/sb-1"}},
		},
	}
	if err := drv.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox: %v", err)
	}
	if len(netns.verifiedPaths) != 1 || netns.verifiedPaths[0] != "/var/run/netns/sb-1" {
		t.Fatalf("expected VerifyLoopbackOnly called once, got %v", netns.verifiedPaths)
	}

	// 3. NRI CreateContainer injects /dev/net/tun + egress/ingress sockets ONLY on tun2connect.
	adjSidecar, _, err := drv.CreateContainer(ctx, pod, &nriapi.Container{Name: Tun2ConnectContainerName})
	if err != nil || adjSidecar == nil {
		t.Fatalf("CreateContainer sidecar: adj=%v err=%v", adjSidecar, err)
	}
	if len(adjSidecar.Linux.Devices) != 1 || adjSidecar.Linux.Devices[0].Path != "/dev/net/tun" {
		t.Fatalf("expected /dev/net/tun on sidecar, got %+v", adjSidecar.Linux.Devices)
	}
	// Sidecar mounts: egress, ingress, merged CA, extra CA = 4.
	if len(adjSidecar.Mounts) != 4 {
		t.Fatalf("expected 4 mounts on sidecar, got %d", len(adjSidecar.Mounts))
	}

	// Workload container gets CA mounts + agents.net/language CA env vars only — zero /dev/net/tun, zero egress.sock!
	adjAgent, _, err := drv.CreateContainer(ctx, pod, &nriapi.Container{Name: "agent"})
	if err != nil || adjAgent == nil {
		t.Fatalf("CreateContainer agent: adj=%v err=%v", adjAgent, err)
	}
	if adjAgent.Linux != nil && len(adjAgent.Linux.Devices) > 0 {
		t.Fatalf("agent container must NOT receive /dev/net/tun, got %+v", adjAgent.Linux.Devices)
	}
	if len(adjAgent.Mounts) != 2 || adjAgent.Mounts[0].Destination != catrust.ContainerCABundlePath || adjAgent.Mounts[1].Destination != catrust.ContainerExtraCAPath {
		t.Fatalf("agent container mounts = %+v, want merged + extra CA bundles only", adjAgent.Mounts)
	}
	agentEnv := envMap(adjAgent.Env)
	if agentEnv["AGENT_CA_CERT"] != catrust.ContainerCABundlePath || agentEnv["NODE_EXTRA_CA_CERTS"] != catrust.ContainerExtraCAPath || agentEnv["REQUESTS_CA_BUNDLE"] != catrust.ContainerCABundlePath {
		t.Fatalf("missing expected CA trust env vars: %+v", agentEnv)
	}

	// 4. SyncPod captures ServiceAccount & warm-pool SandboxClaim adoption metadata.
	drv.SyncPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "sb-1",
			Namespace:   "agents",
			UID:         podUID,
			Labels:      map[string]string{extensionsv1beta1.SandboxIDLabel: "claim-uid-99"},
			Annotations: map[string]string{extensionsv1beta1.SandboxClaimNameAnnotation: "claim-alpha"},
		},
		Spec: corev1.PodSpec{ServiceAccountName: "agent-sa"},
	})
	updatedCfg, ok := st.Get(podUID)
	if !ok || updatedCfg.ServiceAccount != "agent-sa" || updatedCfg.SandboxClaimName != "claim-alpha" {
		t.Fatalf("SyncPod did not update identity: %+v", updatedCfg)
	}

	// 5. StopPodSandbox + RemovePodSandbox + UnprepareResourceClaims clean up cleanly.
	if err := drv.StopPodSandbox(ctx, pod); err != nil {
		t.Fatalf("StopPodSandbox: %v", err)
	}
	if err := drv.RemovePodSandbox(ctx, pod); err != nil {
		t.Fatalf("RemovePodSandbox: %v", err)
	}
	unprep, err := drv.UnprepareResourceClaims(ctx, []kubeletplugin.NamespacedObject{
		{NamespacedName: types.NamespacedName{Namespace: "agents", Name: "claim-1"}, UID: claimUID},
	})
	if err != nil || unprep[claimUID] != nil {
		t.Fatalf("UnprepareResourceClaims: err=%v res=%+v", err, unprep)
	}
}

func TestExplicitProxySocketAtAndMagicLanguageEnvVars(t *testing.T) {
	ctx := t.Context()
	st, _ := store.New(nil)
	tm, err := tunnel.NewManager(shortTempDir(t), nil, tunnel.WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer tm.Close()

	netns := &fakeNetNS{}
	drv, err := New(Config{NodeName: "worker-1", Store: st, Tunnel: tm, NetNS: netns})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	podUID := types.UID("pod-compat")
	claimUID := types.UID("claim-compat")
	claim := makeTestClaim(podUID, claimUID, params.NetworkParameters{
		ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
		AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
		Proxy: &sandboxv1beta1.SandboxExplicitProxyConfig{
			Port:    new(int32(18080)),
			NoProxy: []string{".internal.corp"},
		},
	})
	prepRes, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim})
	if err != nil || prepRes[claimUID].Err != nil {
		t.Fatalf("PrepareResourceClaims: err=%v res=%+v", err, prepRes[claimUID])
	}

	// HostNetwork pod (no network namespace path) must be rejected.
	if err := drv.RunPodSandbox(ctx, &nriapi.PodSandbox{Uid: string(podUID), Name: "sb", Namespace: "agents"}); err == nil {
		t.Fatalf("expected error for hostNetwork pod")
	}

	pod := &nriapi.PodSandbox{
		Uid:       string(podUID),
		Name:      "sb",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/compat"}}},
	}
	if err := drv.RunPodSandbox(ctx, pod); err != nil {
		t.Fatalf("RunPodSandbox compat: %v", err)
	}
	if len(netns.flushedPaths) != 1 || netns.flushedPaths[0] != "/var/run/netns/compat" {
		t.Fatalf("expected FlushNonLoopbackRoutes called once, got %v", netns.flushedPaths)
	}
	if len(netns.listenedAddrs) != 1 || netns.listenedAddrs[0] != "/var/run/netns/compat@127.0.0.1:18080" {
		t.Fatalf("expected socketat ListenAt on 127.0.0.1:18080, got %v", netns.listenedAddrs)
	}

	// Verify ExplicitProxy injects all language magic proxy env vars pointing at http://127.0.0.1:18080
	// and appends cleanly to existing JAVA_TOOL_OPTIONS.
	adj, _, err := drv.CreateContainer(ctx, pod, &nriapi.Container{
		Name: "agent",
		Env:  []string{"JAVA_TOOL_OPTIONS=-Xmx256m"},
	})
	if err != nil || adj == nil {
		t.Fatalf("CreateContainer ExplicitProxy: adj=%+v err=%v", adj, err)
	}
	envs := envMap(adj.Env)
	if envs["HTTP_PROXY"] != "http://127.0.0.1:18080" || envs["http_proxy"] != "http://127.0.0.1:18080" {
		t.Fatalf("unexpected HTTP_PROXY/http_proxy: %+v", envs)
	}
	if envs["NODE_USE_ENV_PROXY"] != "1" || envs["GRPC_PROXY_EXP"] != "http://127.0.0.1:18080" {
		t.Fatalf("missing Node/gRPC proxy env vars: %+v", envs)
	}
	if !strings.HasPrefix(envs["JAVA_TOOL_OPTIONS"], "-Xmx256m -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=18080") {
		t.Fatalf("unexpected JAVA_TOOL_OPTIONS: %q", envs["JAVA_TOOL_OPTIONS"])
	}

	// Verify loopback check failure aborts RunPodSandbox.
	netns.verifyErr = errors.New("non-loopback eth0 present")
	podUID2 := types.UID("pod-bad-netns")
	claimUID2 := types.UID("claim-bad-netns")
	claim2 := makeTestClaim(podUID2, claimUID2, params.NetworkParameters{
		ConfinementMode: sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
	})
	prepRes2, err := drv.PrepareResourceClaims(ctx, []*resourceapi.ResourceClaim{claim2})
	if err != nil || prepRes2[claimUID2].Err != nil {
		t.Fatalf("PrepareResourceClaims 2: err=%v res=%+v", err, prepRes2[claimUID2])
	}
	if err := drv.RunPodSandbox(ctx, &nriapi.PodSandbox{
		Uid:       string(podUID2),
		Name:      "sb2",
		Namespace: "agents",
		Linux:     &nriapi.LinuxPodSandbox{Namespaces: []*nriapi.LinuxNamespace{{Type: "network", Path: "/var/run/netns/bad"}}},
	}); err == nil {
		t.Fatalf("expected RunPodSandbox to fail when non-loopback interface exists under PodNetworkIsolated")
	}
}
