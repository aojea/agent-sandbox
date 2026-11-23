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

// Package driver implements the per-node sandbox-net DRA kubelet plugin and
// NRI runtime plugin following DraNet's slow-path DRA / fast-path NRI split
// without writing CDI JSON specification files to disk.
package driver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	nriapi "github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"
	"k8s.io/klog/v2"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsv1beta1 "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/auth"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/catrust"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/metrics"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/params"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/proxyenv"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/store"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/tunnel"
)

const (
	// DefaultDeviceNamePrefix is the DNS-label prefix for per-pod DRA slot devices
	// published by sandbox-net on each node using standard GA resource.k8s.io/v1.
	DefaultDeviceNamePrefix = "slot-"

	// DefaultMaxSandboxes is the fallback per-node slot count when node
	// status.allocatable.pods cannot be read and --max-sandboxes is unset.
	DefaultMaxSandboxes int64 = 110

	// Tun2ConnectContainerName is the name of the single per-Pod tun2connect native sidecar.
	Tun2ConnectContainerName = "sandbox-net-tun2connect"

	containerEgressMountDir  = "/run/agents.net"
	containerIngressMountDir = "/run/agents.net/ingress"
)

// NetNSManager abstracts Pod network namespace inspection, compat route flushing,
// and goroutine-safe cross-netns listener binding (socketat).
type NetNSManager interface {
	VerifyLoopbackOnly(netnsPath string) error
	FlushNonLoopbackRoutes(netnsPath string) error
	ListenAt(netnsPath, network, address string) (net.Listener, error)
}

// Config configures the per-node SandboxNetDriver.
type Config struct {
	DriverName        string
	NodeName          string
	KubeClient        kubernetes.Interface
	Store             *store.PodConfigStore
	Tunnel            *tunnel.Manager
	CAMaterializer    *catrust.Materializer
	NetNS             NetNSManager
	MaxSandboxes      int64
	KubeletRootDir    string
	NRISocketPath     string
	NRIPluginIdx      string
	IngressBridgeAddr string
}

// SandboxNetDriver combines a DRA kubeletplugin.DRAPlugin (slow path), an NRI runtime
// plugin (fast path, zero CDI files), socketat Pod-loopback listeners for ExplicitProxy,
// and a node-scoped core/v1 Pod informer for ServiceAccount and warm-pool claim sync.
type SandboxNetDriver struct {
	driverName     string
	nodeName       string
	kubeClient     kubernetes.Interface
	store          *store.PodConfigStore
	tunnel         *tunnel.Manager
	caMat          *catrust.Materializer
	netns          NetNSManager
	maxSandboxes   int64
	kubeletRootDir string
	nriSocketPath  string
	nriPluginIdx   string
	ingressAddr    string

	draPlugin *kubeletplugin.Helper
	nriPlugin stub.Stub

	unhealthy atomic.Bool
	statusWG  sync.WaitGroup
}

var _ kubeletplugin.DRAPlugin = &SandboxNetDriver{}

// New creates a SandboxNetDriver without starting network or kubelet listeners.
func New(cfg Config) (*SandboxNetDriver, error) {
	if cfg.NodeName == "" {
		return nil, errors.New("node name is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("store is required")
	}
	if cfg.Tunnel == nil {
		return nil, errors.New("tunnel manager is required")
	}
	driverName := cfg.DriverName
	if driverName == "" {
		driverName = sandboxv1beta1.SandboxNetDriverName
	}
	kubeletRoot := cfg.KubeletRootDir
	if kubeletRoot == "" {
		kubeletRoot = auth.DefaultKubeletRootDir
	}
	nriIdx := cfg.NRIPluginIdx
	if nriIdx == "" {
		nriIdx = "00"
	}
	maxSandboxes := max(cfg.MaxSandboxes, 0)
	netnsMgr := cfg.NetNS
	if netnsMgr == nil {
		netnsMgr = NewLinuxNetNSManager()
	}
	caMat := cfg.CAMaterializer
	if caMat == nil {
		caMat = catrust.NewMaterializer(cfg.KubeClient, "")
	}

	return &SandboxNetDriver{
		driverName:     driverName,
		nodeName:       cfg.NodeName,
		kubeClient:     cfg.KubeClient,
		store:          cfg.Store,
		tunnel:         cfg.Tunnel,
		caMat:          caMat,
		netns:          netnsMgr,
		maxSandboxes:   maxSandboxes,
		kubeletRootDir: kubeletRoot,
		nriSocketPath:  cfg.NRISocketPath,
		nriPluginIdx:   nriIdx,
		ingressAddr:    cfg.IngressBridgeAddr,
	}, nil
}

// Start registers the DRA kubelet plugin, connects the NRI stub, publishes the node's
// GA resource.k8s.io/v1 slot ResourceSlice(s), and starts the node-scoped Pod identity informer.
func (d *SandboxNetDriver) Start(ctx context.Context) error {
	d.resolveSlotCount(ctx)

	pluginDir := filepath.Join(d.kubeletRootDir, "plugins", d.driverName)
	if err := os.MkdirAll(pluginDir, 0o750); err != nil {
		return fmt.Errorf("create DRA plugin dir %q: %w", pluginDir, err)
	}

	draHelper, err := kubeletplugin.Start(
		ctx,
		d,
		kubeletplugin.KubeClient(d.kubeClient),
		kubeletplugin.NodeName(d.nodeName),
		kubeletplugin.DriverName(d.driverName),
		kubeletplugin.RegistrarDirectoryPath(filepath.Join(d.kubeletRootDir, "plugins_registry")),
		kubeletplugin.PluginDataDirectoryPath(pluginDir),
		kubeletplugin.HealthService(false),
	)
	if err != nil {
		return fmt.Errorf("start DRA kubeletplugin: %w", err)
	}
	d.draPlugin = draHelper

	if err := d.PublishResourceSlice(ctx); err != nil {
		draHelper.Stop()
		return fmt.Errorf("publish initial ResourceSlice: %w", err)
	}

	nriOpts := []stub.Option{
		stub.WithPluginName(d.driverName),
		stub.WithPluginIdx(d.nriPluginIdx),
		stub.WithOnClose(func() {
			klog.InfoS("NRI connection closed; reconnecting")
		}),
	}
	if d.nriSocketPath != "" {
		nriOpts = append(nriOpts, stub.WithSocketPath(d.nriSocketPath))
	}

	nriStub, err := stub.New(d, nriOpts...)
	if err != nil {
		draHelper.Stop()
		return fmt.Errorf("create NRI stub: %w", err)
	}
	d.nriPlugin = nriStub

	go func() {
		wait.UntilWithContext(ctx, func(runCtx context.Context) {
			if err := nriStub.Run(runCtx); err != nil && runCtx.Err() == nil {
				klog.ErrorS(err, "NRI plugin loop exited; retrying")
			}
		}, 2*time.Second)
	}()

	regSock := filepath.Join(d.kubeletRootDir, "plugins_registry", d.driverName+"-reg.sock")
	klog.InfoS("sandbox-net DRA+NRI driver started",
		"driver", d.driverName,
		"node", d.nodeName,
		"maxSandboxes", d.maxSandboxes,
		"registrationSocket", regSock,
	)

	if d.kubeClient != nil {
		d.startNodePodInformer(ctx)
	}

	return nil
}

// Stop stops the DRA helper, waits for in-flight status writes, and disconnects NRI.
func (d *SandboxNetDriver) Stop() {
	if d.draPlugin != nil {
		d.draPlugin.Stop()
	}
	d.statusWG.Wait()
	if d.nriPlugin != nil {
		d.nriPlugin.Stop()
	}
}

func (d *SandboxNetDriver) startNodePodInformer(ctx context.Context) {
	fieldSel := fields.OneTermEqualSelector("spec.nodeName", d.nodeName).String()
	factory := informers.NewSharedInformerFactoryWithOptions(
		d.kubeClient,
		30*time.Second,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fieldSel
		}),
	)
	podInf := factory.Core().V1().Pods().Informer()
	_, _ = podInf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if pod, ok := obj.(*corev1.Pod); ok {
				d.SyncPod(pod)
			}
		},
		UpdateFunc: func(_, newObj any) {
			if pod, ok := newObj.(*corev1.Pod); ok {
				d.SyncPod(pod)
			}
		},
	})
	factory.Start(ctx.Done())
	cache.WaitForCacheSync(ctx.Done(), podInf.HasSynced)
}

// SyncPod updates attested Pod/Sandbox/Claim metadata for a tracked Pod on this node.
// When warm-pool adoption changes the owning SandboxClaim UID, existing pre-claim tunnels
// are revoked immediately so subsequent connections carry the new claim identity.
func (d *SandboxNetDriver) SyncPod(pod *corev1.Pod) {
	if pod == nil {
		return
	}
	cfg, ok := d.store.Get(pod.UID)
	if !ok {
		return
	}
	newClaimUID := pod.Labels[extensionsv1beta1.SandboxIDLabel]
	newClaimName := pod.Annotations[extensionsv1beta1.SandboxClaimNameAnnotation]
	sandboxName := resolveSandboxName(pod)

	claimChanged := cfg.SandboxClaimUID != newClaimUID && newClaimUID != ""
	metaChanged := cfg.PodName != pod.Name ||
		cfg.PodNamespace != pod.Namespace ||
		cfg.ServiceAccount != pod.Spec.ServiceAccountName ||
		cfg.SandboxName != sandboxName ||
		cfg.SandboxClaimUID != newClaimUID ||
		cfg.SandboxClaimName != newClaimName

	if !metaChanged {
		return
	}
	if err := d.store.UpdateIdentity(pod.UID, pod.Name, pod.Namespace, pod.Spec.ServiceAccountName, sandboxName, newClaimUID, newClaimName); err != nil {
		klog.ErrorS(err, "failed to checkpoint updated Pod identity", "podUID", pod.UID)
	}
	d.tunnel.UpdateIdentity(pod.UID, d.buildWorkloadIdentity(pod.UID, pod.Name, pod.Namespace, pod.Spec.ServiceAccountName, sandboxName, newClaimUID, newClaimName, cfg.Parameters.Custom), claimChanged)
}

// resolveSlotCount determines how many GA DRA device slots to publish on this node.
// If MaxSandboxes was not explicitly configured, it reads node.Status.Allocatable.Pods()
// so sandbox-net capacity automatically tracks the node's pod capacity without requiring
// any alpha/beta DRA feature gates.
func (d *SandboxNetDriver) resolveSlotCount(ctx context.Context) {
	if d.maxSandboxes > 0 {
		return
	}
	if d.kubeClient != nil {
		getCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		node, err := d.kubeClient.CoreV1().Nodes().Get(getCtx, d.nodeName, metav1.GetOptions{})
		if err != nil {
			klog.V(2).InfoS("failed to read node allocatable pods; falling back to default slot count",
				"node", d.nodeName, "default", DefaultMaxSandboxes, "err", err)
		} else if podsQty := node.Status.Allocatable.Pods(); podsQty != nil && podsQty.Value() > 0 {
			d.maxSandboxes = podsQty.Value()
			return
		}
	}
	d.maxSandboxes = DefaultMaxSandboxes
}

// BuildResourceSlice builds standard GA resource.k8s.io/v1 ResourceSlice(s) containing one
// lightweight slot device per allocatable pod on this node (chunked at ResourceSliceMaxDevices).
// Using plain per-pod devices avoids DRAConsumableCapacity and DRADeviceTaints feature gates.
func (d *SandboxNetDriver) BuildResourceSlice() resourceslice.DriverResources {
	if d.unhealthy.Load() {
		return resourceslice.DriverResources{
			Pools: map[string]resourceslice.Pool{
				d.nodeName: {},
			},
		}
	}

	total := d.maxSandboxes
	if total <= 0 {
		total = DefaultMaxSandboxes
	}

	maxPerSlice := int64(resourceapi.ResourceSliceMaxDevices)
	slices := make([]resourceslice.Slice, 0, (total+maxPerSlice-1)/maxPerSlice)
	for start := int64(0); start < total; start += maxPerSlice {
		end := min(start+maxPerSlice, total)
		devs := make([]resourceapi.Device, 0, end-start)
		for i := start; i < end; i++ {
			devs = append(devs, resourceapi.Device{
				Name: DefaultDeviceNamePrefix + strconv.FormatInt(i, 10),
			})
		}
		slices = append(slices, resourceslice.Slice{Devices: devs})
	}

	return resourceslice.DriverResources{
		Pools: map[string]resourceslice.Pool{
			d.nodeName: {
				Slices: slices,
			},
		},
	}
}

// PublishResourceSlice publishes the node's ResourceSlice(s) via kubeletplugin.
func (d *SandboxNetDriver) PublishResourceSlice(ctx context.Context) error {
	if d.draPlugin == nil {
		return nil
	}
	return d.draPlugin.PublishResources(ctx, d.BuildResourceSlice())
}

// SetHealthy toggles whether this node advertises available sandbox-net slots.
// When unhealthy, slices are withdrawn so new Pods do not schedule here without
// requiring the DRADeviceTaints feature gate; existing Pods continue running.
func (d *SandboxNetDriver) SetHealthy(ctx context.Context, healthy bool) error {
	prev := !d.unhealthy.Load()
	d.unhealthy.Store(!healthy)
	if prev == healthy {
		return nil
	}
	return d.PublishResourceSlice(ctx)
}

// PrepareResourceClaims runs on the DRA slow path BEFORE CRI RunPodSandbox.
// It decodes DeviceClass + ResourceClaim opaque parameters, starts the per-Pod agents.net
// UDS listener, materializes any declarative Pod CA bundles, checkpoints state, and returns
// zero CDI devices.
func (d *SandboxNetDriver) PrepareResourceClaims(ctx context.Context, claims []*resourceapi.ResourceClaim) (map[types.UID]kubeletplugin.PrepareResult, error) {
	if len(claims) == 0 {
		return nil, nil
	}
	results := make(map[types.UID]kubeletplugin.PrepareResult, len(claims))
	for _, claim := range claims {
		res := d.prepareResourceClaim(ctx, claim)
		if res.Err != nil {
			metrics.DriverHookRequestsTotal.WithLabelValues("PrepareResourceClaims", "failed").Inc()
		} else {
			metrics.DriverHookRequestsTotal.WithLabelValues("PrepareResourceClaims", "success").Inc()
		}
		results[claim.UID] = res
	}
	return results, nil
}

func (d *SandboxNetDriver) prepareResourceClaim(ctx context.Context, claim *resourceapi.ResourceClaim) kubeletplugin.PrepareResult {
	if claim.Status.Allocation == nil {
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("claim %s/%s has no allocation", claim.Namespace, claim.Name)}
	}
	if len(claim.Status.ReservedFor) == 0 {
		return kubeletplugin.PrepareResult{}
	}
	if len(claim.Status.ReservedFor) > 1 {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("sandbox-net supports one pod per claim, got %d", len(claim.Status.ReservedFor)),
		}
	}
	reserved := claim.Status.ReservedFor[0]
	if reserved.Resource != "pods" || reserved.APIGroup != "" {
		return kubeletplugin.PrepareResult{
			Err: fmt.Errorf("sandbox-net supports Pods only, got %s/%s", reserved.APIGroup, reserved.Resource),
		}
	}
	podUID := reserved.UID

	var matchedResult *resourceapi.DeviceRequestAllocationResult
	for i := range claim.Status.Allocation.Devices.Results {
		res := &claim.Status.Allocation.Devices.Results[i]
		if res.Driver == d.driverName {
			matchedResult = res
			break
		}
	}
	if matchedResult == nil {
		return kubeletplugin.PrepareResult{}
	}

	netParams, err := params.Decode(claim.Status.Allocation.Devices.Config, d.driverName)
	if err != nil {
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("decode sandbox-net parameters for claim %s/%s: %w", claim.Namespace, claim.Name, err)}
	}

	identity := d.buildWorkloadIdentity(podUID, reserved.Name, claim.Namespace, "", reserved.Name, "", "", netParams.Custom)
	paths, err := d.tunnel.EnsureListener(ctx, podUID, tunnel.ListenerConfig{
		Identity:           identity,
		Upstream:           netParams.Upstream,
		PodCertVolumeName:  netParams.PodCertVolumeName,
		SATokenVolumeName:  netParams.SATokenVolumeName,
		HasIngress:         len(netParams.IngressPorts) > 0,
		MaxConnections:     int(*netParams.MaxConnections),
		IdleTimeoutSeconds: int(*netParams.IdleTimeoutSeconds),
	})
	if err != nil {
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("start agents.net listener for pod %s: %w", podUID, err)}
	}

	caBundle, err := d.caMat.Materialize(ctx, netParams.CATrust, claim.Namespace, filepath.Join(paths.PodRootDir, "ca"))
	if err != nil {
		_ = d.tunnel.Remove(podUID)
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("materialize Pod CA trust bundle for pod %s: %w", podUID, err)}
	}

	podCfg := store.PodConfig{
		PodUID:         podUID,
		PodName:        reserved.Name,
		PodNamespace:   claim.Namespace,
		SandboxName:    reserved.Name,
		ClaimUID:       claim.UID,
		ClaimNamespace: claim.Namespace,
		ClaimName:      claim.Name,
		DeviceName:     matchedResult.Device,
		PoolName:       matchedResult.Pool,
		Parameters:     netParams,
		SocketPaths:    paths,
		CABundle:       caBundle,
	}
	if err := d.store.Upsert(podCfg); err != nil {
		_ = d.tunnel.Remove(podUID)
		return kubeletplugin.PrepareResult{Err: fmt.Errorf("checkpoint pod config for %s: %w", podUID, err)}
	}

	// Return empty CDI devices: NRI CreateContainer injects mounts, CA bundles, and env in memory.
	return kubeletplugin.PrepareResult{}
}

// UnprepareResourceClaims tears down tunnel listeners, host socket/CA dirs, and checkpointed state.
func (d *SandboxNetDriver) UnprepareResourceClaims(_ context.Context, claims []kubeletplugin.NamespacedObject) (map[types.UID]error, error) {
	results := make(map[types.UID]error, len(claims))
	for _, claim := range claims {
		podCfg, ok := d.store.GetByClaimUID(claim.UID)
		if !ok {
			results[claim.UID] = nil
			continue
		}
		var errs []error
		if err := d.tunnel.Remove(podCfg.PodUID); err != nil {
			errs = append(errs, err)
		}
		if err := d.store.Delete(podCfg.PodUID); err != nil {
			errs = append(errs, err)
		}
		err := errors.Join(errs...)
		if err != nil {
			metrics.DriverHookRequestsTotal.WithLabelValues("UnprepareResourceClaims", "failed").Inc()
		} else {
			metrics.DriverHookRequestsTotal.WithLabelValues("UnprepareResourceClaims", "success").Inc()
		}
		results[claim.UID] = err
	}
	return results, nil
}

// HandleError logs DRA background errors per kubeletplugin contract.
func (d *SandboxNetDriver) HandleError(ctx context.Context, err error, msg string) {
	runtime.HandleErrorWithContext(ctx, err, msg)
}

// WatchHealthStatus declines kubelet health RPCs when HealthService(false) is used.
func (d *SandboxNetDriver) WatchHealthStatus(_ context.Context, _ chan<- kubeletplugin.DeviceHealthReport) error {
	return kubeletplugin.ErrHealthNotSupported
}

// Synchronize runs on NRI startup / DaemonSet restart. It restores per-Pod agents.net
// UDS listeners (and socketat loopback listeners for ExplicitProxy Pods) and reaps orphans.
func (d *SandboxNetDriver) Synchronize(ctx context.Context, pods []*nriapi.PodSandbox, _ []*nriapi.Container) ([]*nriapi.ContainerUpdate, error) {
	livePods := make(map[types.UID]*nriapi.PodSandbox, len(pods))
	for _, pod := range pods {
		livePods[types.UID(pod.GetUid())] = pod
	}

	now := time.Now().UTC()
	for _, uid := range d.store.ListPodUIDs() {
		cfg, ok := d.store.Get(uid)
		if !ok {
			continue
		}
		pod, isLive := livePods[uid]
		if !isLive {
			_ = d.tunnel.Remove(uid)
			_ = d.store.Delete(uid)
			continue
		}
		ns := getNetworkNamespace(pod)
		_ = d.store.UpdateNetNS(uid, ns, now)

		maxConns := int(params.DefaultMaxConnections)
		if cfg.Parameters.MaxConnections != nil {
			maxConns = int(*cfg.Parameters.MaxConnections)
		}
		idleSecs := int(params.DefaultIdleTimeoutSeconds)
		if cfg.Parameters.IdleTimeoutSeconds != nil {
			idleSecs = int(*cfg.Parameters.IdleTimeoutSeconds)
		}

		identity := d.buildWorkloadIdentity(
			uid,
			cfg.PodName,
			cfg.PodNamespace,
			cfg.ServiceAccount,
			cfg.SandboxName,
			cfg.SandboxClaimUID,
			cfg.SandboxClaimName,
			cfg.Parameters.Custom,
		)
		if _, err := d.tunnel.EnsureListener(ctx, uid, tunnel.ListenerConfig{
			Identity:           identity,
			Upstream:           cfg.Parameters.Upstream,
			PodCertVolumeName:  cfg.Parameters.PodCertVolumeName,
			SATokenVolumeName:  cfg.Parameters.SATokenVolumeName,
			HasIngress:         len(cfg.Parameters.IngressPorts) > 0,
			MaxConnections:     maxConns,
			IdleTimeoutSeconds: idleSecs,
		}); err != nil {
			klog.ErrorS(err, "failed to restore agents.net listener during Synchronize", "podUID", uid)
			continue
		}

		if cfg.Parameters.AdapterMode == sandboxv1beta1.SandboxAdapterModeExplicitProxy && ns != "" {
			addr := fmt.Sprintf("127.0.0.1:%d", cfg.Parameters.EffectiveProxyPort())
			ln, err := d.netns.ListenAt(ns, "tcp", addr)
			if err != nil {
				klog.ErrorS(err, "failed to restore socketat loopback proxy listener during Synchronize", "podUID", uid, "addr", addr)
			} else if err := d.tunnel.AttachListener(uid, ln); err != nil {
				klog.ErrorS(err, "failed to attach restored loopback listener", "podUID", uid)
			}
		}
	}

	metrics.DriverHookRequestsTotal.WithLabelValues("Synchronize", "success").Inc()
	return nil, nil
}

// RunPodSandbox runs synchronously once per Pod BEFORE any container is created or started.
// Under PodNetworkIsolated it verifies the Pod netns has only loopback; under NetworkPolicyDenyAll
// it flushes routes on non-loopback interfaces (eth0) so tun0 owns 0.0.0.0/0 and ::/0 cleanly.
// Under ExplicitProxy it also binds 127.0.0.1:<port> inside the Pod netns via socketat so every
// language HTTP client can reach the agents.net boundary over loopback without a sidecar.
func (d *SandboxNetDriver) RunPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	podUID := types.UID(pod.GetUid())
	cfg, ok := d.store.Get(podUID)
	if !ok {
		return nil
	}

	ns := getNetworkNamespace(pod)
	if ns == "" {
		metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "failed").Inc()
		return fmt.Errorf("sandbox-net forbids hostNetwork pods (%s/%s)", pod.GetNamespace(), pod.GetName())
	}

	mode := cfg.Parameters.ConfinementMode
	if mode == "" {
		mode = sandboxv1beta1.SandboxConfinementModePodNetworkIsolated
	}

	switch mode {
	case sandboxv1beta1.SandboxConfinementModePodNetworkIsolated:
		if err := d.netns.VerifyLoopbackOnly(ns); err != nil {
			metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "failed").Inc()
			return fmt.Errorf("PodNetworkIsolated check failed for pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
		}
	case sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll:
		if err := d.netns.FlushNonLoopbackRoutes(ns); err != nil {
			metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "failed").Inc()
			return fmt.Errorf("NetworkPolicyDenyAll route flush failed for pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
		}
	default:
		metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "failed").Inc()
		return fmt.Errorf("unsupported confinementMode %q for pod %s/%s", mode, pod.GetNamespace(), pod.GetName())
	}

	if cfg.Parameters.AdapterMode == sandboxv1beta1.SandboxAdapterModeExplicitProxy {
		addr := fmt.Sprintf("127.0.0.1:%d", cfg.Parameters.EffectiveProxyPort())
		ln, err := d.netns.ListenAt(ns, "tcp", addr)
		if err != nil {
			metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "failed").Inc()
			return fmt.Errorf("bind ExplicitProxy loopback listener %s in pod %s/%s via socketat: %w", addr, pod.GetNamespace(), pod.GetName(), err)
		}
		if err := d.tunnel.AttachListener(podUID, ln); err != nil {
			metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "failed").Inc()
			return fmt.Errorf("attach ExplicitProxy loopback listener for pod %s/%s: %w", pod.GetNamespace(), pod.GetName(), err)
		}
	}

	if err := d.store.UpdateNetNS(podUID, ns, time.Now().UTC()); err != nil {
		metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "failed").Inc()
		return fmt.Errorf("record pod netns: %w", err)
	}

	claimUID := pod.GetLabels()[extensionsv1beta1.SandboxIDLabel]
	claimName := pod.GetAnnotations()[extensionsv1beta1.SandboxClaimNameAnnotation]
	_ = d.store.UpdateIdentity(podUID, pod.GetName(), pod.GetNamespace(), cfg.ServiceAccount, pod.GetName(), claimUID, claimName)
	d.tunnel.UpdateIdentity(podUID, d.buildWorkloadIdentity(podUID, pod.GetName(), pod.GetNamespace(), cfg.ServiceAccount, pod.GetName(), claimUID, claimName, cfg.Parameters.Custom), false)

	d.reportResourceClaimDeviceStatusAsync(cfg)
	metrics.DriverHookRequestsTotal.WithLabelValues("RunPodSandbox", "success").Inc()
	return nil
}

// CreateContainer runs per container in the Pod and injects mounts, /dev/net/tun, Pod CA
// certificates, and language-specific proxy/CA environment variables in memory via
// ContainerAdjustment with zero CDI files.
func (d *SandboxNetDriver) CreateContainer(_ context.Context, pod *nriapi.PodSandbox, ctr *nriapi.Container) (*nriapi.ContainerAdjustment, []*nriapi.ContainerUpdate, error) {
	podUID := types.UID(pod.GetUid())
	cfg, ok := d.store.Get(podUID)
	if !ok {
		return nil, nil, nil
	}
	d.store.TouchNRIActivity(podUID, time.Now().UTC())

	adj := &nriapi.ContainerAdjustment{}
	changed := false
	desiredEnv := make(map[string]string)
	var javaToolOpts string

	adapterMode := cfg.Parameters.AdapterMode
	if adapterMode == "" {
		adapterMode = sandboxv1beta1.SandboxAdapterModeTunSidecar
	}

	switch adapterMode {
	case sandboxv1beta1.SandboxAdapterModeTunSidecar:
		if ctr.GetName() == Tun2ConnectContainerName {
			changed = true
			adj.AddMount(&nriapi.Mount{
				Destination: containerEgressMountDir,
				Source:      cfg.SocketPaths.EgressDir,
				Type:        "bind",
				Options:     []string{"rbind", "ro"},
			})
			desiredEnv["AGENTS_NET_EGRESS_SOCKET"] = filepath.Join(containerEgressMountDir, tunnel.EgressSocketName)
			if len(cfg.Parameters.IngressPorts) > 0 {
				adj.AddMount(&nriapi.Mount{
					Destination: containerIngressMountDir,
					Source:      cfg.SocketPaths.IngressDir,
					Type:        "bind",
					Options:     []string{"rbind", "rw"},
				})
				desiredEnv["AGENTS_NET_INGRESS_SOCKET"] = filepath.Join(containerIngressMountDir, tunnel.IngressSocketName)
				desiredEnv["AGENTS_NET_INGRESS_PORTS"] = formatIngressPorts(cfg.Parameters.IngressPorts)
			}
			if cfg.Parameters.ConfinementMode == sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll {
				desiredEnv["AGENTS_NET_COMPAT_ISOLATED"] = "1"
			}
			adj.AddDevice(&nriapi.LinuxDevice{
				Path:  "/dev/net/tun",
				Type:  "c",
				Major: 10,
				Minor: 200,
			})
		}

	case sandboxv1beta1.SandboxAdapterModeExplicitProxy:
		changed = true
		adj.AddMount(&nriapi.Mount{
			Destination: containerEgressMountDir,
			Source:      cfg.SocketPaths.EgressDir,
			Type:        "bind",
			Options:     []string{"rbind", "ro"},
		})
		egressSock := filepath.Join(containerEgressMountDir, tunnel.EgressSocketName)
		var extraNoProxy []string
		if cfg.Parameters.Proxy != nil {
			extraNoProxy = cfg.Parameters.Proxy.NoProxy
		}
		pVars, jOpts := proxyenv.ExplicitProxyEnv(egressSock, cfg.Parameters.EffectiveProxyPort(), extraNoProxy)
		maps.Copy(desiredEnv, pVars)
		javaToolOpts = jOpts
	}

	// Inject materialized Pod CA bundles into EVERY container in the Pod per agents.net Section 2.3.B.
	if cfg.CABundle.MergedHostPath != "" && cfg.Parameters.CATrust != nil && cfg.Parameters.CATrust.Mode != sandboxv1beta1.SandboxCATrustModeNone {
		changed = true
		adj.AddMount(&nriapi.Mount{
			Destination: catrust.ContainerCABundlePath,
			Source:      cfg.CABundle.MergedHostPath,
			Type:        "bind",
			Options:     []string{"rbind", "ro"},
		})
		if cfg.CABundle.ExtraHostPath != "" {
			adj.AddMount(&nriapi.Mount{
				Destination: catrust.ContainerExtraCAPath,
				Source:      cfg.CABundle.ExtraHostPath,
				Type:        "bind",
				Options:     []string{"rbind", "ro"},
			})
		}
		caMode := cfg.Parameters.CATrust.Mode
		if caMode == "" || caMode == sandboxv1beta1.SandboxCATrustModeInjectEnv {
			maps.Copy(desiredEnv, catrust.EnvVars(catrust.ContainerCABundlePath, catrust.ContainerExtraCAPath))
		}
	}

	for _, entry := range proxyenv.MergeNonClobbering(ctr.GetEnv(), desiredEnv, javaToolOpts) {
		changed = true
		adj.AddEnv(entry.Key, entry.Value)
	}

	metrics.DriverHookRequestsTotal.WithLabelValues("CreateContainer", "success").Inc()
	if !changed {
		return nil, nil, nil
	}
	return adj, nil, nil
}

// StopPodSandbox immediately revokes the sandbox's listeners and closes all active tunnels.
func (d *SandboxNetDriver) StopPodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	podUID := types.UID(pod.GetUid())
	if _, ok := d.store.Get(podUID); !ok {
		return nil
	}
	d.tunnel.Revoke(podUID)
	metrics.DriverHookRequestsTotal.WithLabelValues("StopPodSandbox", "success").Inc()
	return nil
}

// RemovePodSandbox cleans up host socket/CA directories and checkpointed state.
func (d *SandboxNetDriver) RemovePodSandbox(_ context.Context, pod *nriapi.PodSandbox) error {
	podUID := types.UID(pod.GetUid())
	if _, ok := d.store.Get(podUID); !ok {
		return nil
	}
	var errs []error
	if err := d.tunnel.Remove(podUID); err != nil {
		errs = append(errs, err)
	}
	if err := d.store.Delete(podUID); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		metrics.DriverHookRequestsTotal.WithLabelValues("RemovePodSandbox", "failed").Inc()
		return err
	}
	metrics.DriverHookRequestsTotal.WithLabelValues("RemovePodSandbox", "success").Inc()
	return nil
}

func (d *SandboxNetDriver) buildWorkloadIdentity(
	podUID types.UID,
	podName, namespace, sa, sandboxName, claimUID, claimName string,
	custom map[string]string,
) auth.WorkloadIdentity {
	return auth.WorkloadIdentity{
		Namespace:      namespace,
		PodName:        podName,
		PodUID:         podUID,
		ServiceAccount: sa,
		NodeName:       d.nodeName,
		SandboxName:    sandboxName,
		ClaimUID:       claimUID,
		ClaimName:      claimName,
		Custom:         custom,
	}
}

func resolveSandboxName(pod *corev1.Pod) string {
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller && ref.Kind == "Sandbox" {
			return ref.Name
		}
	}
	return pod.Name
}

func (d *SandboxNetDriver) reportResourceClaimDeviceStatusAsync(cfg store.PodConfig) {
	if d.kubeClient == nil || cfg.ClaimNamespace == "" || cfg.ClaimName == "" {
		return
	}
	d.statusWG.Go(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		claim, err := d.kubeClient.ResourceV1().ResourceClaims(cfg.ClaimNamespace).Get(ctx, cfg.ClaimName, metav1.GetOptions{})
		if err != nil {
			klog.V(2).InfoS("skipping ResourceClaim.status.devices update; get failed", "claim", cfg.ClaimNamespace+"/"+cfg.ClaimName, "err", err)
			return
		}

		entry := resourceapi.AllocatedDeviceStatus{
			Driver: d.driverName,
			Pool:   cfg.PoolName,
			Device: cfg.DeviceName,
			Conditions: []metav1.Condition{
				{
					Type:               "Ready",
					Status:             metav1.ConditionTrue,
					Reason:             "SandboxNetPrepared",
					Message:            "sandbox-net agents.net listener prepared for Pod",
					LastTransitionTime: metav1.Now(),
				},
			},
		}
		if d.ingressAddr != "" {
			entry.NetworkData = &resourceapi.NetworkDeviceData{
				InterfaceName: d.ingressAddr,
			}
		}

		devices := make([]resourceapi.AllocatedDeviceStatus, 0, len(claim.Status.Devices)+1)
		replaced := false
		for i := range claim.Status.Devices {
			existing := claim.Status.Devices[i]
			if existing.Driver == entry.Driver && existing.Pool == entry.Pool && existing.Device == entry.Device && existing.ShareID == nil {
				devices = append(devices, entry)
				replaced = true
				continue
			}
			devices = append(devices, existing)
		}
		if !replaced {
			devices = append(devices, entry)
		}

		patchBytes, err := json.Marshal(map[string]any{
			"status": map[string]any{
				"devices": devices,
			},
		})
		if err != nil {
			klog.ErrorS(err, "marshal ResourceClaim.status.devices patch", "claim", cfg.ClaimNamespace+"/"+cfg.ClaimName)
			return
		}
		if _, err := d.kubeClient.ResourceV1().ResourceClaims(cfg.ClaimNamespace).Patch(
			ctx, cfg.ClaimName, types.MergePatchType, patchBytes, metav1.PatchOptions{}, "status",
		); err != nil {
			klog.ErrorS(err, "failed to update ResourceClaim.status.devices", "claim", cfg.ClaimNamespace+"/"+cfg.ClaimName)
		}
	})
}

func getNetworkNamespace(pod *nriapi.PodSandbox) string {
	if pod == nil || pod.Linux == nil {
		return ""
	}
	for _, ns := range pod.Linux.Namespaces {
		if ns.Type == "network" {
			return ns.Path
		}
	}
	return ""
}

func formatIngressPorts(ports []sandboxv1beta1.SandboxIngressPort) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.FormatInt(int64(p.Port), 10))
	}
	return strings.Join(parts, ",")
}
