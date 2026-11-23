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

// Command sandbox-net runs the per-node agents.net traffic plumbing DaemonSet
// (standard GA DRA plugin + NRI runtime plugin + socketat loopback listeners +
// authenticated upstream CONNECT / RFC 9298 connect-udp forwarder).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/auth"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/catrust"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/driver"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/ingress"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/store"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/tunnel"
)

func main() {
	var (
		kubeconfig         string
		nodeName           string
		driverName         string
		socketRoot         string
		checkpointPath     string
		kubeletRoot        string
		nriSocket          string
		nriPluginIdx       string
		nodeTokenPath      string
		spiffeSocket       string
		spireDelegatedSock string
		systemRootsPath    string
		metricsAddr        string
		ingressAddr        string
		ingressTLSCert     string
		ingressTLSKey      string
		ingressClientCA    string
		maxSandboxes       int64
	)

	klog.InitFlags(nil)
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig (defaults to in-cluster config)")
	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "Kubernetes node name")
	flag.StringVar(&driverName, "driver-name", sandboxv1beta1.SandboxNetDriverName, "DRA driver and NRI plugin name")
	flag.StringVar(&socketRoot, "socket-root", "/run/sandbox-net/pods", "Host directory for per-Pod agents.net Unix sockets and CA bundles")
	flag.StringVar(&checkpointPath, "checkpoint-path", "/run/sandbox-net/state.db", "BoltDB tmpfs checkpoint path")
	flag.StringVar(&kubeletRoot, "kubelet-root-dir", auth.DefaultKubeletRootDir, "Host kubelet root directory")
	flag.StringVar(&nriSocket, "nri-socket", "", "Optional containerd/CRI-O NRI socket path")
	flag.StringVar(&nriPluginIdx, "nri-plugin-idx", "00", "NRI plugin index")
	flag.StringVar(&nodeTokenPath, "node-token-path", auth.DefaultNodeTokenPath, "Projected ServiceAccount token path for ServiceAccountToken Node mode")
	flag.StringVar(&spiffeSocket, "spiffe-socket", auth.DefaultSPIFFEWorkloadSocket, "SPIFFE Workload API Unix socket path")
	flag.StringVar(&spireDelegatedSock, "spire-delegated-socket", auth.DefaultSPIREDelegatedSocket, "SPIRE Delegated Identity Unix socket path")
	flag.StringVar(&systemRootsPath, "system-roots-path", "", "Optional host system CA bundle path for AppendSystemRoots mode (auto-detected if empty)")
	flag.StringVar(&metricsAddr, "metrics-addr", ":9102", "Address for Prometheus /metrics and /healthz")
	flag.StringVar(&ingressAddr, "ingress-addr", "", "Optional host listen address for the HTTP CONNECT ingress bridge (e.g. :15080)")
	flag.StringVar(&ingressTLSCert, "ingress-tls-cert", "", "Optional PEM server certificate path for TLS on --ingress-addr")
	flag.StringVar(&ingressTLSKey, "ingress-tls-key", "", "Optional PEM server key path for TLS on --ingress-addr")
	flag.StringVar(&ingressClientCA, "ingress-client-ca", "", "Optional PEM client CA bundle path to enforce mTLS on --ingress-addr")
	flag.Int64Var(&maxSandboxes, "max-sandboxes", 0, "Per-node DRA slot count (0 auto-detects from node status.allocatable.pods, fallback 110)")
	flag.Parse()

	if nodeName == "" {
		klog.Fatalf("--node-name or NODE_NAME environment variable is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	restCfg, err := loadRestConfig(kubeconfig)
	if err != nil {
		klog.Fatalf("load kubernetes config: %v", err)
	}
	kubeClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		klog.Fatalf("create kubernetes client: %v", err)
	}

	boltBackend, err := store.OpenBolt(checkpointPath)
	if err != nil {
		klog.Fatalf("open checkpoint store %q: %v", checkpointPath, err)
	}
	podStore, err := store.New(boltBackend)
	if err != nil {
		klog.Fatalf("hydrate pod store: %v", err)
	}
	defer func() { _ = podStore.Close() }()

	authResolver := auth.NewResolver(auth.ResolverConfig{
		KubeletRootDir:              kubeletRoot,
		DefaultNodeTokenPath:        nodeTokenPath,
		DefaultSPIFFEWorkloadSocket: spiffeSocket,
		DefaultSPIREDelegatedSocket: spireDelegatedSock,
		KubeClient:                  kubeClient,
	})
	defer func() { _ = authResolver.Close() }()

	tunnelMgr, err := tunnel.NewManager(socketRoot, authResolver)
	if err != nil {
		klog.Fatalf("create agents.net tunnel manager: %v", err)
	}
	defer tunnelMgr.Close()

	var ingressSrv *ingress.Server
	if ingressAddr != "" {
		ingressTLS, err := buildIngressTLSConfig(ingressTLSCert, ingressTLSKey, ingressClientCA)
		if err != nil {
			klog.Fatalf("configure ingress TLS: %v", err)
		}
		ingressSrv, err = ingress.NewServer(ingress.Config{
			ListenAddr: ingressAddr,
			Store:      podStore,
			TLSConfig:  ingressTLS,
		})
		if err != nil {
			klog.Fatalf("create ingress bridge: %v", err)
		}
		if _, err := ingressSrv.Start(); err != nil {
			klog.Fatalf("start ingress bridge: %v", err)
		}
		defer func() { _ = ingressSrv.Close() }()
	}

	drv, err := driver.New(driver.Config{
		DriverName:        driverName,
		NodeName:          nodeName,
		KubeClient:        kubeClient,
		Store:             podStore,
		Tunnel:            tunnelMgr,
		Ingress:           ingressSrv,
		CAMaterializer:    catrust.NewMaterializer(kubeClient, systemRootsPath),
		MaxSandboxes:      maxSandboxes,
		KubeletRootDir:    kubeletRoot,
		NRISocketPath:     nriSocket,
		NRIPluginIdx:      nriPluginIdx,
		IngressBridgeAddr: ingressAddr,
	})
	if err != nil {
		klog.Fatalf("create DRA+NRI driver: %v", err)
	}
	if err := drv.Start(ctx); err != nil {
		klog.Fatalf("start DRA+NRI driver: %v", err)
	}
	defer drv.Stop()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	srv := &http.Server{
		Addr:              metricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		klog.InfoS("serving metrics and healthz", "addr", metricsAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			klog.ErrorS(err, "metrics server exited")
		}
	}()

	<-ctx.Done()
	klog.InfoS("shutting down sandbox-net")
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func loadRestConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func buildIngressTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" && clientCAFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("both --ingress-tls-cert and --ingress-tls-key are required when TLS is enabled")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load ingress TLS keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
	}
	if clientCAFile != "" {
		caBytes, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read ingress client CA %q: %w", clientCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("no valid CA certificates in %q", clientCAFile)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
