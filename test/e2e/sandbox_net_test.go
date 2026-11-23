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

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	resourcev1 "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	extensionsv1beta1 "sigs.k8s.io/agent-sandbox/extensions/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/test/e2e/framework"
	"sigs.k8s.io/agent-sandbox/test/e2e/framework/predicates"
)

const (
	sandboxNetE2EWorkloadImage = "python:3.14-slim"
	sandboxNetSystemNS         = "agent-sandbox-system"
	sandboxNetDaemonSetName    = "sandbox-net"
)

func sandboxNetTestUpstreamImage() string {
	return fmt.Sprintf("%ssandbox-net-test-upstream:%s", getImagePrefix(), getImageTag())
}

func sandboxRouterGoImage() string {
	return fmt.Sprintf("%ssandbox-router-go:%s", getImagePrefix(), getImageTag())
}

type e2ePKI struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	caCertPEM []byte
}

func newE2EPKI(t *testing.T, cn string) *e2ePKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
	if err != nil {
		t.Fatalf("generate CA serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return &e2ePKI{
		caCert:    cert,
		caKey:     key,
		caCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

func (p *e2ePKI) issueCert(t *testing.T, cn string, dnsNames []string, ips []net.IP, isServer bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
	if err != nil {
		t.Fatalf("generate leaf serial: %v", err)
	}
	eku := x509.ExtKeyUsageClientAuth
	if isServer {
		eku = x509.ExtKeyUsageServerAuth
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

type upstreamProxyRecord struct {
	Target    string            `json:"target"`
	Protocol  string            `json:"protocol"`
	Transport string            `json:"transport"`
	Headers   map[string]string `json:"headers"`
	PeerCN    string            `json:"peer_cn"`
	JWTSub    string            `json:"jwt_sub"`
	JWTAud    []string          `json:"jwt_aud"`
	JWTNode   string            `json:"jwt_node"`
	Decision  string            `json:"decision"`
}

type upstreamProxyStats struct {
	TLSConnections int64 `json:"tls_connections"`
}

func repoRootFromE2E(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve caller path")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// ensureSandboxNetDeployed installs sandbox-net RBAC, default GA DeviceClass, and DaemonSet
// from packages/sandbox-net/deploy/ using the local/CI image prefix & tag, then waits for
// the DaemonSet to be Ready and for at least one GA ResourceSlice to be published.
func ensureSandboxNetDeployed(t *testing.T, tc *framework.TestContext) {
	t.Helper()
	ctx := t.Context()
	root := repoRootFromE2E(t)
	deployDir := filepath.Join(root, "packages", "sandbox-net", "deploy")
	image := fmt.Sprintf("%ssandbox-net:%s", getImagePrefix(), getImageTag())

	applyManifestFile := func(filename string, rewrite func(string) string) {
		raw, err := os.ReadFile(filepath.Join(deployDir, filename))
		if err != nil {
			t.Fatalf("read deploy manifest %s: %v", filename, err)
		}
		content := string(raw)
		if rewrite != nil {
			content = rewrite(content)
		}
		if stdout, stderr, err := kubectlApplyStdin(ctx, content); err != nil {
			t.Fatalf("kubectl apply %s failed: %v\nstdout=%s\nstderr=%s", filename, err, stdout, stderr)
		}
	}

	applyManifestFile("rbac.yaml", nil)
	applyManifestFile("deviceclass.yaml", nil)
	applyManifestFile("daemonset.yaml", func(raw string) string {
		const defaultImageLine = "image: registry.k8s.io/agent-sandbox/sandbox-net:latest"
		replacement := fmt.Sprintf("image: %s\n          imagePullPolicy: IfNotPresent", image)
		if !strings.Contains(raw, defaultImageLine) {
			t.Fatalf("daemonset.yaml missing expected image line %q", defaultImageLine)
		}
		return strings.Replace(raw, defaultImageLine, replacement, 1)
	})

	t.Cleanup(func() {
		if t.Failed() {
			dumpPodLogsBySelector(t, sandboxNetSystemNS, "app.kubernetes.io/name=sandbox-net")
		}
	})

	// Wait for DaemonSet pods to be ready.
	err := wait.PollUntilContextTimeout(ctx, 2*time.Second, 2*time.Minute, true, func(pollCtx context.Context) (bool, error) {
		var ds appsv1.DaemonSet
		if err := tc.Get(pollCtx, types.NamespacedName{Namespace: sandboxNetSystemNS, Name: sandboxNetDaemonSetName}, &ds); err != nil {
			return false, nil
		}
		return ds.Status.DesiredNumberScheduled > 0 &&
			ds.Status.NumberReady == ds.Status.DesiredNumberScheduled &&
			ds.Status.UpdatedNumberScheduled == ds.Status.DesiredNumberScheduled, nil
	})
	if err != nil {
		t.Fatalf("sandbox-net DaemonSet did not become ready: %v", err)
	}

	// Wait for at least one GA ResourceSlice published by sandbox-net.agents.x-k8s.io.
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(pollCtx context.Context) (bool, error) {
		var slices resourcev1.ResourceSliceList
		if err := tc.List(pollCtx, &slices); err != nil {
			return false, nil
		}
		for i := range slices.Items {
			if slices.Items[i].Spec.Driver == sandboxv1beta1.SandboxNetDriverName && len(slices.Items[i].Spec.Devices) > 0 {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("sandbox-net did not publish a GA ResourceSlice: %v", err)
	}
}

func kubectlApplyStdin(ctx context.Context, manifest string) (string, string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", framework.GetKubeconfig(), "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func kubectlRun(ctx context.Context, args ...string) (string, string, error) {
	fullArgs := append([]string{"--kubeconfig", framework.GetKubeconfig()}, args...)
	cmd := exec.CommandContext(ctx, "kubectl", fullArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func execInAgentPod(ctx context.Context, t *testing.T, ns, pod string, command ...string) (string, string, error) {
	t.Helper()
	args := append([]string{"exec", "-n", ns, pod, "-c", "agent", "--"}, command...)
	return kubectlRun(ctx, args...)
}

func dumpPodLogsBySelector(t *testing.T, ns, selector string) {
	t.Helper()
	out, stderr, err := kubectlRun(context.Background(), "logs", "-n", ns, "-l", selector, "--tail=120", "--all-containers=true")
	t.Logf("=== Logs %s (%s) err=%v ===\n%s\n%s", ns, selector, err, out, stderr)
}

type testUpstreamOpts struct {
	requireMTLS      bool
	requireBearerAud string
}

type testInfra struct {
	namespace     string
	upstreamPKI   *e2ePKI
	destPKI       *e2ePKI
	upstreamAddr  string
	upstreamFQDN  string
	destFQDN      string
	destServiceIP string
	proxyPodName  string
	destPodName   string
	upstreamCASec string
	upstreamCACM  string
	destCASec     string
	extraCACM     string
	clientMTLSSec string
}

// deployTestInfra sets up an isolated namespace with:
//   - upstream-ca ConfigMap & Secret (cert-manager kubernetes.io/tls format)
//   - dest-ca-tls Secret (cert-manager kubernetes.io/tls format with tls.crt, tls.key, AND ca.crt)
//   - extra-ca ConfigMap
//   - client-mtls Secret (cert-manager kubernetes.io/tls format with client cert, key, and ca.crt)
//   - dest-server Pod + Service (HTTPS :8443 signed by destPKI + HTTP :8080)
//   - upstream-proxy Pod + Service (HTTPS CONNECT :8443 signed by upstreamPKI + admin :8081)
func deployTestInfra(t *testing.T, tc *framework.TestContext, prefix string, opts testUpstreamOpts) *testInfra {
	t.Helper()
	ctx := t.Context()

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()),
		},
	}
	if err := tc.CreateWithCleanup(ctx, ns); err != nil {
		t.Fatalf("create namespace %s: %v", ns.Name, err)
	}

	upstreamFQDN := fmt.Sprintf("upstream-proxy.%s.svc", ns.Name)
	destFQDN := fmt.Sprintf("dest-server.%s.svc", ns.Name)

	upstreamPKI := newE2EPKI(t, "e2e-upstream-ca")
	destPKI := newE2EPKI(t, "e2e-dest-ca")
	extraPKI := newE2EPKI(t, "e2e-extra-ca")

	upSrvCert, upSrvKey := upstreamPKI.issueCert(t, upstreamFQDN, []string{upstreamFQDN, upstreamFQDN + ".cluster.local", "upstream-proxy"}, nil, true)
	dstSrvCert, dstSrvKey := destPKI.issueCert(t, destFQDN, []string{destFQDN, destFQDN + ".cluster.local", "dest-server"}, nil, true)
	cliCert, cliKey := upstreamPKI.issueCert(t, "sandbox-e2e-mtls-client", nil, nil, false)

	// Store upstream CA in both ConfigMap (trust-manager style) and Secret (cert-manager style).
	mustCreate := func(obj client.Object) {
		if err := tc.CreateWithCleanup(ctx, obj); err != nil {
			t.Fatalf("create %T %s/%s: %v", obj, obj.GetNamespace(), obj.GetName(), err)
		}
	}

	mustCreate(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "upstream-ca", Namespace: ns.Name},
		Data:       map[string]string{"ca.crt": string(upstreamPKI.caCertPEM)},
	})
	mustCreate(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "extra-ca", Namespace: ns.Name},
		Data:       map[string]string{"ca.crt": string(extraPKI.caCertPEM)},
	})
	mustCreate(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "upstream-proxy-tls", Namespace: ns.Name},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": upSrvCert,
			"tls.key": upSrvKey,
			"ca.crt":  upstreamPKI.caCertPEM,
		},
	})
	// cert-manager kubernetes.io/tls Secret for dest-server: includes tls.key alongside ca.crt
	// so we prove sandbox-net extracts ONLY CERTIFICATE PEM blocks into /var/run/agent-ca.pem.
	mustCreate(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "dest-ca-tls", Namespace: ns.Name},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": dstSrvCert,
			"tls.key": dstSrvKey,
			"ca.crt":  destPKI.caCertPEM,
		},
	})
	mustCreate(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-mtls", Namespace: ns.Name},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": cliCert,
			"tls.key": cliKey,
			"ca.crt":  upstreamPKI.caCertPEM,
		},
	})
	upstreamImage := sandboxNetTestUpstreamImage()

	destPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "dest-server",
			Namespace: ns.Name,
			Labels:    map[string]string{"app": "dest-server"},
		},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken:  new(false),
			TerminationGracePeriodSeconds: new(int64(1)),
			Containers: []corev1.Container{
				{
					Name:            "dest",
					Image:           upstreamImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Args:            []string{"--mode=dest"},
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8080},
						{ContainerPort: 8443},
						{ContainerPort: 5353, Protocol: corev1.ProtocolUDP},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)},
						},
						PeriodSeconds: 1,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "tls", MountPath: "/tls", ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "dest-ca-tls"}}},
			},
		},
	}
	mustCreate(destPod)

	destSvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "dest-server", Namespace: ns.Name},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "dest-server"},
			Ports: []corev1.ServicePort{
				{Name: "http", Port: 8080, TargetPort: intstr.FromInt32(8080)},
				{Name: "https", Port: 8443, TargetPort: intstr.FromInt32(8443)},
				{Name: "udp", Port: 5353, Protocol: corev1.ProtocolUDP, TargetPort: intstr.FromInt32(5353)},
			},
		},
	}
	mustCreate(destSvc)

	proxyArgs := []string{"--mode=proxy", "--proxy-addr=:8443", "--admin-addr=:8081"}
	if opts.requireMTLS {
		proxyArgs = append(proxyArgs, "--require-mtls=true")
	}
	if opts.requireBearerAud != "" {
		proxyArgs = append(proxyArgs, "--require-bearer-aud="+opts.requireBearerAud)
	}

	proxyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "upstream-proxy",
			Namespace: ns.Name,
			Labels:    map[string]string{"app": "upstream-proxy"},
		},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken:  new(false),
			TerminationGracePeriodSeconds: new(int64(1)),
			Containers: []corev1.Container{
				{
					Name:            "proxy",
					Image:           upstreamImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Args:            proxyArgs,
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8443},
						{ContainerPort: 8081},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8081)},
						},
						PeriodSeconds: 1,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "tls", MountPath: "/tls", ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "tls", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "upstream-proxy-tls"}}},
			},
		},
	}
	mustCreate(proxyPod)

	proxySvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "upstream-proxy", Namespace: ns.Name},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "upstream-proxy"},
			Ports: []corev1.ServicePort{
				{Name: "https", Port: 8443, TargetPort: intstr.FromInt32(8443)},
				{Name: "admin", Port: 8081, TargetPort: intstr.FromInt32(8081)},
			},
		},
	}
	mustCreate(proxySvc)

	tc.MustWaitForObject(destPod, predicates.ReadyConditionIsTrue)
	tc.MustWaitForObject(proxyPod, predicates.ReadyConditionIsTrue)

	// Wait for EndpointSlices to report Ready endpoints and verify the proxy admin Service
	// responds before creating Sandboxes.
	for _, svcName := range []string{"dest-server", "upstream-proxy"} {
		err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 30*time.Second, true, func(pollCtx context.Context) (bool, error) {
			var esList discoveryv1.EndpointSliceList
			if err := tc.List(pollCtx, &esList, client.InNamespace(ns.Name), client.MatchingLabels{discoveryv1.LabelServiceName: svcName}); err != nil {
				return false, nil
			}
			for i := range esList.Items {
				for _, ep := range esList.Items[i].Endpoints {
					if ep.Conditions.Ready != nil && *ep.Conditions.Ready {
						return true, nil
					}
				}
			}
			return false, nil
		})
		if err != nil {
			t.Fatalf("EndpointSlice for Service %s/%s not ready: %v", ns.Name, svcName, err)
		}
	}
	healthzPath := fmt.Sprintf("/api/v1/namespaces/%s/services/upstream-proxy:8081/proxy/healthz", ns.Name)
	err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 30*time.Second, true, func(pollCtx context.Context) (bool, error) {
		out, _, cmdErr := kubectlRun(pollCtx, "get", "--raw", healthzPath)
		return cmdErr == nil && strings.Contains(out, "ok"), nil
	})
	if err != nil {
		t.Fatalf("upstream-proxy admin endpoint %s not ready: %v", healthzPath, err)
	}

	var gotDestSvc corev1.Service
	if err := tc.Get(ctx, types.NamespacedName{Namespace: ns.Name, Name: "dest-server"}, &gotDestSvc); err != nil {
		t.Fatalf("get dest-server Service: %v", err)
	}

	t.Cleanup(func() {
		if t.Failed() {
			dumpPodLogsBySelector(t, ns.Name, "app=upstream-proxy")
		}
	})

	return &testInfra{
		namespace:     ns.Name,
		upstreamPKI:   upstreamPKI,
		destPKI:       destPKI,
		upstreamAddr:  fmt.Sprintf("https://%s:8443", upstreamFQDN),
		upstreamFQDN:  upstreamFQDN,
		destFQDN:      destFQDN,
		destServiceIP: gotDestSvc.Spec.ClusterIP,
		proxyPodName:  proxyPod.Name,
		destPodName:   destPod.Name,
		upstreamCASec: "upstream-proxy-tls",
		upstreamCACM:  "upstream-ca",
		destCASec:     "dest-ca-tls",
		extraCACM:     "extra-ca",
		clientMTLSSec: "client-mtls",
	}
}

func fetchUpstreamRecords(ctx context.Context, t *testing.T, infra *testInfra) []upstreamProxyRecord {
	t.Helper()
	rawPath := fmt.Sprintf("/api/v1/namespaces/%s/services/upstream-proxy:8081/proxy/records", infra.namespace)
	stdout, stderr, err := kubectlRun(ctx, "get", "--raw", rawPath)
	if err != nil {
		t.Fatalf("fetch upstream records failed: %v (stderr=%s)", err, stderr)
	}
	var recs []upstreamProxyRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &recs); err != nil {
		t.Fatalf("parse upstream records %q: %v", stdout, err)
	}
	return recs
}

func fetchUpstreamStats(ctx context.Context, t *testing.T, infra *testInfra) upstreamProxyStats {
	t.Helper()
	rawPath := fmt.Sprintf("/api/v1/namespaces/%s/services/upstream-proxy:8081/proxy/stats", infra.namespace)
	stdout, stderr, err := kubectlRun(ctx, "get", "--raw", rawPath)
	if err != nil {
		t.Fatalf("fetch upstream stats failed: %v (stderr=%s)", err, stderr)
	}
	var stats upstreamProxyStats
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &stats); err != nil {
		t.Fatalf("parse upstream stats %q: %v", stdout, err)
	}
	return stats
}

func pythonWorkloadPodTemplate(extraEnv ...corev1.EnvVar) sandboxv1beta1.PodTemplate {
	return sandboxv1beta1.PodTemplate{
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken:  new(false),
			TerminationGracePeriodSeconds: new(int64(1)),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot: new(true),
				RunAsUser:    new(int64(1000)),
				RunAsGroup:   new(int64(1000)),
			},
			Containers: []corev1.Container{
				{
					Name:    "agent",
					Image:   sandboxNetE2EWorkloadImage,
					Command: []string{"python3", "-c", "import os, signal, time; signal.signal(signal.SIGTERM, lambda *_: os._exit(0)); time.sleep(3600)"},
					Env:     extraEnv,
					SecurityContext: &corev1.SecurityContext{
						AllowPrivilegeEscalation: new(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					},
				},
			},
		},
	}
}

// TestSandboxNetExplicitProxyDefaultPortAndCATrust validates the end-to-end sandbox-net data path
// on a real Kubernetes cluster with standard GA DRA (zero feature gates):
//   - controller-owned ResourceClaim allocated to a node slot-* device
//   - direct TCP egress blocked via NRI route flush (NetworkPolicyDenyAll)
//   - socketat loopback listener on default port 15001 + all language magic proxy/CA env vars
//   - non-clobbering JAVA_TOOL_OPTIONS merge
//   - cert-manager kubernetes.io/tls Secret + ConfigMap CA trust with private key stripping
//   - HTTPS (CONNECT), plain HTTP (HTTP_PROXY), direct agents.net UDS, and 403 Boundary-Reason denial
//   - attested Agents-Net-* and custom Agents-Net-Param-* headers at the upstream proxy
func TestSandboxNetExplicitProxyDefaultPortAndCATrust(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-default", testUpstreamOpts{})

	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-default",
			Namespace: infra.namespace,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(corev1.EnvVar{
					Name:  "JAVA_TOOL_OPTIONS",
					Value: "-Xmx128m",
				}),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Proxy: &sandboxv1beta1.SandboxExplicitProxyConfig{
						NoProxy: []string{".internal.test"},
					},
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						Address:  infra.upstreamAddr,
						Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP1,
						TLS: &sandboxv1beta1.SandboxUpstreamTLS{
							CACertificateRefs: []sandboxv1beta1.SandboxCASource{
								{
									Type:         sandboxv1beta1.SandboxCASourceTypeConfigMap,
									ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: infra.upstreamCACM},
								},
							},
						},
					},
					CATrust: &sandboxv1beta1.SandboxCATrustSpec{
						Mode:       sandboxv1beta1.SandboxCATrustModeInjectEnv,
						BundleMode: sandboxv1beta1.SandboxCABundleModeAppendSystemRoots,
						Sources: []sandboxv1beta1.SandboxCASource{
							{
								Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
								SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.destCASec},
							},
							{
								Type:         sandboxv1beta1.SandboxCASourceTypeConfigMap,
								ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: infra.extraCACM},
							},
						},
					},
					Parameters: []sandboxv1beta1.SandboxNetworkParameter{
						{Name: "tenant", Value: "team-alpha"},
						{Name: "env", Value: "e2e"},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, sb); err != nil {
		t.Fatalf("create Sandbox: %v", err)
	}
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	// Verify GA ResourceClaim exists, is controller-owned, and is allocated to a node slot-* device.
	var claim resourcev1.ResourceClaim
	if err := tc.Get(ctx, types.NamespacedName{Namespace: infra.namespace, Name: sb.Name + "-network"}, &claim); err != nil {
		t.Fatalf("get ResourceClaim: %v", err)
	}
	if claim.Status.Allocation == nil || len(claim.Status.Allocation.Devices.Results) != 1 {
		t.Fatalf("expected allocated ResourceClaim, got %+v", claim.Status.Allocation)
	}
	allocDev := claim.Status.Allocation.Devices.Results[0]
	if allocDev.Driver != sandboxv1beta1.SandboxNetDriverName || !strings.HasPrefix(allocDev.Device, "slot-") {
		t.Fatalf("unexpected allocated GA DRA device: %+v", allocDev)
	}

	// Verify sandbox-net reports Ready=True in ResourceClaim.status.devices via least-privilege
	// resourceclaims/driver MergePatch (without touching immutable status.allocation).
	err := wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 15*time.Second, true, func(pollCtx context.Context) (bool, error) {
		var updatedClaim resourcev1.ResourceClaim
		if err := tc.Get(pollCtx, types.NamespacedName{Namespace: infra.namespace, Name: claim.Name}, &updatedClaim); err != nil {
			return false, nil
		}
		for _, dev := range updatedClaim.Status.Devices {
			if dev.Driver == sandboxv1beta1.SandboxNetDriverName && dev.Device == allocDev.Device {
				for _, cond := range dev.Conditions {
					if cond.Type == "Ready" && cond.Status == metav1.ConditionTrue && cond.Reason == "SandboxNetPrepared" {
						return true, nil
					}
				}
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("expected ResourceClaim.status.devices Ready=True condition: %v", err)
	}

	var pod corev1.Pod
	if err := tc.Get(ctx, types.NamespacedName{Namespace: infra.namespace, Name: sb.Name}, &pod); err != nil {
		t.Fatalf("get Pod: %v", err)
	}

	// Run in-sandbox verification script exercising env vars, CA trust files, direct egress block,
	// HTTPS via HTTPS_PROXY+SSL_CERT_FILE, plain HTTP via HTTP_PROXY, direct UDS, and 403 denial.
	probeScript := fmt.Sprintf(`
import json, os, socket, ssl, urllib.request

# 1. Verify magic language proxy and CA env vars.
want_proxy = "http://127.0.0.1:15001"
for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "AGENTS_NET_PROXY_URL", "GRPC_PROXY_EXP"):
    assert os.environ.get(k) == want_proxy, f"{k}={os.environ.get(k)!r} != {want_proxy!r}"
assert os.environ.get("NODE_USE_ENV_PROXY") == "1", f"NODE_USE_ENV_PROXY={os.environ.get('NODE_USE_ENV_PROXY')!r}"
assert ".internal.test" in os.environ.get("NO_PROXY", ""), f"NO_PROXY={os.environ.get('NO_PROXY')!r}"
java_opts = os.environ.get("JAVA_TOOL_OPTIONS", "")
assert java_opts.startswith("-Xmx128m "), f"JAVA_TOOL_OPTIONS clobbered: {java_opts!r}"
assert "-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=15001" in java_opts, f"JAVA_TOOL_OPTIONS missing proxy: {java_opts!r}"
for k in ("AGENT_CA_CERT", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT"):
    assert os.environ.get(k) == "/var/run/agent-ca.pem", f"{k}={os.environ.get(k)!r}"
assert os.environ.get("NODE_EXTRA_CA_CERTS") == "/var/run/agent-extra-ca.pem", f"NODE_EXTRA_CA_CERTS={os.environ.get('NODE_EXTRA_CA_CERTS')!r}"

# 2. Verify mounted CA bundles have zero PRIVATE KEY blocks and AppendSystemRoots merged system roots + 2 custom CAs.
merged = open("/var/run/agent-ca.pem", "r").read()
extra = open("/var/run/agent-extra-ca.pem", "r").read()
assert "PRIVATE KEY" not in merged and "PRIVATE KEY" not in extra, "private key leaked into CA bundle"
assert extra.count("BEGIN CERTIFICATE") == 2, f"expected 2 custom CAs in extra bundle, got {extra.count('BEGIN CERTIFICATE')}"
assert merged.count("BEGIN CERTIFICATE") > 2, f"expected system roots + custom CAs in merged bundle, got {merged.count('BEGIN CERTIFICATE')}"

# 3. Direct TCP egress bypassing proxy MUST fail (non-loopback routes flushed by sandbox-net).
direct_blocked = False
try:
    s = socket.create_connection((%q, 8080), timeout=2)
    s.close()
except OSError:
    direct_blocked = True
assert direct_blocked, "direct TCP egress unexpectedly succeeded"

# 4. Standard HTTPS request using ONLY injected HTTPS_PROXY + SSL_CERT_FILE succeeds against custom-CA dest-server.
https_body = json.loads(urllib.request.urlopen("https://%s:8443/via-https", timeout=10).read().decode())
assert https_body["scheme"] == "https" and https_body["path"] == "/via-https", f"bad https_body: {https_body}"

# 5. Plain HTTP request using ONLY injected HTTP_PROXY tunnels through upstream CONNECT and succeeds.
http_body = json.loads(urllib.request.urlopen("http://%s:8080/via-http", timeout=10).read().decode())
assert http_body["scheme"] == "http" and http_body["path"] == "/via-http", f"bad http_body: {http_body}"

# 6. Direct agents.net Unix domain socket (/run/agents.net/egress.sock) CONNECT works.
uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
uds.settimeout(5)
uds.connect(os.environ["AGENTS_NET_EGRESS_SOCKET"])
uds.sendall(b"CONNECT %s:8080 HTTP/1.1\r\nHost: %s:8080\r\n\r\n")
resp = uds.recv(4096).decode("iso-8859-1")
assert resp.startswith("HTTP/1.1 200 "), f"UDS CONNECT failed: {resp!r}"
uds.sendall(b"GET /via-uds HTTP/1.1\r\nHost: %s:8080\r\nConnection: close\r\n\r\n")
uds_data = b""
while True:
    chunk = uds.recv(4096)
    if not chunk:
        break
    uds_data += chunk
uds.close()
assert b"/via-uds" in uds_data, f"UDS HTTP body missing /via-uds: {uds_data!r}"

# 7. Blocked destination returns 403 + Boundary-Reason + Proxy-Status from upstream portal.
blk = socket.create_connection(("127.0.0.1", 15001), timeout=5)
blk.sendall(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
blk_resp = blk.recv(4096).decode("iso-8859-1")
blk.close()
assert blk_resp.startswith("HTTP/1.1 403 "), f"expected 403 for blocked target, got {blk_resp!r}"
assert "Boundary-Reason:" in blk_resp and "blocked-by-portal" in blk_resp, f"missing Boundary-Reason/Proxy-Status: {blk_resp!r}"
print("ALL_CHECKS_PASSED")
`, infra.destServiceIP, infra.destFQDN, infra.destFQDN, infra.destFQDN, infra.destFQDN, infra.destFQDN)

	stdout, stderr, err := execInAgentPod(ctx, t, infra.namespace, pod.Name, "python3", "-c", probeScript)
	if err != nil || !strings.Contains(stdout, "ALL_CHECKS_PASSED") {
		t.Fatalf("in-sandbox probe failed: err=%v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}

	// Verify upstream proxy saw attested Agents-Net-* and custom Agents-Net-Param-* headers.
	recs := fetchUpstreamRecords(ctx, t, infra)
	if len(recs) < 4 {
		t.Fatalf("expected at least 4 upstream records (https, http, uds, blocked), got %d: %+v", len(recs), recs)
	}
	var sawAllow, sawDeny bool
	for _, r := range recs {
		if r.Headers["agents-net-sandbox-namespace"] != infra.namespace {
			t.Fatalf("unexpected namespace header: %+v", r.Headers)
		}
		if r.Headers["agents-net-sandbox-name"] != sb.Name {
			t.Fatalf("unexpected sandbox header: %+v", r.Headers)
		}
		if r.Headers["agents-net-pod-uid"] != string(pod.UID) {
			t.Fatalf("unexpected pod uid header: got %q want %q", r.Headers["agents-net-pod-uid"], pod.UID)
		}
		if r.Headers["agents-net-node-name"] != pod.Spec.NodeName {
			t.Fatalf("unexpected node header: got %q want %q", r.Headers["agents-net-node-name"], pod.Spec.NodeName)
		}
		if r.Headers["agents-net-param-tenant"] != "team-alpha" || r.Headers["agents-net-param-env"] != "e2e" {
			t.Fatalf("missing custom Agents-Net-Param-* headers: %+v", r.Headers)
		}
		if r.Decision == "allow" {
			sawAllow = true
		}
		if r.Decision == "deny" && r.Target == "blocked.example:443" {
			sawDeny = true
		}
	}
	if !sawAllow || !sawDeny {
		t.Fatalf("expected both allow and deny upstream records, got allow=%v deny=%v", sawAllow, sawDeny)
	}
}

// TestSandboxNetCustomProxyPortAndMTLSAuth validates:
//   - parametrizable ExplicitProxy listening port (18080 instead of default 15001)
//   - upstream MTLS authentication using a cert-manager kubernetes.io/tls Secret
//   - upstream.tls.caCertificateRefs reading ca.crt directly from that Secret
//   - caTrust.bundleMode=Replace (no system roots included in /var/run/agent-ca.pem)
func TestSandboxNetCustomProxyPortAndMTLSAuth(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-mtls", testUpstreamOpts{requireMTLS: true})

	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-mtls",
			Namespace: infra.namespace,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Proxy: &sandboxv1beta1.SandboxExplicitProxyConfig{
						Port: new(int32(18080)),
					},
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						Address:  infra.upstreamAddr,
						Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP1,
						TLS: &sandboxv1beta1.SandboxUpstreamTLS{
							CACertificateRefs: []sandboxv1beta1.SandboxCASource{
								{
									Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
									SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.clientMTLSSec},
								},
							},
						},
						Auth: &sandboxv1beta1.SandboxUpstreamAuth{
							Type: sandboxv1beta1.SandboxUpstreamAuthTypeMTLS,
							MTLS: &sandboxv1beta1.SandboxMTLSAuth{
								SecretRef: &corev1.LocalObjectReference{Name: infra.clientMTLSSec},
							},
						},
					},
					CATrust: &sandboxv1beta1.SandboxCATrustSpec{
						Mode:       sandboxv1beta1.SandboxCATrustModeInjectEnv,
						BundleMode: sandboxv1beta1.SandboxCABundleModeReplace,
						Sources: []sandboxv1beta1.SandboxCASource{
							{
								Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
								SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.destCASec},
							},
						},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, sb); err != nil {
		t.Fatalf("create Sandbox: %v", err)
	}
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	probeScript := fmt.Sprintf(`
import json, os, urllib.request

assert os.environ.get("HTTP_PROXY") == "http://127.0.0.1:18080", f"HTTP_PROXY={os.environ.get('HTTP_PROXY')!r}"
assert os.environ.get("HTTPS_PROXY") == "http://127.0.0.1:18080", f"HTTPS_PROXY={os.environ.get('HTTPS_PROXY')!r}"
assert "-Dhttp.proxyPort=18080" in os.environ.get("JAVA_TOOL_OPTIONS", ""), f"JAVA_TOOL_OPTIONS={os.environ.get('JAVA_TOOL_OPTIONS')!r}"

# Replace mode must contain ONLY the 1 custom CA certificate (no system roots).
merged = open("/var/run/agent-ca.pem", "r").read()
assert merged.count("BEGIN CERTIFICATE") == 1, f"Replace mode cert count = {merged.count('BEGIN CERTIFICATE')}, want 1"

body = json.loads(urllib.request.urlopen("https://%s:8443/mtls-ok", timeout=10).read().decode())
assert body["path"] == "/mtls-ok", f"unexpected body: {body}"
print("MTLS_OK")
`, infra.destFQDN)

	stdout, stderr, err := execInAgentPod(ctx, t, infra.namespace, sb.Name, "python3", "-c", probeScript)
	if err != nil || !strings.Contains(stdout, "MTLS_OK") {
		t.Fatalf("mTLS probe failed: err=%v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}

	recs := fetchUpstreamRecords(ctx, t, infra)
	if len(recs) == 0 {
		t.Fatalf("expected upstream records after mTLS request")
	}
	if recs[0].PeerCN != "sandbox-e2e-mtls-client" {
		t.Fatalf("upstream verified client CN = %q, want sandbox-e2e-mtls-client", recs[0].PeerCN)
	}
}

// TestSandboxNetServiceAccountTokenAuth validates ServiceAccountToken Node-mode upstream auth
// (compatible with gke-labs/service-portals TokenReview + node-name attestation).
func TestSandboxNetServiceAccountTokenAuth(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-satoken", testUpstreamOpts{requireBearerAud: "agents.net/upstream"})

	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-satoken",
			Namespace: infra.namespace,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						Address:  infra.upstreamAddr,
						Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP1,
						TLS: &sandboxv1beta1.SandboxUpstreamTLS{
							CACertificateRefs: []sandboxv1beta1.SandboxCASource{
								{
									Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
									SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.upstreamCASec},
								},
							},
						},
						Auth: &sandboxv1beta1.SandboxUpstreamAuth{
							Type: sandboxv1beta1.SandboxUpstreamAuthTypeServiceAccountToken,
							ServiceAccountToken: &sandboxv1beta1.SandboxServiceAccountTokenAuth{
								Audience: "agents.net/upstream",
								Mode:     sandboxv1beta1.SandboxServiceAccountTokenModeNode,
							},
						},
					},
					CATrust: &sandboxv1beta1.SandboxCATrustSpec{
						Mode: sandboxv1beta1.SandboxCATrustModeInjectEnv,
						Sources: []sandboxv1beta1.SandboxCASource{
							{
								Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
								SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.destCASec},
							},
						},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, sb); err != nil {
		t.Fatalf("create Sandbox: %v", err)
	}
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	probeScript := fmt.Sprintf(`
import json, urllib.request
body = json.loads(urllib.request.urlopen("https://%s:8443/jwt-ok", timeout=10).read().decode())
assert body["path"] == "/jwt-ok", f"unexpected body: {body}"
print("JWT_OK")
`, infra.destFQDN)

	stdout, stderr, err := execInAgentPod(ctx, t, infra.namespace, sb.Name, "python3", "-c", probeScript)
	if err != nil || !strings.Contains(stdout, "JWT_OK") {
		t.Fatalf("ServiceAccountToken probe failed: err=%v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}

	recs := fetchUpstreamRecords(ctx, t, infra)
	if len(recs) == 0 {
		t.Fatalf("expected upstream records after JWT-authenticated request")
	}
	wantSub := fmt.Sprintf("system:serviceaccount:%s:%s", sandboxNetSystemNS, sandboxNetDaemonSetName)
	if recs[0].JWTSub != wantSub {
		t.Fatalf("upstream JWT sub = %q, want %q", recs[0].JWTSub, wantSub)
	}
	if recs[0].JWTNode != "" && recs[0].Headers["agents-net-node-name"] != recs[0].JWTNode {
		t.Fatalf("JWT node %q does not match Agents-Net-Node-Name %q", recs[0].JWTNode, recs[0].Headers["agents-net-node-name"])
	}
}

// TestSandboxNetLifecycleSuspendAndResume verifies that suspending a Sandbox deletes both its
// Pod and its controller-owned DRA ResourceClaim (releasing the node slot immediately), and
// resuming recreates both and restores proxied egress.
func TestSandboxNetLifecycleSuspendAndResume(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-lifecycle", testUpstreamOpts{})

	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-lifecycle",
			Namespace: infra.namespace,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						Address:  infra.upstreamAddr,
						Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP1,
						TLS: &sandboxv1beta1.SandboxUpstreamTLS{
							CACertificateRefs: []sandboxv1beta1.SandboxCASource{
								{
									Type:         sandboxv1beta1.SandboxCASourceTypeConfigMap,
									ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: infra.upstreamCACM},
								},
							},
						},
					},
					CATrust: &sandboxv1beta1.SandboxCATrustSpec{
						Mode: sandboxv1beta1.SandboxCATrustModeInjectEnv,
						Sources: []sandboxv1beta1.SandboxCASource{
							{
								Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
								SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.destCASec},
							},
						},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, sb); err != nil {
		t.Fatalf("create Sandbox: %v", err)
	}
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	claimKey := types.NamespacedName{Namespace: infra.namespace, Name: sb.Name + "-network"}
	var initialClaim resourcev1.ResourceClaim
	if err := tc.Get(ctx, claimKey, &initialClaim); err != nil {
		t.Fatalf("expected initial ResourceClaim: %v", err)
	}

	// Suspend the Sandbox -> both Pod and ResourceClaim must be deleted.
	framework.MustUpdateObject(tc.ClusterClient, sb, func(obj *sandboxv1beta1.Sandbox) {
		obj.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeSuspended
	})
	if err := tc.WaitForObjectNotFound(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: sb.Name, Namespace: infra.namespace}}); err != nil {
		t.Fatalf("Pod not deleted on suspend: %v", err)
	}
	if err := tc.WaitForObjectNotFound(ctx, &resourcev1.ResourceClaim{ObjectMeta: metav1.ObjectMeta{Name: claimKey.Name, Namespace: claimKey.Namespace}}); err != nil {
		t.Fatalf("ResourceClaim not deleted on suspend: %v", err)
	}

	// Resume the Sandbox -> new ResourceClaim + Pod are created and HTTPS egress works again.
	framework.MustUpdateObject(tc.ClusterClient, sb, func(obj *sandboxv1beta1.Sandbox) {
		obj.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeRunning
	})
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	var resumedClaim resourcev1.ResourceClaim
	if err := tc.Get(ctx, claimKey, &resumedClaim); err != nil {
		t.Fatalf("expected recreated ResourceClaim after resume: %v", err)
	}
	if resumedClaim.UID == initialClaim.UID {
		t.Fatalf("expected new ResourceClaim UID after resume, still %s", resumedClaim.UID)
	}

	stdout, stderr, err := execInAgentPod(ctx, t, infra.namespace, sb.Name,
		"python3", "-c", fmt.Sprintf("import urllib.request; print(urllib.request.urlopen('https://%s:8443/resumed', timeout=10).read().decode())", infra.destFQDN))
	if err != nil || !strings.Contains(stdout, "/resumed") {
		t.Fatalf("resumed HTTPS request failed: err=%v stdout=%s stderr=%s", err, stdout, stderr)
	}
}

// TestSandboxNetWarmPoolAdoptionIdentitySync validates SandboxTemplate (deny-all NetworkPolicy) +
// SandboxWarmPool + SandboxClaim adoption: once adopted, sandbox-net's Pod informer updates the
// live workload identity so subsequent upstream requests carry Agents-Net-Claim-Name and Claim-Uid.
func TestSandboxNetWarmPoolAdoptionIdentitySync(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-warmpool", testUpstreamOpts{})

	tpl := &extensionsv1beta1.SandboxTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "tpl-net",
			Namespace: infra.namespace,
		},
		Spec: extensionsv1beta1.SandboxTemplateSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						Address:  infra.upstreamAddr,
						Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP1,
						TLS: &sandboxv1beta1.SandboxUpstreamTLS{
							CACertificateRefs: []sandboxv1beta1.SandboxCASource{
								{
									Type:         sandboxv1beta1.SandboxCASourceTypeConfigMap,
									ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: infra.upstreamCACM},
								},
							},
						},
					},
					CATrust: &sandboxv1beta1.SandboxCATrustSpec{
						Mode: sandboxv1beta1.SandboxCATrustModeInjectEnv,
						Sources: []sandboxv1beta1.SandboxCASource{
							{
								Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
								SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.destCASec},
							},
						},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, tpl); err != nil {
		t.Fatalf("create SandboxTemplate: %v", err)
	}

	// Verify SandboxTemplate controller creates a strict deny-all NetworkPolicy under NetworkPolicyDenyAll.
	err := wait.PollUntilContextTimeout(ctx, time.Second, 30*time.Second, true, func(pollCtx context.Context) (bool, error) {
		var npList networkingv1.NetworkPolicyList
		if err := tc.List(pollCtx, &npList, client.InNamespace(infra.namespace)); err != nil {
			return false, nil
		}
		for i := range npList.Items {
			np := &npList.Items[i]
			if len(np.Spec.Ingress) == 0 && len(np.Spec.Egress) == 0 && len(np.Spec.PolicyTypes) == 2 {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("expected strict deny-all NetworkPolicy for SandboxTemplate: %v", err)
	}

	pool := &extensionsv1beta1.SandboxWarmPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pool-net",
			Namespace: infra.namespace,
		},
		Spec: extensionsv1beta1.SandboxWarmPoolSpec{
			Replicas: new(int32(1)),
			TemplateRef: extensionsv1beta1.SandboxTemplateRef{
				Name: tpl.Name,
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, pool); err != nil {
		t.Fatalf("create SandboxWarmPool: %v", err)
	}
	if err := tc.WaitForWarmPoolReady(ctx, types.NamespacedName{Namespace: infra.namespace, Name: pool.Name}); err != nil {
		t.Fatalf("WaitForWarmPoolReady: %v", err)
	}

	// Adopt the warm Sandbox via SandboxClaim.
	claim := &extensionsv1beta1.SandboxClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "claim-adopted",
			Namespace: infra.namespace,
		},
		Spec: extensionsv1beta1.SandboxClaimSpec{
			WarmPoolRef: extensionsv1beta1.SandboxWarmPoolRef{
				Name: pool.Name,
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, claim); err != nil {
		t.Fatalf("create SandboxClaim: %v", err)
	}
	tc.MustWaitForObject(claim, predicates.ReadyConditionIsTrue)

	var gotClaim extensionsv1beta1.SandboxClaim
	if err := tc.Get(ctx, types.NamespacedName{Namespace: infra.namespace, Name: claim.Name}, &gotClaim); err != nil {
		t.Fatalf("get SandboxClaim: %v", err)
	}
	adoptedPodName := gotClaim.Status.SandboxStatus.Name
	if adoptedPodName == "" {
		t.Fatalf("SandboxClaim missing adopted sandbox name: %+v", gotClaim.Status)
	}

	// Poll until sandbox-net's Pod informer observes the adopted claim labels/annotations and
	// stamps Agents-Net-Claim-Name and Agents-Net-Claim-Uid on upstream CONNECT requests.
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 30*time.Second, true, func(pollCtx context.Context) (bool, error) {
		stdout, _, execErr := execInAgentPod(pollCtx, t, infra.namespace, adoptedPodName,
			"python3", "-c", fmt.Sprintf("import urllib.request; print(urllib.request.urlopen('https://%s:8443/adopted', timeout=5).read().decode())", infra.destFQDN))
		if execErr != nil || !strings.Contains(stdout, "/adopted") {
			return false, nil
		}
		recs := fetchUpstreamRecords(pollCtx, t, infra)
		for _, r := range recs {
			if r.Headers["agents-net-claim-name"] == claim.Name && r.Headers["agents-net-claim-uid"] == string(gotClaim.UID) {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("adopted Pod did not propagate Agents-Net-Claim-* headers to upstream: %v (records=%+v)",
			err, fetchUpstreamRecords(ctx, t, infra))
	}
}

// TestSandboxNetDeviceClassDefaultsAndOpaqueOverride validates that cluster administrators can
// define default upstream, proxy port, and custom opaque metadata on a DRA DeviceClass while
// individual Sandboxes reference only deviceClassName and layer per-Sandbox custom parameters.
func TestSandboxNetDeviceClassDefaultsAndOpaqueOverride(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-dc", testUpstreamOpts{})

	classParams := map[string]any{
		"confinementMode": "NetworkPolicyDenyAll",
		"adapterMode":     "ExplicitProxy",
		"proxy": map[string]any{
			"port": 16001,
		},
		"upstream": map[string]any{
			"address":  infra.upstreamAddr,
			"protocol": "HTTP1",
			"tls": map[string]any{
				"caCertificateRefs": []map[string]any{
					{
						"type": "ConfigMap",
						"configMapRef": map[string]any{
							"name": infra.upstreamCACM,
						},
					},
				},
			},
		},
		"caTrust": map[string]any{
			"mode": "InjectEnv",
			"sources": []map[string]any{
				{
					"type": "Secret",
					"secretRef": map[string]any{
						"name": infra.destCASec,
					},
				},
			},
		},
		"custom": map[string]string{
			"cluster-tier": "gold",
			"shared":       "from-class",
		},
	}
	rawClassParams, err := json.Marshal(classParams)
	if err != nil {
		t.Fatalf("marshal DeviceClass opaque params: %v", err)
	}

	dcName := fmt.Sprintf("sandbox-net-e2e-%d", time.Now().UnixNano())
	dc := &resourcev1.DeviceClass{
		ObjectMeta: metav1.ObjectMeta{Name: dcName},
		Spec: resourcev1.DeviceClassSpec{
			Selectors: []resourcev1.DeviceSelector{
				{
					CEL: &resourcev1.CELDeviceSelector{
						Expression: fmt.Sprintf(`device.driver == "%s"`, sandboxv1beta1.SandboxNetDriverName),
					},
				},
			},
			Config: []resourcev1.DeviceClassConfiguration{
				{
					DeviceConfiguration: resourcev1.DeviceConfiguration{
						Opaque: &resourcev1.OpaqueDeviceConfiguration{
							Driver:     sandboxv1beta1.SandboxNetDriverName,
							Parameters: k8sruntime.RawExtension{Raw: rawClassParams},
						},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, dc); err != nil {
		t.Fatalf("create custom DeviceClass: %v", err)
	}

	// Sandbox omits upstream, proxy, and caTrust completely — all inherited from DeviceClass —
	// while layering per-Sandbox custom parameters.
	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-dc-override",
			Namespace: infra.namespace,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					DeviceClassName: dcName,
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Parameters: []sandboxv1beta1.SandboxNetworkParameter{
						{Name: "shared", Value: "from-sandbox"},
						{Name: "workload", Value: "override-test"},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, sb); err != nil {
		t.Fatalf("create Sandbox referencing custom DeviceClass: %v", err)
	}
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	probeScript := fmt.Sprintf(`
import json, os, urllib.request
assert os.environ.get("HTTP_PROXY") == "http://127.0.0.1:16001", f"HTTP_PROXY={os.environ.get('HTTP_PROXY')!r}"
body = json.loads(urllib.request.urlopen("https://%s:8443/dc-ok", timeout=10).read().decode())
assert body["path"] == "/dc-ok", f"unexpected body: {body}"
print("DC_OK")
`, infra.destFQDN)

	stdout, stderr, err := execInAgentPod(ctx, t, infra.namespace, sb.Name, "python3", "-c", probeScript)
	if err != nil || !strings.Contains(stdout, "DC_OK") {
		t.Fatalf("DeviceClass override probe failed: err=%v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}

	recs := fetchUpstreamRecords(ctx, t, infra)
	if len(recs) == 0 {
		t.Fatalf("expected upstream record")
	}
	h := recs[0].Headers
	if h["agents-net-param-cluster-tier"] != "gold" ||
		h["agents-net-param-shared"] != "from-sandbox" ||
		h["agents-net-param-workload"] != "override-test" {
		t.Fatalf("unexpected merged Agents-Net-Param-* headers: %+v", h)
	}
}

// TestSandboxNetIngressViaSandboxRouter validates host-side ingress enforcement end-to-end:
//   - sandbox Pod binds HTTP listeners strictly on 127.0.0.1:8080 (declared in ingressPorts)
//     and 127.0.0.1:9999 (undeclared) so direct PodIP traffic cannot reach them
//   - sandbox-router-go routes traffic through sandbox-net's host HTTP CONNECT bridge (:15080)
//   - declared port 8080 succeeds via socketat.DialAtPath into the Pod loopback
//   - undeclared port 9999 is denied with 403 ingress-port-denied
//   - suspending the Sandbox immediately revokes ingress
func TestSandboxNetIngressViaSandboxRouter(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)

	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("snet-ingress-%d", time.Now().UnixNano()),
		},
	}
	if err := tc.CreateWithCleanup(ctx, ns); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	mustCreate := func(obj client.Object) {
		if err := tc.CreateWithCleanup(ctx, obj); err != nil {
			t.Fatalf("create %T %s/%s: %v", obj, obj.GetNamespace(), obj.GetName(), err)
		}
	}

	// Serve two loopback-only HTTP servers inside the isolated sandbox Pod:
	// 127.0.0.1:8080 (allowed by ingressPorts) and 127.0.0.1:9999 (denied).
	loopbackServersScript := `
import http.server, os, signal, threading
signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
def make_handler(tag):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = f"{tag}:{self.path}".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    return H
s8080 = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), make_handler("loopback-8080"))
s9999 = http.server.ThreadingHTTPServer(("127.0.0.1", 9999), make_handler("loopback-9999"))
threading.Thread(target=s9999.serve_forever, daemon=True).start()
s8080.serve_forever()
`
	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-ingress",
			Namespace: ns.Name,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: sandboxv1beta1.PodTemplate{
					Spec: corev1.PodSpec{
						AutomountServiceAccountToken:  new(false),
						TerminationGracePeriodSeconds: new(int64(1)),
						SecurityContext: &corev1.PodSecurityContext{
							RunAsNonRoot: new(true),
							RunAsUser:    new(int64(1000)),
							RunAsGroup:   new(int64(1000)),
						},
						Containers: []corev1.Container{
							{
								Name:    "agent",
								Image:   sandboxNetE2EWorkloadImage,
								Command: []string{"python3", "-c", loopbackServersScript},
								ReadinessProbe: &corev1.Probe{
									ProbeHandler: corev1.ProbeHandler{
										Exec: &corev1.ExecAction{
											Command: []string{
												"python3", "-c",
												"import socket; [socket.create_connection(('127.0.0.1', p), timeout=1).close() for p in (8080, 9999)]",
											},
										},
									},
									PeriodSeconds: 1,
								},
								SecurityContext: &corev1.SecurityContext{
									AllowPrivilegeEscalation: new(false),
									Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
								},
							},
						},
					},
				},
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					IngressPorts: []sandboxv1beta1.SandboxIngressPort{
						{Port: 8080, Protocol: sandboxv1beta1.SandboxIngressProtocolTCP},
					},
				},
			},
		},
	}
	mustCreate(sb)
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	// Deploy sandbox-router-go scoped to this namespace with Pod cache + sandbox-net ingress enabled.
	mustCreate(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "sandbox-router", Namespace: ns.Name},
	})
	mustCreate(&rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "sandbox-router-pods", Namespace: ns.Name},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "watch"}},
		},
	})
	mustCreate(&rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "sandbox-router-pods", Namespace: ns.Name},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     "sandbox-router-pods",
		},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.ServiceAccountKind, Name: "sandbox-router", Namespace: ns.Name},
		},
	})

	routerPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sandbox-router",
			Namespace: ns.Name,
			Labels:    map[string]string{"app": "sandbox-router"},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName:            "sandbox-router",
			TerminationGracePeriodSeconds: new(int64(1)),
			Containers: []corev1.Container{
				{
					Name:            "router",
					Image:           sandboxRouterGoImage(),
					ImagePullPolicy: corev1.PullIfNotPresent,
					Args: []string{
						"--cache-enabled=true",
						"--cache-namespace=" + ns.Name,
						"--authz-mode=allow-all",
						"--sandbox-net-ingress-port=15080",
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/readyz", Port: intstr.FromInt32(8081)},
						},
						PeriodSeconds: 1,
					},
					SecurityContext: &corev1.SecurityContext{
						RunAsNonRoot:             new(true),
						AllowPrivilegeEscalation: new(false),
						Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					},
				},
			},
		},
	}
	mustCreate(routerPod)
	t.Cleanup(func() {
		if t.Failed() {
			dumpPodLogsBySelector(t, ns.Name, "app=sandbox-router")
		}
	})
	tc.MustWaitForObject(routerPod, predicates.ReadyConditionIsTrue)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local port: %v", err)
	}
	localPort := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	pfCtx, stopPF := context.WithCancel(ctx)
	defer stopPF()
	if err := tc.PortForward(pfCtx, types.NamespacedName{Namespace: ns.Name, Name: routerPod.Name}, localPort, 8080); err != nil {
		t.Fatalf("PortForward sandbox-router: %v", err)
	}

	httpCli := &http.Client{Timeout: 5 * time.Second}
	callRouter := func(port, path string) (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d%s", localPort, path), nil)
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("X-Sandbox-Id", sb.Name)
		req.Header.Set("X-Sandbox-Namespace", ns.Name)
		req.Header.Set("X-Sandbox-Port", port)
		resp, err := httpCli.Do(req)
		if err != nil {
			return 0, "", err
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(body), nil
	}

	// 1. Declared ingress port 8080 reaches the loopback-only server via sandbox-net ingress bridge.
	err = wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 15*time.Second, true, func(_ context.Context) (bool, error) {
		code, body, reqErr := callRouter("8080", "/hello")
		return reqErr == nil && code == http.StatusOK && body == "loopback-8080:/hello", nil
	})
	if err != nil {
		code, body, reqErr := callRouter("8080", "/hello")
		t.Fatalf("allowed ingress port 8080 failed: err=%v last=(code=%d body=%q reqErr=%v)", err, code, body, reqErr)
	}

	// 2. Undeclared port 9999 MUST be rejected with 403 ingress-port-denied by sandbox-net.
	code, body, err := callRouter("9999", "/secret")
	if err != nil {
		t.Fatalf("denied ingress port request failed: %v", err)
	}
	if code != http.StatusForbidden || !strings.Contains(body, "ingress-port-denied") {
		t.Fatalf("undeclared port 9999: status=%d body=%q, want 403 ingress-port-denied", code, body)
	}

	// 3. Suspending the Sandbox deletes the Pod and revokes ingress immediately.
	framework.MustUpdateObject(tc.ClusterClient, sb, func(obj *sandboxv1beta1.Sandbox) {
		obj.Spec.OperatingMode = sandboxv1beta1.SandboxOperatingModeSuspended
	})
	if err := tc.WaitForObjectNotFound(ctx, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: sb.Name, Namespace: ns.Name}}); err != nil {
		t.Fatalf("Pod not deleted on suspend: %v", err)
	}
	err = wait.PollUntilContextTimeout(ctx, 250*time.Millisecond, 10*time.Second, true, func(_ context.Context) (bool, error) {
		c, _, reqErr := callRouter("8080", "/after-suspend")
		return reqErr == nil && c != http.StatusOK, nil
	})
	if err != nil {
		t.Fatalf("ingress still returned 200 after Sandbox suspend: %v", err)
	}
}

// TestSandboxNetHTTP2AndConnectUDP validates:
//   - default upstream.protocol (HTTP2) multiplexed CONNECT over a shared TLS connection
//   - HTTP/2 upstream 403 Proxy-Status forwarding to the sandbox
//   - RFC 9298 connect-udp capsule relay over /run/agents.net/egress.sock to dest-server:5353
func TestSandboxNetHTTP2AndConnectUDP(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-h2-udp", testUpstreamOpts{})

	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-h2-udp",
			Namespace: infra.namespace,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						// Protocol omitted deliberately to test the default HTTP2 path.
						Address: infra.upstreamAddr,
						TLS: &sandboxv1beta1.SandboxUpstreamTLS{
							CACertificateRefs: []sandboxv1beta1.SandboxCASource{
								{
									Type:         sandboxv1beta1.SandboxCASourceTypeConfigMap,
									ConfigMapRef: &sandboxv1beta1.SandboxConfigMapKeyRef{Name: infra.upstreamCACM},
								},
							},
						},
					},
					CATrust: &sandboxv1beta1.SandboxCATrustSpec{
						Mode: sandboxv1beta1.SandboxCATrustModeInjectEnv,
						Sources: []sandboxv1beta1.SandboxCASource{
							{
								Type:      sandboxv1beta1.SandboxCASourceTypeSecret,
								SecretRef: &sandboxv1beta1.SandboxSecretKeyRef{Name: infra.destCASec},
							},
						},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, sb); err != nil {
		t.Fatalf("create Sandbox: %v", err)
	}
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	probeScript := fmt.Sprintf(`
import json, os, socket, urllib.request

# 1. Two HTTPS requests over the default HTTP/2 CONNECT upstream tunnel.
for path in ("/h2-one", "/h2-two"):
    body = json.loads(urllib.request.urlopen(f"https://%s:8443{path}", timeout=10).read().decode())
    assert body["scheme"] == "https" and body["path"] == path, f"bad H2 body: {body}"

# 2. Blocked target over HTTP/2 CONNECT returns 403 + Proxy-Status.
blk = socket.create_connection(("127.0.0.1", 15001), timeout=5)
blk.sendall(b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
blk_resp = blk.recv(4096).decode("iso-8859-1")
blk.close()
assert blk_resp.startswith("HTTP/1.1 403 ") and "blocked-by-portal" in blk_resp, f"bad H2 deny: {blk_resp!r}"

# 3. RFC 9298 connect-udp capsule relay over /run/agents.net/egress.sock to dest-server UDP echo (:5353).
uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
uds.settimeout(10)
uds.connect(os.environ["AGENTS_NET_EGRESS_SOCKET"])
req = (
    "GET /.well-known/masque/udp/%s/5353/ HTTP/1.1\r\n"
    "Host: egress.local\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: connect-udp\r\n"
    "Capsule-Protocol: ?1\r\n\r\n"
).encode("ascii")
uds.sendall(req)

buf = b""
while b"\r\n\r\n" not in buf:
    chunk = uds.recv(4096)
    assert chunk, "EOF waiting for 101 Switching Protocols"
    buf += chunk
head, rest = buf.split(b"\r\n\r\n", 1)
assert head.startswith(b"HTTP/1.1 101 "), f"connect-udp upgrade failed: {head!r}"

# Write RFC 9298 DATAGRAM capsule: type=0, length=1+len(payload), context_id=0, payload.
payload = b"masque-e2e-ping"
capsule = bytes([0, len(payload) + 1, 0]) + payload
uds.sendall(capsule)

want = b"udp-echo:" + payload
while len(rest) < 3 + len(want):
    chunk = uds.recv(4096)
    assert chunk, f"EOF reading UDP echo capsule, got {rest!r}"
    rest += chunk
uds.close()
assert rest[0] == 0 and rest[2] == 0, f"unexpected capsule framing: {rest!r}"
got_len = rest[1] - 1
got_payload = rest[3:3 + got_len]
assert got_payload == want, f"UDP echo mismatch: got {got_payload!r}, want {want!r}"
print("H2_AND_UDP_OK")
`, infra.destFQDN, infra.destFQDN)

	stdout, stderr, err := execInAgentPod(ctx, t, infra.namespace, sb.Name, "python3", "-c", probeScript)
	if err != nil || !strings.Contains(stdout, "H2_AND_UDP_OK") {
		t.Fatalf("HTTP/2 + connect-udp probe failed: err=%v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}

	recs := fetchUpstreamRecords(ctx, t, infra)
	var h2Allow, h2Deny, udpAllow int
	for _, r := range recs {
		switch {
		case r.Transport == "tcp" && r.Protocol == "HTTP/2.0" && r.Decision == "allow":
			h2Allow++
		case r.Transport == "tcp" && r.Protocol == "HTTP/2.0" && r.Decision == "deny":
			h2Deny++
		case r.Transport == "udp" && r.Decision == "allow":
			udpAllow++
		}
	}
	if h2Allow < 2 || h2Deny < 1 || udpAllow < 1 {
		t.Fatalf("expected >=2 H2 allows, >=1 H2 deny, >=1 UDP allow; got h2Allow=%d h2Deny=%d udpAllow=%d records=%+v",
			h2Allow, h2Deny, udpAllow, recs)
	}

	// All 3 TCP requests multiplexed on 1 HTTP/2 TLS conn + 1 HTTP/1.1 TLS conn for connect-udp.
	stats := fetchUpstreamStats(ctx, t, infra)
	if stats.TLSConnections > 2 {
		t.Fatalf("expected HTTP/2 connection multiplexing (<= 2 TLS connections for 3 TCP + 1 UDP), got %d", stats.TLSConnections)
	}
}

// TestSandboxNetClusterTrustBundleAndMountOnly validates:
//   - Kubernetes ClusterTrustBundle (KEP-3257) by exact name for upstream.tls.caCertificateRefs
//   - ClusterTrustBundle by signerName + labelSelector for caTrust.sources
//   - caTrust.mode=MountOnly mounts /var/run/agent-ca.pem WITHOUT injecting CA env vars
func TestSandboxNetClusterTrustBundleAndMountOnly(t *testing.T) {
	tc := framework.NewTestContext(t)
	ctx := t.Context()
	ensureSandboxNetDeployed(t, tc)
	infra := deployTestInfra(t, tc, "snet-ctb", testUpstreamOpts{})

	const signerName = "sandbox-net.e2e.test/ca"
	destCTB := &certificatesv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:   fmt.Sprintf("sandbox-net.e2e.test:ca:%s", infra.namespace),
			Labels: map[string]string{"e2e-run": infra.namespace},
		},
		Spec: certificatesv1beta1.ClusterTrustBundleSpec{
			SignerName:  signerName,
			TrustBundle: string(infra.destPKI.caCertPEM),
		},
	}
	upstreamCTB := &certificatesv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("e2e-upstream-%s", infra.namespace),
		},
		Spec: certificatesv1beta1.ClusterTrustBundleSpec{
			TrustBundle: string(infra.upstreamPKI.caCertPEM),
		},
	}
	if err := tc.CreateWithCleanup(ctx, destCTB); err != nil {
		t.Fatalf("create dest ClusterTrustBundle: %v", err)
	}
	if err := tc.CreateWithCleanup(ctx, upstreamCTB); err != nil {
		t.Fatalf("create upstream ClusterTrustBundle: %v", err)
	}

	sb := &sandboxv1beta1.Sandbox{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sb-ctb-mountonly",
			Namespace: infra.namespace,
		},
		Spec: sandboxv1beta1.SandboxSpec{
			SandboxBlueprint: sandboxv1beta1.SandboxBlueprint{
				PodTemplate: pythonWorkloadPodTemplate(),
				Network: &sandboxv1beta1.SandboxNetworkSpec{
					ConfinementMode: sandboxv1beta1.SandboxConfinementModeNetworkPolicyDenyAll,
					AdapterMode:     sandboxv1beta1.SandboxAdapterModeExplicitProxy,
					Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
						Address: infra.upstreamAddr,
						TLS: &sandboxv1beta1.SandboxUpstreamTLS{
							CACertificateRefs: []sandboxv1beta1.SandboxCASource{
								{
									Type: sandboxv1beta1.SandboxCASourceTypeClusterTrustBundle,
									ClusterTrustBundle: &sandboxv1beta1.SandboxClusterTrustBundleRef{
										Name: upstreamCTB.Name,
									},
								},
							},
						},
					},
					CATrust: &sandboxv1beta1.SandboxCATrustSpec{
						Mode:       sandboxv1beta1.SandboxCATrustModeMountOnly,
						BundleMode: sandboxv1beta1.SandboxCABundleModeAppendSystemRoots,
						Sources: []sandboxv1beta1.SandboxCASource{
							{
								Type: sandboxv1beta1.SandboxCASourceTypeClusterTrustBundle,
								ClusterTrustBundle: &sandboxv1beta1.SandboxClusterTrustBundleRef{
									SignerName: signerName,
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{"e2e-run": infra.namespace},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if err := tc.CreateWithCleanup(ctx, sb); err != nil {
		t.Fatalf("create Sandbox: %v", err)
	}
	tc.MustWaitForObject(sb, predicates.ReadyConditionIsTrue)

	probeScript := fmt.Sprintf(`
import json, os, ssl, urllib.error, urllib.request

# 1. MountOnly must NOT inject any CA env vars.
for k in ("AGENT_CA_CERT", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "PIP_CERT"):
    assert k not in os.environ, f"MountOnly unexpectedly injected {k}={os.environ[k]!r}"

# 2. Bundle files must still be mounted cleanly.
merged = open("/var/run/agent-ca.pem", "r").read()
assert "BEGIN CERTIFICATE" in merged and "PRIVATE KEY" not in merged

# 3. Default HTTPS fails cert verification because SSL_CERT_FILE is not injected.
failed_default = False
try:
    urllib.request.urlopen("https://%s:8443/must-fail", timeout=10)
except (ssl.SSLError, urllib.error.URLError):
    failed_default = True
assert failed_default, "default HTTPS unexpectedly succeeded under MountOnly without SSL_CERT_FILE"

# 4. Explicit cafile=/var/run/agent-ca.pem succeeds using the ClusterTrustBundle CA.
ctx = ssl.create_default_context(cafile="/var/run/agent-ca.pem")
body = json.loads(urllib.request.urlopen("https://%s:8443/mount-only-ok", context=ctx, timeout=10).read().decode())
assert body["path"] == "/mount-only-ok", f"unexpected body: {body}"
print("CTB_MOUNT_ONLY_OK")
`, infra.destFQDN, infra.destFQDN)

	stdout, stderr, err := execInAgentPod(ctx, t, infra.namespace, sb.Name, "python3", "-c", probeScript)
	if err != nil || !strings.Contains(stdout, "CTB_MOUNT_ONLY_OK") {
		t.Fatalf("ClusterTrustBundle + MountOnly probe failed: err=%v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
}
