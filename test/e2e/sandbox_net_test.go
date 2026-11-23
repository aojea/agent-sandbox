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
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
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

// testUpstreamProxyScript runs a self-contained TLS/mTLS/JWT HTTP CONNECT upstream proxy
// using Python 3 stdlib so E2E tests exercise the real sandbox-net data path without extra images.
const testUpstreamProxyScript = `
import base64
import http.server
import json
import os
import signal
import socket
import ssl
import sys
import threading

signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

PROXY_PORT = int(os.environ.get("PROXY_PORT", "8443"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "8081"))
REQUIRE_MTLS = os.environ.get("REQUIRE_MTLS", "0") == "1"
REQUIRE_AUD = os.environ.get("REQUIRE_BEARER_AUD", "")
CERT_FILE = "/tls/tls.crt"
KEY_FILE = "/tls/tls.key"
CA_FILE = "/tls/ca.crt"

records_lock = threading.Lock()
records = []

def decode_jwt_payload(token):
    parts = token.split(".")
    if len(parts) < 2:
        return None
    seg = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg.encode("ascii")).decode("utf-8"))
    except Exception:
        return None

def extract_cn(peer_cert):
    if not peer_cert:
        return ""
    for rdn in peer_cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return ""

def relay(src, dst):
    try:
        while True:
            data = src.recv(16384)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass

def read_http_head(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            return None, b""
    if b"\r\n\r\n" not in buf:
        return None, b""
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head.decode("iso-8859-1"), rest

def handle_client(raw_conn, tls_ctx):
    conn = None
    try:
        conn = tls_ctx.wrap_socket(raw_conn, server_side=True)
        peer_cn = extract_cn(conn.getpeercert()) if REQUIRE_MTLS else ""
        head_text, leftover = read_http_head(conn)
        if not head_text:
            return
        lines = head_text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or parts[0] != "CONNECT":
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        target = parts[1]
        hdrs = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()

        jwt_sub = ""
        jwt_aud = []
        jwt_node = ""
        if REQUIRE_AUD:
            authz = hdrs.get("proxy-authorization", "")
            if not authz.startswith("Bearer "):
                conn.sendall(
                    b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                    b'Proxy-Status: test-portal; error=http_request_denied; details="missing-bearer-token"\r\n'
                    b'Content-Length: 0\r\nConnection: close\r\n\r\n'
                )
                return
            payload = decode_jwt_payload(authz[len("Bearer "):].strip())
            if not payload:
                conn.sendall(
                    b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                    b'Proxy-Status: test-portal; error=http_request_denied; details="invalid-jwt"\r\n'
                    b'Content-Length: 0\r\nConnection: close\r\n\r\n'
                )
                return
            aud = payload.get("aud", [])
            if isinstance(aud, str):
                aud = [aud]
            if REQUIRE_AUD not in aud:
                conn.sendall(
                    b'HTTP/1.1 403 Forbidden\r\n'
                    b'Proxy-Status: test-portal; error=http_request_denied; details="bad-audience"\r\n'
                    b'Content-Length: 0\r\nConnection: close\r\n\r\n'
                )
                return
            jwt_sub = payload.get("sub", "")
            jwt_aud = aud
            jwt_node = payload.get("kubernetes.io", {}).get("node", {}).get("name", "")

        decision = "allow"
        if "blocked" in target:
            decision = "deny"

        with records_lock:
            records.append({
                "target": target,
                "headers": hdrs,
                "peer_cn": peer_cn,
                "jwt_sub": jwt_sub,
                "jwt_aud": jwt_aud,
                "jwt_node": jwt_node,
                "decision": decision,
            })

        if decision == "deny":
            conn.sendall(
                b'HTTP/1.1 403 Forbidden\r\n'
                b'Proxy-Status: test-portal; error=http_request_denied; details="blocked-by-portal"\r\n'
                b'Content-Length: 0\r\nConnection: close\r\n\r\n'
            )
            return

        host, port_s = target.rsplit(":", 1)
        host = host.strip("[]")
        port = int(port_s)
        dst = socket.create_connection((host, port), timeout=10)
        try:
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if leftover:
                dst.sendall(leftover)
            t1 = threading.Thread(target=relay, args=(conn, dst), daemon=True)
            t2 = threading.Thread(target=relay, args=(dst, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        finally:
            try:
                dst.close()
            except Exception:
                pass
    except Exception as exc:
        print(f"proxy error: {exc}", file=sys.stderr, flush=True)
    finally:
        try:
            if conn is not None:
                conn.close()
            else:
                raw_conn.close()
        except Exception:
            pass

class AdminHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        if self.path == "/records":
            with records_lock:
                body = json.dumps(records).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass

def main():
    tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    if REQUIRE_MTLS:
        tls_ctx.verify_mode = ssl.CERT_REQUIRED
        tls_ctx.load_verify_locations(cafile=CA_FILE)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PROXY_PORT))
    srv.listen(128)

    # Start /healthz admin server only after PROXY_PORT is listening.
    admin_srv = http.server.ThreadingHTTPServer(("0.0.0.0", ADMIN_PORT), AdminHandler)
    threading.Thread(target=admin_srv.serve_forever, daemon=True).start()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle_client, args=(c, tls_ctx), daemon=True).start()

if __name__ == "__main__":
    main()
`

// testDestServerScript serves both HTTPS (8443, signed by our custom test CA) and plain HTTP (8080).
const testDestServerScript = `
import http.server
import json
import os
import signal
import ssl
import threading

signal.signal(signal.SIGTERM, lambda *_: os._exit(0))

def make_handler(scheme):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/healthz":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok\n")
                return
            body = json.dumps({
                "scheme": scheme,
                "path": self.path,
                "host": self.headers.get("Host", ""),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass
    return Handler

def main():
    http_srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8080), make_handler("http"))
    https_srv = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), make_handler("https"))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="/tls/tls.crt", keyfile="/tls/tls.key")
    https_srv.socket = ctx.wrap_socket(https_srv.socket, server_side=True)

    threading.Thread(target=http_srv.serve_forever, daemon=True).start()
    https_srv.serve_forever()

if __name__ == "__main__":
    main()
`

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
	Target   string            `json:"target"`
	Headers  map[string]string `json:"headers"`
	PeerCN   string            `json:"peer_cn"`
	JWTSub   string            `json:"jwt_sub"`
	JWTAud   []string          `json:"jwt_aud"`
	JWTNode  string            `json:"jwt_node"`
	Decision string            `json:"decision"`
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

func execInPod(ctx context.Context, t *testing.T, ns, pod, container string, command ...string) (string, string, error) {
	t.Helper()
	args := []string{"exec", "-n", ns, pod}
	if container != "" {
		args = append(args, "-c", container)
	}
	args = append(args, "--")
	args = append(args, command...)
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
	mustCreate(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-scripts", Namespace: ns.Name},
		Data: map[string]string{
			"upstream_proxy.py": testUpstreamProxyScript,
			"dest_server.py":    testDestServerScript,
		},
	})

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
					Name:    "dest",
					Image:   sandboxNetE2EWorkloadImage,
					Command: []string{"python3", "/scripts/dest_server.py"},
					Ports: []corev1.ContainerPort{
						{ContainerPort: 8080},
						{ContainerPort: 8443},
					},
					ReadinessProbe: &corev1.Probe{
						ProbeHandler: corev1.ProbeHandler{
							HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)},
						},
						PeriodSeconds: 1,
					},
					VolumeMounts: []corev1.VolumeMount{
						{Name: "scripts", MountPath: "/scripts", ReadOnly: true},
						{Name: "tls", MountPath: "/tls", ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "scripts", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "test-scripts"}}}},
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
			},
		},
	}
	mustCreate(destSvc)

	proxyEnv := []corev1.EnvVar{
		{Name: "PROXY_PORT", Value: "8443"},
		{Name: "ADMIN_PORT", Value: "8081"},
	}
	if opts.requireMTLS {
		proxyEnv = append(proxyEnv, corev1.EnvVar{Name: "REQUIRE_MTLS", Value: "1"})
	}
	if opts.requireBearerAud != "" {
		proxyEnv = append(proxyEnv, corev1.EnvVar{Name: "REQUIRE_BEARER_AUD", Value: opts.requireBearerAud})
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
					Name:    "proxy",
					Image:   sandboxNetE2EWorkloadImage,
					Command: []string{"python3", "/scripts/upstream_proxy.py"},
					Env:     proxyEnv,
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
						{Name: "scripts", MountPath: "/scripts", ReadOnly: true},
						{Name: "tls", MountPath: "/tls", ReadOnly: true},
					},
				},
			},
			Volumes: []corev1.Volume{
				{Name: "scripts", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "test-scripts"}}}},
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

	// Wait for EndpointSlices to report Ready endpoints and verify the proxy Service ClusterIP
	// is reachable from inside the cluster so tests do not race kube-proxy sync.
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
	err := wait.PollUntilContextTimeout(ctx, 500*time.Millisecond, 30*time.Second, true, func(pollCtx context.Context) (bool, error) {
		out, _, execErr := execInPod(pollCtx, t, ns.Name, proxyPod.Name, "proxy",
			"python3", "-c", fmt.Sprintf("import socket; s=socket.create_connection((%q, 8443), timeout=2); s.close(); print('OK')", upstreamFQDN))
		return execErr == nil && strings.Contains(out, "OK"), nil
	})
	if err != nil {
		t.Fatalf("upstream-proxy Service %s:8443 not reachable via kube-proxy: %v", upstreamFQDN, err)
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
	stdout, stderr, err := execInPod(ctx, t, infra.namespace, infra.proxyPodName, "proxy",
		"python3", "-c", "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8081/records', timeout=5).read().decode())")
	if err != nil {
		t.Fatalf("fetch upstream records failed: %v (stderr=%s)", err, stderr)
	}
	var recs []upstreamProxyRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout)), &recs); err != nil {
		t.Fatalf("parse upstream records %q: %v", stdout, err)
	}
	return recs
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

	stdout, stderr, err := execInPod(ctx, t, infra.namespace, pod.Name, "agent", "python3", "-c", probeScript)
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

	stdout, stderr, err := execInPod(ctx, t, infra.namespace, sb.Name, "agent", "python3", "-c", probeScript)
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

	stdout, stderr, err := execInPod(ctx, t, infra.namespace, sb.Name, "agent", "python3", "-c", probeScript)
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

	stdout, stderr, err := execInPod(ctx, t, infra.namespace, sb.Name, "agent",
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
		stdout, _, execErr := execInPod(pollCtx, t, infra.namespace, adoptedPodName, "agent",
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

	stdout, stderr, err := execInPod(ctx, t, infra.namespace, sb.Name, "agent", "python3", "-c", probeScript)
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
