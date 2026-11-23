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

package proxy

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/agent-sandbox/sandbox-router/cache"
	"sigs.k8s.io/agent-sandbox/sandbox-router/config"
)

type staticSandboxNetLookup struct {
	entry cache.Entry
}

func (s staticSandboxNetLookup) Resolve(namespace, name string, _ types.UID) (cache.Entry, cache.ResolutionSource, bool) {
	if s.entry.Namespace == namespace && s.entry.SandboxName == name {
		return s.entry, cache.ResolutionByName, true
	}
	return cache.Entry{}, 0, false
}

func (s staticSandboxNetLookup) Invalidate(cache.Entry) bool { return false }

func TestSandboxNetIngressRoutingAllowDenyAndMTLS(t *testing.T) {
	// Simulated isolated sandbox HTTP server reached only via the ingress bridge.
	sandboxBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "isolated-ok:"+r.URL.Path)
	}))
	defer sandboxBackend.Close()

	// Build a real CA + server/client certs to test mTLS between sandbox-router and ingress bridge.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "router-ingress-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	issue := func(cn string, isServer bool) (tls.Certificate, []byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		eku := x509.ExtKeyUsageClientAuth
		var ips []net.IP
		if isServer {
			eku = x509.ExtKeyUsageServerAuth
			ips = []net.IP{net.ParseIP("127.0.0.1")}
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			IPAddresses:  ips,
		}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		keyDER, _ := x509.MarshalPKCS8PrivateKey(k)
		cPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, _ := tls.X509KeyPair(cPEM, kPEM)
		return pair, cPEM, kPEM
	}

	srvPair, _, _ := issue("sandbox-net-ingress", true)
	_, cliCertPEM, cliKeyPEM := issue("sandbox-router", false)

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	cliCertPath := filepath.Join(tmpDir, "tls.crt")
	cliKeyPath := filepath.Join(tmpDir, "tls.key")
	_ = os.WriteFile(caPath, caPEM, 0o600)
	_ = os.WriteFile(cliCertPath, cliCertPEM, 0o600)
	_ = os.WriteFile(cliKeyPath, cliKeyPEM, 0o600)

	const targetPodUID = "pod-isolated-uid-1"

	// Minimal fake sandbox-net mTLS HTTP CONNECT ingress bridge allowing only <targetPodUID>:8080.
	bridgeLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	})
	if err != nil {
		t.Fatalf("tls.Listen bridge: %v", err)
	}
	defer func() { _ = bridgeLn.Close() }()

	go func() {
		for {
			c, err := bridgeLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				if req.Host != targetPodUID+":8080" {
					_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: ingress-port-denied\r\nContent-Length: 0\r\n\r\n")
					return
				}
				dst, err := net.DialTimeout("tcp", sandboxBackend.Listener.Addr().String(), 2*time.Second)
				if err != nil {
					_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				defer func() { _ = dst.Close() }()
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(dst, br) }()
				_, _ = io.Copy(conn, dst)
			}(c)
		}
	}()

	_, rawPort, _ := net.SplitHostPort(bridgeLn.Addr().String())
	bridgePort, _ := strconv.Atoi(rawPort)

	cfg := config.Defaults()
	cfg.CacheEnabled = true
	cfg.SandboxNetIngressPort = bridgePort
	cfg.SandboxNetIngressCAFile = caPath
	cfg.SandboxNetIngressCertFile = cliCertPath
	cfg.SandboxNetIngressKeyFile = cliKeyPath
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	// Simulate a PodNetworkIsolated sandbox with EMPTY PodIP, only HostIP + UsesSandboxNet=true.
	handler := NewHandler(Options{
		Config: &cfg,
		Cache: staticSandboxNetLookup{
			entry: cache.Entry{
				SandboxUID:     "sb-uid-1",
				PodUID:         targetPodUID,
				PodIP:          "",
				HostIP:         "127.0.0.1",
				UsesSandboxNet: true,
				SandboxName:    "iso-sb",
				Namespace:      "agents",
			},
		},
	})
	defer handler.Close()

	routerSrv := httptest.NewServer(handler)
	defer routerSrv.Close()

	// 1. Allowed port 8080 reaches the zero-PodIP isolated sandbox over mTLS CONNECT bridge.
	req, _ := http.NewRequest(http.MethodGet, routerSrv.URL+"/api/ping", nil)
	req.Header.Set("X-Sandbox-Id", "iso-sb")
	req.Header.Set("X-Sandbox-Namespace", "agents")
	req.Header.Set("X-Sandbox-Port", "8080")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("allowed ingress request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "isolated-ok:/api/ping" {
		t.Fatalf("allowed response: status=%d body=%q", resp.StatusCode, string(body))
	}

	// 2. Disallowed port 9999 returns 403 Forbidden directly from ErrorHandler without retrying.
	denyReq, _ := http.NewRequest(http.MethodGet, routerSrv.URL+"/secret", nil)
	denyReq.Header.Set("X-Sandbox-Id", "iso-sb")
	denyReq.Header.Set("X-Sandbox-Namespace", "agents")
	denyReq.Header.Set("X-Sandbox-Port", "9999")
	denyResp, err := http.DefaultClient.Do(denyReq)
	if err != nil {
		t.Fatalf("denied ingress request: %v", err)
	}
	denyBody, _ := io.ReadAll(denyResp.Body)
	_ = denyResp.Body.Close()
	if denyResp.StatusCode != http.StatusForbidden || !strings.Contains(string(denyBody), "ingress-port-denied") {
		t.Fatalf("denied response: status=%d body=%q, want 403 ingress-port-denied", denyResp.StatusCode, string(denyBody))
	}
}
