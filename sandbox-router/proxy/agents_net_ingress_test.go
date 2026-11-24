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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/agent-sandbox/sandbox-router/cache"
	"sigs.k8s.io/agent-sandbox/sandbox-router/config"
)

type mapAgentsNetLookup struct {
	entries       map[string]cache.Entry
	invalidations atomic.Int32
}

func (m *mapAgentsNetLookup) Resolve(namespace, name string, _ types.UID) (cache.Entry, cache.ResolutionSource, bool) {
	if e, ok := m.entries[namespace+"/"+name]; ok {
		return e, cache.ResolutionByName, true
	}
	return cache.Entry{}, 0, false
}

func (m *mapAgentsNetLookup) Invalidate(cache.Entry) bool {
	m.invalidations.Add(1)
	return true
}

type fakeConnectBridge struct {
	ln    net.Listener
	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

func startFakeConnectBridge(t *testing.T, tlsCfg *tls.Config, handler func(conn net.Conn, br *bufio.Reader, req *http.Request) (dstAddr string, handled bool)) *fakeConnectBridge {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen bridge: %v", err)
	}
	b := &fakeConnectBridge{
		ln:    ln,
		conns: make(map[net.Conn]struct{}),
	}
	b.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.track(c)
			b.wg.Go(func() {
				defer b.closeConn(c)
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				dstAddr, handled := handler(c, br, req)
				if handled {
					return
				}
				dst, err := net.DialTimeout("tcp", dstAddr, 2*time.Second)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				b.track(dst)
				defer b.closeConn(dst)
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				var pipeWG sync.WaitGroup
				pipeWG.Go(func() {
					_, _ = io.Copy(dst, br)
					if cw, ok := dst.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
					}
				})
				_, _ = io.Copy(c, dst)
				_ = c.Close()
				_ = dst.Close()
				pipeWG.Wait()
			})
		}
	})
	return b
}

func (b *fakeConnectBridge) track(c net.Conn) {
	b.mu.Lock()
	b.conns[c] = struct{}{}
	b.mu.Unlock()
}

func (b *fakeConnectBridge) closeConn(c net.Conn) {
	b.mu.Lock()
	delete(b.conns, c)
	b.mu.Unlock()
	_ = c.Close()
}

func (b *fakeConnectBridge) Port() int {
	_, rawPort, _ := net.SplitHostPort(b.ln.Addr().String())
	p, _ := strconv.Atoi(rawPort)
	return p
}

func (b *fakeConnectBridge) Close() {
	_ = b.ln.Close()
	b.mu.Lock()
	for c := range b.conns {
		_ = c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

func TestAgentsNetIngressRoutingAllowDenyAndMTLS(t *testing.T) {
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

	srvPair, _, _ := issue("dra-agents-net-ingress", true)
	_, cliCertPEM, cliKeyPEM := issue("sandbox-router", false)

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	cliCertPath := filepath.Join(tmpDir, "tls.crt")
	cliKeyPath := filepath.Join(tmpDir, "tls.key")
	_ = os.WriteFile(caPath, caPEM, 0o600)
	_ = os.WriteFile(cliCertPath, cliCertPEM, 0o600)
	_ = os.WriteFile(cliKeyPath, cliKeyPEM, 0o600)

	const targetPodUID = "pod-isolated-uid-1"

	// Minimal fake agents.net mTLS HTTP CONNECT ingress bridge allowing only <targetPodUID>:8080.
	bridge := startFakeConnectBridge(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvPair},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}, func(conn net.Conn, _ *bufio.Reader, req *http.Request) (string, bool) {
		if req.Host != targetPodUID+":8080" {
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: ingress-port-denied\r\nContent-Length: 0\r\n\r\n")
			return "", true
		}
		return sandboxBackend.Listener.Addr().String(), false
	})

	cfg := config.Defaults()
	cfg.CacheEnabled = true
	cfg.AgentsNetIngressPort = bridge.Port()
	cfg.AgentsNetIngressCAFile = caPath
	cfg.AgentsNetIngressCertFile = cliCertPath
	cfg.AgentsNetIngressKeyFile = cliKeyPath
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	// Simulate a PodNetworkIsolated sandbox with EMPTY PodIP, only HostIP + UsesAgentsNet=true.
	lookup := &mapAgentsNetLookup{
		entries: map[string]cache.Entry{
			"agents/iso-sb": {
				SandboxUID:    "sb-uid-1",
				PodUID:        targetPodUID,
				PodIP:         "",
				HostIP:        "127.0.0.1",
				UsesAgentsNet: true,
				SandboxName:   "iso-sb",
				Namespace:     "agents",
			},
		},
	}
	handler := NewHandler(Options{
		Config: &cfg,
		Cache:  lookup,
	})
	routerSrv := httptest.NewServer(handler)
	httpClient := &http.Client{Transport: &http.Transport{}}
	defer func() {
		httpClient.CloseIdleConnections()
		handler.Close()
		bridge.Close()
		routerSrv.Close()
	}()

	// 1. Allowed port 8080 reaches the zero-PodIP isolated sandbox over mTLS CONNECT bridge.
	req, _ := http.NewRequest(http.MethodGet, routerSrv.URL+"/api/ping", nil)
	req.Header.Set("X-Sandbox-Id", "iso-sb")
	req.Header.Set("X-Sandbox-Namespace", "agents")
	req.Header.Set("X-Sandbox-Port", "8080")
	resp, err := httpClient.Do(req)
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
	denyResp, err := httpClient.Do(denyReq)
	if err != nil {
		t.Fatalf("denied ingress request: %v", err)
	}
	denyBody, _ := io.ReadAll(denyResp.Body)
	_ = denyResp.Body.Close()
	if denyResp.StatusCode != http.StatusForbidden || !strings.Contains(string(denyBody), "ingress-port-denied") {
		t.Fatalf("denied response: status=%d body=%q, want 403 ingress-port-denied", denyResp.StatusCode, string(denyBody))
	}
	if got := lookup.invalidations.Load(); got != 0 {
		t.Fatalf("expected 0 cache invalidations on 403 ingress denial, got %d", got)
	}
}

func TestAgentsNetIngressRetriesPoolIsolationGRPCWebSocketAndServerName(t *testing.T) {
	// 1. Two distinct backends proving per-PodUID connection pool isolation on the same HostIP.
	backendA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			line, _ := brw.ReadString('\n')
			_, _ = io.WriteString(conn, "ws-echo:"+line)
			return
		}
		_, _ = io.WriteString(w, "backend-A:"+r.URL.Path)
	}))
	defer backendA.Close()

	// Backend B serves h2c (unencrypted HTTP/2) to exercise native gRPC over the agents.net bridge.
	var h2cProtos http.Protocols
	h2cProtos.SetHTTP1(true)
	h2cProtos.SetUnencryptedHTTP2(true)
	backendB := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "grpc-ok")
			w.Header().Set("Grpc-Status", "0")
			return
		}
		_, _ = io.WriteString(w, "backend-B:"+r.URL.Path)
	}))
	backendB.Config.Protocols = &h2cProtos
	backendB.Start()
	defer backendB.Close()

	// Build CA + server cert carrying ONLY a DNS SAN (no IP SAN) to test AgentsNetIngressServerName.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sni-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "dra-agents-net.local"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"dra-agents-net.local"},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	srvPair := tls.Certificate{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}

	caPath := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(caPath, caPEM, 0o600)

	var (
		pod404Hits atomic.Int32
		pod503Hits atomic.Int32
	)
	bridge := startFakeConnectBridge(t, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvPair},
	}, func(conn net.Conn, _ *bufio.Reader, req *http.Request) (string, bool) {
		switch req.Host {
		case "pod-a:8080":
			return backendA.Listener.Addr().String(), false
		case "pod-b:8080":
			return backendB.Listener.Addr().String(), false
		case "pod-404:8080":
			pod404Hits.Add(1)
			_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nBoundary-Reason: unknown-sandbox\r\nContent-Length: 0\r\n\r\n")
			return "", true
		case "pod-flaky:8080":
			if pod503Hits.Add(1) == 1 {
				_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nBoundary-Reason: sandbox-not-ready\r\nContent-Length: 0\r\n\r\n")
				return "", true
			}
			return backendA.Listener.Addr().String(), false
		case "pod-503-always:8080":
			_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\nBoundary-Reason: sandbox-not-ready\r\nContent-Length: 0\r\n\r\n")
			return "", true
		default:
			_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nBoundary-Reason: ingress-port-denied\r\nContent-Length: 0\r\n\r\n")
			return "", true
		}
	})

	cfg := config.Defaults()
	cfg.CacheEnabled = true
	cfg.UpstreamMaxRetries = 2
	cfg.UpstreamRetryInitialDelay = 10 * time.Millisecond
	cfg.UpstreamRetryMaxDelay = 20 * time.Millisecond
	cfg.AgentsNetIngressPort = bridge.Port()
	cfg.AgentsNetIngressCAFile = caPath
	cfg.AgentsNetIngressServerName = "dra-agents-net.local"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	lookup := &mapAgentsNetLookup{
		entries: map[string]cache.Entry{
			// NetworkPolicyDenyAll sandbox: has PodIP AND UsesAgentsNet=true -> must still use bridge!
			"agents/sb-a": {
				SandboxUID: "sb-a", PodUID: "pod-a", PodIP: "192.0.2.10", HostIP: "127.0.0.1",
				UsesAgentsNet: true, SandboxName: "sb-a", Namespace: "agents",
			},
			// PodNetworkIsolated sandbox on the SAME HostIP (zero PodIP).
			"agents/sb-b": {
				SandboxUID: "sb-b", PodUID: "pod-b", PodIP: "", HostIP: "127.0.0.1",
				UsesAgentsNet: true, SandboxName: "sb-b", Namespace: "agents",
			},
			"agents/sb-404": {
				SandboxUID: "sb-404", PodUID: "pod-404", PodIP: "", HostIP: "127.0.0.1",
				UsesAgentsNet: true, SandboxName: "sb-404", Namespace: "agents",
			},
			"agents/sb-flaky": {
				SandboxUID: "sb-flaky", PodUID: "pod-flaky", PodIP: "", HostIP: "127.0.0.1",
				UsesAgentsNet: true, SandboxName: "sb-flaky", Namespace: "agents",
			},
			"agents/sb-503": {
				SandboxUID: "sb-503", PodUID: "pod-503-always", PodIP: "", HostIP: "127.0.0.1",
				UsesAgentsNet: true, SandboxName: "sb-503", Namespace: "agents",
			},
		},
	}

	handler := NewHandler(Options{Config: &cfg, Cache: lookup})
	routerSrv := httptest.NewUnstartedServer(handler)
	routerSrv.Config.Protocols = &h2cProtos
	routerSrv.Start()
	httpClient := &http.Client{Transport: &http.Transport{}}
	var h2cOnly http.Protocols
	h2cOnly.SetUnencryptedHTTP2(true)
	h2Client := &http.Client{
		Transport: &http.Transport{
			Protocols: &h2cOnly,
		},
	}
	defer func() {
		h2Client.CloseIdleConnections()
		httpClient.CloseIdleConnections()
		handler.Close()
		bridge.Close()
		routerSrv.Close()
	}()

	doHTTP := func(sbID, path string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, routerSrv.URL+path, nil)
		req.Header.Set("X-Sandbox-Id", sbID)
		req.Header.Set("X-Sandbox-Namespace", "agents")
		req.Header.Set("X-Sandbox-Port", "8080")
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("HTTP %s %s: %v", sbID, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// 1. Per-PodUID connection pool isolation + NetworkPolicyDenyAll routing + AgentsNetIngressServerName.
	if status, body := doHTTP("sb-a", "/one"); status != http.StatusOK || body != "backend-A:/one" {
		t.Fatalf("sb-a: status=%d body=%q, want 200 backend-A:/one", status, body)
	}
	if status, body := doHTTP("sb-b", "/two"); status != http.StatusOK || body != "backend-B:/two" {
		t.Fatalf("sb-b: status=%d body=%q, want 200 backend-B:/two", status, body)
	}

	// 2. 404 unknown-sandbox is NOT retried and does NOT invalidate cache.
	if status, _ := doHTTP("sb-404", "/check"); status != http.StatusNotFound {
		t.Fatalf("sb-404 status = %d, want 404", status)
	}
	if got := pod404Hits.Load(); got != 1 {
		t.Fatalf("expected 404 to hit bridge exactly once (no retries), got %d", got)
	}

	// 3. Transient 503 sandbox-not-ready IS retried and succeeds on attempt 2.
	if status, body := doHTTP("sb-flaky", "/retry"); status != http.StatusOK || body != "backend-A:/retry" {
		t.Fatalf("sb-flaky: status=%d body=%q, want 200 backend-A:/retry", status, body)
	}
	if got := pod503Hits.Load(); got != 2 {
		t.Fatalf("expected 503 to retry and hit bridge twice, got %d", got)
	}

	// 4. Exhausted 503 returns 503 and does NOT invalidate zero-PodIP cache entry.
	if status, _ := doHTTP("sb-503", "/down"); status != http.StatusServiceUnavailable {
		t.Fatalf("sb-503 status = %d, want 503", status)
	}
	if got := lookup.invalidations.Load(); got != 0 {
		t.Fatalf("expected 0 cache invalidations for zero-PodIP agents.net pods, got %d", got)
	}

	// 5. WebSocket upgrade tunnels cleanly through the agents.net ingress bridge.
	rawConn, err := net.DialTimeout("tcp", routerSrv.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial router for ws: %v", err)
	}
	defer func() { _ = rawConn.Close() }()
	_ = rawConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(rawConn, "GET /ws HTTP/1.1\r\nHost: router\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Sandbox-Id: sb-a\r\nX-Sandbox-Namespace: agents\r\nX-Sandbox-Port: 8080\r\n\r\n")
	wsBR := bufio.NewReader(rawConn)
	wsLine, err := wsBR.ReadString('\n')
	if err != nil || !strings.HasPrefix(wsLine, "HTTP/1.1 101 ") {
		t.Fatalf("WebSocket upgrade status = %q err=%v, want 101", wsLine, err)
	}
	for {
		hl, err := wsBR.ReadString('\n')
		if err != nil || hl == "\r\n" {
			break
		}
	}
	_, _ = io.WriteString(rawConn, "hello-ws\n")
	if got, err := wsBR.ReadString('\n'); err != nil || got != "ws-echo:hello-ws\n" {
		t.Fatalf("WebSocket echo = %q err=%v, want ws-echo:hello-ws", got, err)
	}

	// 6. Native gRPC (h2c) tunnels cleanly through the agents.net bridge, and 503 maps to codes.Unavailable (14).
	grpcReq, _ := http.NewRequest(http.MethodPost, routerSrv.URL+"/pkg.Svc/Call", strings.NewReader("req"))
	grpcReq.Header.Set("Content-Type", "application/grpc")
	grpcReq.Header.Set("X-Sandbox-Id", "sb-b")
	grpcReq.Header.Set("X-Sandbox-Namespace", "agents")
	grpcReq.Header.Set("X-Sandbox-Port", "8080")
	grpcResp, err := h2Client.Do(grpcReq)
	if err != nil {
		t.Fatalf("gRPC over agents.net bridge: %v", err)
	}
	grpcBody, _ := io.ReadAll(grpcResp.Body)
	_ = grpcResp.Body.Close()
	if grpcResp.StatusCode != http.StatusOK || string(grpcBody) != "grpc-ok" || grpcResp.Trailer.Get("Grpc-Status") != "0" {
		t.Fatalf("gRPC response: status=%d body=%q trailer=%v", grpcResp.StatusCode, string(grpcBody), grpcResp.Trailer)
	}

	grpc503Req, _ := http.NewRequest(http.MethodPost, routerSrv.URL+"/pkg.Svc/Down", strings.NewReader("req"))
	grpc503Req.Header.Set("Content-Type", "application/grpc")
	grpc503Req.Header.Set("X-Sandbox-Id", "sb-503")
	grpc503Req.Header.Set("X-Sandbox-Namespace", "agents")
	grpc503Req.Header.Set("X-Sandbox-Port", "8080")
	grpc503Resp, err := h2Client.Do(grpc503Req)
	if err != nil {
		t.Fatalf("gRPC 503 request: %v", err)
	}
	_, _ = io.ReadAll(grpc503Resp.Body)
	_ = grpc503Resp.Body.Close()
	if got := grpc503Resp.Trailer.Get("Grpc-Status"); got != "14" {
		t.Fatalf("gRPC 503 Grpc-Status = %q, want 14 (Unavailable)", got)
	}
}
