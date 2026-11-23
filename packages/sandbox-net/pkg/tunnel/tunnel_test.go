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

package tunnel

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/auth"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw := strings.TrimSpace(s.buf.String())
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\n")
}

func generateTestCerts(t *testing.T) (caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM []byte, caPool *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPool = x509.NewCertPool()
	caPool.AddCert(caCert)

	issue := func(cn string, isServer bool) ([]byte, []byte) {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<60))
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			DNSNames:     []string{"upstream.local"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		if isServer {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &k.PublicKey, caKey)
		if err != nil {
			t.Fatalf("leaf cert: %v", err)
		}
		kDER, _ := x509.MarshalPKCS8PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kDER})
	}
	srvCertPEM, srvKeyPEM = issue("upstream.local", true)
	cliCertPEM, cliKeyPEM = issue("sandbox-node-1", false)
	return
}

func TestTunnelHTTP2MTLSForwardingDenyAndRevoke(t *testing.T) {
	ctx := t.Context()
	caPEM, srvCertPEM, srvKeyPEM, cliCertPEM, cliKeyPEM, caPool := generateTestCerts(t)

	srvPair, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("server pair: %v", err)
	}

	var mu sync.Mutex
	var lastHeaders http.Header
	var lastPeerCN string

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastHeaders = r.Header.Clone()
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			lastPeerCN = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		mu.Unlock()

		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if strings.HasPrefix(r.Host, "blocked.example:") {
			w.Header().Set("Proxy-Status", `portal; error=http_request_denied; details="policy-blocked"`)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Echo tunnel back to the client.
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{srvPair},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		NextProtos:   []string{"h2"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	srv := &http.Server{
		Handler:   handler,
		TLSConfig: tlsCfg,
		Protocols: new(http.Protocols),
	}
	srv.Protocols.SetHTTP2(true)
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	certDir := t.TempDir()
	caPath := filepath.Join(certDir, "ca.crt")
	_ = os.WriteFile(caPath, caPEM, 0o600)
	_ = os.WriteFile(filepath.Join(certDir, "tls.crt"), cliCertPEM, 0o600)
	_ = os.WriteFile(filepath.Join(certDir, "tls.key"), cliKeyPEM, 0o600)

	auditBuf := &syncBuffer{}
	resolver := auth.NewResolver(auth.ResolverConfig{})
	defer func() { _ = resolver.Close() }()
	mgr, err := NewManager(t.TempDir(), resolver, WithAuditWriter(auditBuf), WithTimeouts(3*time.Second, 3*time.Second))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	podUID := types.UID("pod-h2-mtls")
	paths, err := mgr.EnsureListener(ctx, podUID, ListenerConfig{
		Identity: auth.WorkloadIdentity{
			Namespace:      "agents",
			PodName:        "sb-1",
			PodUID:         podUID,
			ServiceAccount: "agent-sa",
			NodeName:       "node-1",
			SandboxName:    "sb-1",
			Custom:         map[string]string{"tenant": "team-a"},
		},
		Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
			Address:  "https://" + ln.Addr().String(),
			Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP2,
			TLS: &sandboxv1beta1.SandboxUpstreamTLS{
				ServerName: "upstream.local",
				CACertificateRefs: []sandboxv1beta1.SandboxCASource{
					{Type: sandboxv1beta1.SandboxCASourceTypeHostPath, HostPath: caPath},
				},
			},
			Auth: &sandboxv1beta1.SandboxUpstreamAuth{
				Type: sandboxv1beta1.SandboxUpstreamAuthTypeMTLS,
				MTLS: &sandboxv1beta1.SandboxMTLSAuth{CertDir: certDir},
			},
		},
	})
	if err != nil {
		t.Fatalf("EnsureListener: %v", err)
	}

	// 1. Upstream denial propagates status 403 + Boundary-Reason + Proxy-Status header back to sandbox.
	denyResp := sendRawRequest(t, paths.EgressSocketPath,
		"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n")
	if !strings.HasPrefix(denyResp, "HTTP/1.1 403 ") || !strings.Contains(denyResp, "policy-blocked") || !strings.Contains(denyResp, "Boundary-Reason:") {
		t.Fatalf("denied response = %q, want 403 with policy-blocked and Boundary-Reason", denyResp)
	}

	// Verify AttachListener (used by socketat Pod-loopback in ExplicitProxy mode) shares the exact same tunnel pipeline.
	loopLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	if err := mgr.AttachListener(podUID, loopLn); err != nil {
		t.Fatalf("AttachListener: %v", err)
	}
	tcpConn, err := net.DialTimeout("tcp", loopLn.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial attached loopback listener: %v", err)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(tcpConn, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
	tbr := bufio.NewReader(tcpConn)
	tStatus, err := tbr.ReadString('\n')
	if err != nil || !strings.HasPrefix(tStatus, "HTTP/1.1 200 ") {
		t.Fatalf("loopback CONNECT status = %q err=%v, want 200", tStatus, err)
	}
	_, _ = tbr.ReadString('\n')
	_, _ = io.WriteString(tcpConn, "ping-loopback\n")
	if line, err := tbr.ReadString('\n'); err != nil || line != "ping-loopback\n" {
		t.Fatalf("loopback echo = %q err=%v, want ping-loopback", line, err)
	}
	_ = tcpConn.Close()

	// 2. Allowed destination opens multiplexed HTTP/2 CONNECT tunnel over mTLS with attested headers.
	c, err := net.DialTimeout("unix", paths.EgressSocketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial egress.sock: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")

	br := bufio.NewReader(c)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(statusLine, "HTTP/1.1 200 ") {
		t.Fatalf("CONNECT status = %q err=%v, want 200", statusLine, err)
	}
	_, _ = br.ReadString('\n') // blank line

	_, _ = io.WriteString(c, "ping-h2-mtls\n")
	got, err := br.ReadString('\n')
	if err != nil || got != "ping-h2-mtls\n" {
		t.Fatalf("echo = %q err=%v, want ping-h2-mtls", got, err)
	}

	mu.Lock()
	peerCN := lastPeerCN
	hdrs := lastHeaders.Clone()
	mu.Unlock()
	if peerCN != "sandbox-node-1" {
		t.Fatalf("upstream peer CN = %q, want sandbox-node-1", peerCN)
	}
	if hdrs.Get(auth.HeaderSandboxNamespace) != "agents" || hdrs.Get(auth.HeaderCustomPrefix+"tenant") != "team-a" {
		t.Fatalf("missing attested identity headers: %+v", hdrs)
	}

	// 3. Immediate Revoke terminates active H2 tunnel cleanly.
	mgr.Revoke(podUID)
	buf := make([]byte, 16)
	if _, err := br.Read(buf); err == nil {
		t.Fatalf("expected active tunnel read to fail after Revoke")
	}
	// Close manager to wait for serveConn goroutines to flush final audit records.
	mgr.Close()

	// Verify audit JSONL recorded both deny and allow.
	var sawAllow, sawDeny bool
	for _, line := range auditBuf.Lines() {
		var rec AuditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("invalid audit JSON: %v", err)
		}
		if rec.Decision == "allow" && rec.AuthMode == auth.AuthModeMTLS {
			sawAllow = true
		}
		if rec.Decision == "deny" && rec.UpstreamStatus == 403 {
			sawDeny = true
		}
	}
	if !sawAllow || !sawDeny {
		t.Fatalf("expected both allow and deny audit records, got allow=%v deny=%v", sawAllow, sawDeny)
	}
}

func TestTunnelHTTP1ConnectUDPAndServiceAccountToken(t *testing.T) {
	ctx := t.Context()
	caPEM, srvCertPEM, srvKeyPEM, _, _, _ := generateTestCerts(t)
	srvPair, _ := tls.X509KeyPair(srvCertPEM, srvKeyPEM)

	var mu sync.Mutex
	var gotProxyAuth string
	var gotClaimName string

	// Minimal RFC 9298 connect-udp + HTTP/1.1 CONNECT echo upstream server.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srvPair},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				mu.Lock()
				gotProxyAuth = req.Header.Get("Proxy-Authorization")
				gotClaimName = req.Header.Get(auth.HeaderClaimName)
				mu.Unlock()

				if req.Method == http.MethodGet && strings.EqualFold(req.Header.Get("Upgrade"), "connect-udp") {
					_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
					cs := NewCapsuleStream(br, c)
					for {
						dg, err := cs.ReadDatagram()
						if err != nil {
							return
						}
						if err := cs.WriteDatagram(dg); err != nil {
							return
						}
					}
				}
			}(conn)
		}
	}()

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	_ = os.WriteFile(caPath, caPEM, 0o600)
	tokPath := filepath.Join(tmpDir, "node-token")
	_ = os.WriteFile(tokPath, []byte("jwt-upstream-token"), 0o600)

	resolver := auth.NewResolver(auth.ResolverConfig{DefaultNodeTokenPath: tokPath})
	defer func() { _ = resolver.Close() }()
	mgr, err := NewManager(t.TempDir(), resolver, WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	podUID := types.UID("pod-udp-jwt")
	paths, err := mgr.EnsureListener(ctx, podUID, ListenerConfig{
		Identity: auth.WorkloadIdentity{
			Namespace: "agents",
			PodName:   "warm-1",
			PodUID:    podUID,
			NodeName:  "node-1",
		},
		Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
			Address:  "https://" + ln.Addr().String(),
			Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP1,
			TLS: &sandboxv1beta1.SandboxUpstreamTLS{
				ServerName: "upstream.local",
				CACertificateRefs: []sandboxv1beta1.SandboxCASource{
					{Type: sandboxv1beta1.SandboxCASourceTypeHostPath, HostPath: caPath},
				},
			},
			Auth: &sandboxv1beta1.SandboxUpstreamAuth{
				Type: sandboxv1beta1.SandboxUpstreamAuthTypeServiceAccountToken,
				ServiceAccountToken: &sandboxv1beta1.SandboxServiceAccountTokenAuth{
					Audience: "https://upstream.local",
					Mode:     sandboxv1beta1.SandboxServiceAccountTokenModeNode,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("EnsureListener: %v", err)
	}

	// Simulate warm pool SandboxClaim adoption updating attested metadata.
	mgr.UpdateIdentity(podUID, auth.WorkloadIdentity{
		Namespace: "agents",
		PodName:   "warm-1",
		PodUID:    podUID,
		NodeName:  "node-1",
		ClaimUID:  "claim-uid-42",
		ClaimName: "claim-alpha",
	}, true)

	// Open RFC 9298 connect-udp tunnel and echo a datagram capsule end-to-end.
	c, err := net.DialTimeout("unix", paths.EgressSocketPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial egress.sock: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c,
		"GET /.well-known/masque/udp/1.1.1.1/53/ HTTP/1.1\r\n"+
			"Host: egress.local\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: connect-udp\r\n"+
			"Capsule-Protocol: ?1\r\n\r\n")

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("connect-udp status = %v err=%v, want 101", resp, err)
	}

	cs := NewCapsuleStream(br, c)
	if err := cs.WriteDatagram([]byte("dns-query-payload")); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	echoed, err := cs.ReadDatagram()
	if err != nil || string(echoed) != "dns-query-payload" {
		t.Fatalf("ReadDatagram = %q err=%v, want dns-query-payload", string(echoed), err)
	}

	mu.Lock()
	pa := gotProxyAuth
	cn := gotClaimName
	mu.Unlock()
	if pa != "Bearer jwt-upstream-token" {
		t.Fatalf("upstream Proxy-Authorization = %q, want Bearer jwt-upstream-token", pa)
	}
	if cn != "claim-alpha" {
		t.Fatalf("upstream claim header = %q, want claim-alpha", cn)
	}
}

func TestTunnelUnconfiguredUpstreamFailsClosed(t *testing.T) {
	ctx := t.Context()
	mgr, err := NewManager(t.TempDir(), nil, WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	paths, err := mgr.EnsureListener(ctx, "pod-no-upstream", ListenerConfig{})
	if err != nil {
		t.Fatalf("EnsureListener: %v", err)
	}
	resp := sendRawRequest(t, paths.EgressSocketPath,
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if !strings.HasPrefix(resp, "HTTP/1.1 503 ") || !strings.Contains(resp, "upstream-unconfigured") {
		t.Fatalf("unconfigured upstream response = %q, want 503 upstream-unconfigured", resp)
	}

	mismatch := sendRawRequest(t, paths.EgressSocketPath,
		"CONNECT example.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
	if !strings.HasPrefix(mismatch, "HTTP/1.1 400 ") || !strings.Contains(mismatch, "authority-mismatch") {
		t.Fatalf("authority mismatch response = %q, want 400 authority-mismatch", mismatch)
	}
}

func TestTunnelExplicitHTTPProxyViaConnect(t *testing.T) {
	ctx := t.Context()

	// Destination plain HTTP server reached only through upstream CONNECT.
	destSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok:"+r.URL.Path+":"+r.Header.Get("X-Custom"))
	}))
	defer destSrv.Close()

	// Minimal HTTP/1.1 CONNECT upstream proxy that records attested headers and dials dest.
	var mu sync.Mutex
	var gotSandboxHeader string
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = upLn.Close() }()
	go func() {
		for {
			conn, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				mu.Lock()
				gotSandboxHeader = req.Header.Get(auth.HeaderSandboxName)
				mu.Unlock()

				dst, err := net.DialTimeout("tcp", req.Host, 2*time.Second)
				if err != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer func() { _ = dst.Close() }()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(dst, br) }()
				_, _ = io.Copy(c, dst)
			}(conn)
		}
	}()

	mgr, err := NewManager(t.TempDir(), nil, WithAuditWriter(io.Discard))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer mgr.Close()

	podUID := types.UID("pod-http-proxy")
	if _, err := mgr.EnsureListener(ctx, podUID, ListenerConfig{
		Identity: auth.WorkloadIdentity{
			Namespace:   "agents",
			SandboxName: "http-sb",
			PodName:     "http-sb",
			PodUID:      podUID,
		},
		Upstream: &sandboxv1beta1.SandboxNetworkUpstream{
			Address:  "http://" + upLn.Addr().String(),
			Protocol: sandboxv1beta1.SandboxUpstreamProtocolHTTP1,
		},
	}); err != nil {
		t.Fatalf("EnsureListener: %v", err)
	}

	loopLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	if err := mgr.AttachListener(podUID, loopLn); err != nil {
		t.Fatalf("AttachListener: %v", err)
	}

	proxyURL, _ := url.Parse("http://" + loopLn.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, destSrv.URL+"/hello", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Custom", "v1")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET via HTTP_PROXY: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "ok:/hello:v1" {
		t.Fatalf("unexpected response: status=%d body=%q", resp.StatusCode, string(body))
	}
	mu.Lock()
	sbHdr := gotSandboxHeader
	mu.Unlock()
	if sbHdr != "http-sb" {
		t.Fatalf("upstream %s = %q, want http-sb", auth.HeaderSandboxName, sbHdr)
	}
}

func sendRawRequest(t *testing.T, sockPath, raw string) string {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", sockPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	head, _, _ := strings.Cut(string(resp), "\r\n\r\n")
	return head
}
