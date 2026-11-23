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

package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testCerts(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-upstream-ca"},
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
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, _ := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	srvKeyDER, _ := x509.MarshalPKCS8PrivateKey(srvKey)
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER}),
	)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return pair, pool
}

func TestProxyHTTP2ConnectAndConnectUDP(t *testing.T) {
	srvPair, caPool := testCerts(t)

	destHTTP := httptest.NewServer(makeDestHandler("http"))
	defer destHTTP.Close()

	udpEcho, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp echo: %v", err)
	}
	defer func() { _ = udpEcho.Close() }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, rerr := udpEcho.ReadFrom(buf)
			if rerr != nil {
				return
			}
			_, _ = udpEcho.WriteTo(append([]byte("udp-echo:"), buf[:n]...), addr)
		}
	}()

	state := &proxyState{requireBearerAud: "agents.net/upstream"}
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	tlsLn := &countingListener{
		Listener: tls.NewListener(rawLn, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{srvPair},
			NextProtos:   []string{"h2", "http/1.1"},
		}),
		count: &state.tlsConns,
	}
	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	protos.SetHTTP2(true)
	srv := &http.Server{Protocols: protos, Handler: http.HandlerFunc(state.serveProxy)}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	// Build a minimal unsigned JWT payload for auth claim testing.
	claimsJSON, _ := json.Marshal(map[string]any{
		"sub": "system:serviceaccount:agent-sandbox-system:sandbox-net",
		"aud": []string{"agents.net/upstream"},
		"kubernetes.io": map[string]any{
			"node": map[string]any{"name": "kind-worker"},
		},
	})
	jwtToken := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(claimsJSON) + ".sig"

	// 1. Test HTTP/2 CONNECT tunnel to destHTTP.
	h2Protos := new(http.Protocols)
	h2Protos.SetHTTP2(true)
	h2Tr := &http.Transport{
		Protocols: h2Protos,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    caPool,
			ServerName: "127.0.0.1",
			NextProtos: []string{"h2"},
		},
	}
	defer h2Tr.CloseIdleConnections()

	pr, pw := io.Pipe()
	destHost := strings.TrimPrefix(destHTTP.URL, "http://")
	h2Req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: rawLn.Addr().String()},
		Host:   destHost,
		Header: http.Header{
			"Proxy-Authorization": []string{"Bearer " + jwtToken},
		},
		Body: pr,
	}
	resp, err := h2Tr.RoundTrip(h2Req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("H2 CONNECT failed: resp=%v err=%v", resp, err)
	}
	_, _ = io.WriteString(pw, fmt.Sprintf("GET /h2-ping HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", destHost))
	_ = pw.Close()
	rawResp, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(rawResp), `"/h2-ping"`) {
		t.Fatalf("H2 CONNECT response missing /h2-ping: %q", string(rawResp))
	}

	// 2. Test RFC 9298 connect-udp capsule relay over TLS HTTP/1.1 Upgrade.
	udpHost, udpPort, _ := net.SplitHostPort(udpEcho.LocalAddr().String())
	tlsConn, err := tls.Dial("tcp", rawLn.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    caPool,
		ServerName: "127.0.0.1",
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("tls dial connect-udp: %v", err)
	}
	defer func() { _ = tlsConn.Close() }()
	_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))

	_, _ = fmt.Fprintf(tlsConn,
		"GET /.well-known/masque/udp/%s/%s/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\nProxy-Authorization: Bearer %s\r\n\r\n",
		udpHost, udpPort, jwtToken)
	br := bufio.NewReader(tlsConn)
	uResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil || uResp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("connect-udp upgrade failed: resp=%v err=%v", uResp, err)
	}
	if err := writeDatagramCapsule(tlsConn, []byte("hello-udp")); err != nil {
		t.Fatalf("writeDatagramCapsule: %v", err)
	}
	gotDG, err := readDatagramCapsule(br)
	if err != nil || string(gotDG) != "udp-echo:hello-udp" {
		t.Fatalf("readDatagramCapsule = %q err=%v, want udp-echo:hello-udp", string(gotDG), err)
	}

	recs := state.snapshotRecords()
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d: %+v", len(recs), recs)
	}
	if recs[0].Protocol != "HTTP/2.0" || recs[0].Transport != "tcp" || recs[0].JWTNode != "kind-worker" {
		t.Fatalf("unexpected H2 record: %+v", recs[0])
	}
	if recs[1].Transport != "udp" || recs[1].Decision != "allow" {
		t.Fatalf("unexpected UDP record: %+v", recs[1])
	}
}
