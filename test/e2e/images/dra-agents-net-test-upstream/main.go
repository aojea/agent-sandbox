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

// Binary dra-agents-net-test-upstream provides a zero-dependency Go test fixture
// for dra-agents-net E2E tests in two modes:
//   - --mode=proxy: TLS/mTLS/JWT upstream gateway supporting HTTP/2 CONNECT,
//     HTTP/1.1 CONNECT, and RFC 9298 connect-udp capsule relay plus an admin
//     /records and /stats endpoint.
//   - --mode=dest: HTTP, HTTPS, and UDP echo destination server.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const udpTargetPrefix = "/.well-known/masque/udp/"

type proxyRecord struct {
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

type proxyStats struct {
	TLSConnections int64 `json:"tls_connections"`
}

type countingListener struct {
	net.Listener
	count *atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.count.Add(1)
	}
	return c, err
}

type proxyState struct {
	requireMTLS      bool
	requireBearerAud string
	tlsConns         atomic.Int64

	mu      sync.Mutex
	records []proxyRecord
}

func (s *proxyState) appendRecord(rec proxyRecord) {
	s.mu.Lock()
	s.records = append(s.records, rec)
	s.mu.Unlock()
}

func (s *proxyState) snapshotRecords() []proxyRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]proxyRecord, len(s.records))
	copy(out, s.records)
	return out
}

func (s *proxyState) serveProxy(w http.ResponseWriter, r *http.Request) {
	isConnect := r.Method == http.MethodConnect
	isUDP := r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("Upgrade"), "connect-udp")
	if !isConnect && !isUDP {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var target, transport string
	if isConnect {
		target = r.Host
		transport = "tcp"
	} else {
		host, port, err := parseConnectUDPTarget(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		target = net.JoinHostPort(host, port)
		transport = "udp"
	}

	peerCN := ""
	if s.requireMTLS && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		peerCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}

	hdrs := make(map[string]string, len(r.Header))
	for k, vals := range r.Header {
		if len(vals) > 0 {
			hdrs[strings.ToLower(k)] = vals[0]
		}
	}

	var jwtSub, jwtNode string
	var jwtAud []string
	if s.requireBearerAud != "" {
		authz := r.Header.Get("Proxy-Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			w.Header().Set("Proxy-Status", `test-portal; error=http_request_denied; details="missing-bearer-token"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		payload, err := decodeJWTPayload(strings.TrimSpace(strings.TrimPrefix(authz, "Bearer ")))
		if err != nil {
			w.Header().Set("Proxy-Status", `test-portal; error=http_request_denied; details="invalid-jwt"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		jwtAud = extractAudiences(payload["aud"])
		if !slices.Contains(jwtAud, s.requireBearerAud) {
			w.Header().Set("Proxy-Status", `test-portal; error=http_request_denied; details="bad-audience"`)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		jwtSub, _ = payload["sub"].(string)
		if k8sClaim, ok := payload["kubernetes.io"].(map[string]any); ok {
			if nodeClaim, ok := k8sClaim["node"].(map[string]any); ok {
				jwtNode, _ = nodeClaim["name"].(string)
			}
		}
	}

	decision := "allow"
	if strings.Contains(target, "blocked") {
		decision = "deny"
	}
	s.appendRecord(proxyRecord{
		Target:    target,
		Protocol:  r.Proto,
		Transport: transport,
		Headers:   hdrs,
		PeerCN:    peerCN,
		JWTSub:    jwtSub,
		JWTAud:    jwtAud,
		JWTNode:   jwtNode,
		Decision:  decision,
	})

	if decision == "deny" {
		w.Header().Set("Proxy-Status", `test-portal; error=http_request_denied; details="blocked-by-portal"`)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if isUDP {
		handleConnectUDP(w, r, target)
		return
	}
	if r.ProtoMajor >= 2 {
		handleH2Connect(w, r, target)
		return
	}
	handleH1Connect(w, target)
}

func handleH2Connect(w http.ResponseWriter, r *http.Request, target string) {
	dst, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		w.Header().Set("Proxy-Status", `test-portal; error=destination_unavailable; details="dial-failed"`)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = dst.Close() }()

	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(dst, r.Body)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	})

	buf := make([]byte, 16*1024)
	for {
		n, rerr := dst.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				break
			}
			if ferr := rc.Flush(); ferr != nil {
				break
			}
		}
		if rerr != nil {
			break
		}
	}
	_ = dst.Close()
	// Unblock r.Body.Read cleanly via ResponseController.SetReadDeadline
	// instead of calling r.Body.Close() concurrently with io.Copy.
	_ = rc.SetReadDeadline(time.Unix(1, 0))
	wg.Wait()
}

func handleH1Connect(w http.ResponseWriter, target string) {
	dst, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		w.Header().Set("Proxy-Status", `test-portal; error=destination_unavailable; details="dial-failed"`)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = dst.Close() }()

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "CONNECT hijack unsupported", http.StatusNotImplemented)
		return
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(dst, brw.Reader)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	})
	_, _ = io.Copy(conn, dst)
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	wg.Wait()
}

func handleConnectUDP(w http.ResponseWriter, r *http.Request, target string) {
	if r.ProtoMajor >= 2 {
		http.Error(w, "connect-udp requires HTTP/1.1 upgrade", http.StatusNotImplemented)
		return
	}
	udpConn, err := net.DialTimeout("udp", target, 5*time.Second)
	if err != nil {
		w.Header().Set("Proxy-Status", `test-portal; error=destination_unavailable; details="udp-dial-failed"`)
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer func() { _ = udpConn.Close() }()

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, "connect-udp hijack unsupported", http.StatusNotImplemented)
		return
	}
	defer func() { _ = conn.Close() }()

	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 65535)
		for {
			n, rerr := udpConn.Read(buf)
			if n > 0 {
				if werr := writeDatagramCapsule(conn, buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	})

	for {
		dg, rerr := readDatagramCapsule(brw.Reader)
		if rerr != nil {
			break
		}
		if _, werr := udpConn.Write(dg); werr != nil {
			break
		}
	}
	_ = udpConn.Close()
	wg.Wait()
}

func parseConnectUDPTarget(path string) (string, string, error) {
	if !strings.HasPrefix(path, udpTargetPrefix) || !strings.HasSuffix(path, "/") {
		return "", "", errors.New("invalid connect-udp target path")
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(path, udpTargetPrefix), "/")
	rawHost, rawPort, ok := strings.Cut(rest, "/")
	if !ok || strings.Contains(rawPort, "/") || rawHost == "" || rawPort == "" {
		return "", "", errors.New("invalid connect-udp target segments")
	}
	host, err := url.PathUnescape(rawHost)
	if err != nil || host == "" {
		return "", "", errors.New("invalid connect-udp host")
	}
	port, err := url.PathUnescape(rawPort)
	if err != nil || port == "" {
		return "", "", errors.New("invalid connect-udp port")
	}
	return host, port, nil
}

func readDatagramCapsule(r *bufio.Reader) ([]byte, error) {
	for {
		typ, err := readVarint(r)
		if err != nil {
			return nil, err
		}
		length, err := readVarint(r)
		if err != nil {
			return nil, err
		}
		if length > 65536 {
			return nil, errors.New("capsule too large")
		}
		if typ != 0 {
			if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
				return nil, err
			}
			continue
		}
		if length == 0 {
			return nil, errors.New("empty datagram capsule")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
		ctxID, n, err := decodeVarintSlice(payload)
		if err != nil {
			return nil, err
		}
		if ctxID != 0 {
			continue
		}
		return payload[n:], nil
	}
}

func writeDatagramCapsule(w io.Writer, dg []byte) error {
	var hdr [16]byte
	n := 0
	n += putVarint(hdr[n:], 0)
	n += putVarint(hdr[n:], uint64(len(dg)+1))
	n += putVarint(hdr[n:], 0)
	if _, err := w.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := w.Write(dg)
	return err
}

func readVarint(r *bufio.Reader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	length := 1 << (first >> 6)
	val := uint64(first & 0x3f)
	for i := 1; i < length; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		val = (val << 8) | uint64(b)
	}
	return val, nil
}

func decodeVarintSlice(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	length := 1 << (b[0] >> 6)
	if len(b) < length {
		return 0, 0, io.ErrUnexpectedEOF
	}
	val := uint64(b[0] & 0x3f)
	for i := 1; i < length; i++ {
		val = (val << 8) | uint64(b[i])
	}
	return val, length, nil
}

func putVarint(dst []byte, v uint64) int {
	switch {
	case v < 1<<6:
		dst[0] = byte(v)
		return 1
	case v < 1<<14:
		binary.BigEndian.PutUint16(dst, uint16(v)|0x4000)
		return 2
	case v < 1<<30:
		binary.BigEndian.PutUint32(dst, uint32(v)|0x80000000)
		return 4
	default:
		binary.BigEndian.PutUint64(dst, v|0xc000000000000000)
		return 8
	}
}

func decodeJWTPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, errors.New("malformed jwt")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func extractAudiences(v any) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []any:
		out := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func buildTLSConfig(certFile, keyFile, caFile string, requireMTLS bool, nextProtos []string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
		NextProtos:   nextProtos,
	}
	if requireMTLS {
		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("no valid CA certs in %q", caFile)
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	}
	return cfg, nil
}

func runProxy(ctx context.Context, proxyAddr, adminAddr, certFile, keyFile, caFile string, requireMTLS bool, requireAud string) error {
	tlsCfg, err := buildTLSConfig(certFile, keyFile, caFile, requireMTLS, []string{"h2", "http/1.1"})
	if err != nil {
		return err
	}
	state := &proxyState{
		requireMTLS:      requireMTLS,
		requireBearerAud: requireAud,
	}

	rawLn, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return fmt.Errorf("listen proxy %s: %w", proxyAddr, err)
	}
	tlsLn := &countingListener{
		Listener: tls.NewListener(rawLn, tlsCfg),
		count:    &state.tlsConns,
	}

	protos := new(http.Protocols)
	protos.SetHTTP1(true)
	protos.SetHTTP2(true)
	proxySrv := &http.Server{
		Protocols:         protos,
		Handler:           http.HandlerFunc(state.serveProxy),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Bind admin listener ONLY after proxy listener is bound so /healthz implies proxy readiness.
	adminLn, err := net.Listen("tcp", adminAddr)
	if err != nil {
		_ = tlsLn.Close()
		return fmt.Errorf("listen admin %s: %w", adminAddr, err)
	}
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	adminMux.HandleFunc("/records", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state.snapshotRecords())
	})
	adminMux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(proxyStats{TLSConnections: state.tlsConns.Load()})
	})
	adminMux.HandleFunc("/check-svc", func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if addr == "" {
			http.Error(w, "addr required", http.StatusBadRequest)
			return
		}
		c, dialErr := (&net.Dialer{Timeout: time.Second}).DialContext(r.Context(), "tcp", addr)
		if dialErr != nil {
			http.Error(w, dialErr.Error(), http.StatusServiceUnavailable)
			return
		}
		_ = c.Close()
		_, _ = io.WriteString(w, "ok\n")
	})
	adminSrv := &http.Server{
		Handler:           adminMux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		if err := proxySrv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		if err := adminSrv.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		_ = proxySrv.Close()
		_ = adminSrv.Close()
		return nil
	case err := <-errCh:
		_ = proxySrv.Close()
		_ = adminSrv.Close()
		return err
	}
}

func makeDestHandler(scheme string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"scheme": scheme,
			"path":   r.URL.Path,
			"host":   r.Host,
		})
	})
}

func runDest(ctx context.Context, httpAddr, httpsAddr, udpAddr, certFile, keyFile string) error {
	tlsCfg, err := buildTLSConfig(certFile, keyFile, "", false, []string{"http/1.1"})
	if err != nil {
		return err
	}

	httpLn, err := net.Listen("tcp", httpAddr)
	if err != nil {
		return fmt.Errorf("listen http %s: %w", httpAddr, err)
	}
	rawHTTPSLn, err := net.Listen("tcp", httpsAddr)
	if err != nil {
		_ = httpLn.Close()
		return fmt.Errorf("listen https %s: %w", httpsAddr, err)
	}
	httpsLn := tls.NewListener(rawHTTPSLn, tlsCfg)

	udpPC, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		_ = httpLn.Close()
		_ = httpsLn.Close()
		return fmt.Errorf("listen udp %s: %w", udpAddr, err)
	}

	httpSrv := &http.Server{Handler: makeDestHandler("http"), ReadHeaderTimeout: 10 * time.Second}
	httpsSrv := &http.Server{Handler: makeDestHandler("https"), ReadHeaderTimeout: 10 * time.Second}

	errCh := make(chan error, 3)
	go func() {
		if err := httpSrv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		if err := httpsSrv.Serve(httpsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, rerr := udpPC.ReadFrom(buf)
			if rerr != nil {
				if !errors.Is(rerr, net.ErrClosed) {
					errCh <- rerr
				}
				return
			}
			reply := append([]byte("udp-echo:"), buf[:n]...)
			_, _ = udpPC.WriteTo(reply, addr)
		}
	}()

	select {
	case <-ctx.Done():
		_ = httpSrv.Close()
		_ = httpsSrv.Close()
		_ = udpPC.Close()
		return nil
	case err := <-errCh:
		_ = httpSrv.Close()
		_ = httpsSrv.Close()
		_ = udpPC.Close()
		return err
	}
}

func main() {
	mode := flag.String("mode", "proxy", "server mode: proxy or dest")
	proxyAddr := flag.String("proxy-addr", ":8443", "TLS proxy listen address (proxy mode)")
	adminAddr := flag.String("admin-addr", ":8081", "HTTP admin/healthz listen address (proxy mode)")
	httpAddr := flag.String("http-addr", ":8080", "HTTP listen address (dest mode)")
	httpsAddr := flag.String("https-addr", ":8443", "HTTPS listen address (dest mode)")
	udpAddr := flag.String("udp-addr", ":5353", "UDP echo listen address (dest mode)")
	certFile := flag.String("tls-cert", "/tls/tls.crt", "TLS server certificate path")
	keyFile := flag.String("tls-key", "/tls/tls.key", "TLS server private key path")
	caFile := flag.String("client-ca", "/tls/ca.crt", "Client CA path for mTLS (proxy mode)")
	requireMTLS := flag.Bool("require-mtls", os.Getenv("REQUIRE_MTLS") == "1", "require client certificate (proxy mode)")
	requireAud := flag.String("require-bearer-aud", os.Getenv("REQUIRE_BEARER_AUD"), "required JWT audience in Proxy-Authorization (proxy mode)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var err error
	switch *mode {
	case "proxy":
		err = runProxy(ctx, *proxyAddr, *adminAddr, *certFile, *keyFile, *caFile, *requireMTLS, *requireAud)
	case "dest":
		err = runDest(ctx, *httpAddr, *httpsAddr, *udpAddr, *certFile, *keyFile)
	default:
		err = fmt.Errorf("unknown --mode %q (want proxy or dest)", *mode)
	}
	if err != nil {
		log.Fatalf("dra-agents-net-test-upstream (%s): %v", *mode, err)
	}
}
