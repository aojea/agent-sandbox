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

// Package ingress implements the node-local HTTP CONNECT ingress bridge for
// sandbox-net. Authorized callers (such as sandbox-router) connect to this
// host listener, issue "CONNECT <podUID>:<port> HTTP/1.1", and sandbox-net
// enforces the Sandbox's spec.network.ingressPorts allowlist before dialing
// either the Pod's agents.net ingress.sock (TunSidecar/TunVM) or the Pod's
// loopback 127.0.0.1:<port> via socketat (ExplicitProxy / PodNetworkIsolated).
package ingress

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/metrics"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/socketat"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/store"
)

const (
	defaultDialTimeout = 5 * time.Second
	defaultHeadTimeout = 5 * time.Second
	maxHeadBytes       = 8 * 1024
)

// DialNetNSFunc dials a literal IP:port inside a Linux network namespace.
type DialNetNSFunc func(netnsPath, network, address string, timeout time.Duration) (net.Conn, error)

// Config configures the node-local sandbox-net ingress bridge.
type Config struct {
	ListenAddr  string
	Store       *store.PodConfigStore
	TLSConfig   *tls.Config
	DialNetNS   DialNetNSFunc
	DialTimeout time.Duration
	HeadTimeout time.Duration
}

// Server accepts HTTP/1.1 CONNECT <podUID>:<port> requests on the node host
// network and tunnels allowed connections into the target sandbox Pod.
type Server struct {
	listenAddr  string
	store       *store.PodConfigStore
	tlsConfig   *tls.Config
	dialNetNS   DialNetNSFunc
	dialTimeout time.Duration
	headTimeout time.Duration

	mu     sync.Mutex
	ln     net.Listener
	closed bool
	active map[types.UID]map[net.Conn]func()
	wg     sync.WaitGroup
}

// NewServer constructs an ingress Server without starting its listener.
func NewServer(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("ingress listen address is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("pod config store is required")
	}
	dialNetNS := cfg.DialNetNS
	if dialNetNS == nil {
		dialNetNS = socketat.DialAtPath
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	headTimeout := cfg.HeadTimeout
	if headTimeout <= 0 {
		headTimeout = defaultHeadTimeout
	}
	return &Server{
		listenAddr:  cfg.ListenAddr,
		store:       cfg.Store,
		tlsConfig:   cfg.TLSConfig,
		dialNetNS:   dialNetNS,
		dialTimeout: dialTimeout,
		headTimeout: headTimeout,
		active:      make(map[types.UID]map[net.Conn]func()),
	}, nil
}

// Start binds the TCP (or TLS/mTLS) listener and begins serving in the background.
func (s *Server) Start() (net.Addr, error) {
	rawLn, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen ingress %q: %w", s.listenAddr, err)
	}
	ln := rawLn
	if s.tlsConfig != nil {
		ln = tls.NewListener(rawLn, s.tlsConfig.Clone())
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return nil, errors.New("ingress server already closed")
	}
	s.ln = ln
	s.mu.Unlock()

	s.wg.Go(func() { s.acceptLoop(ln) })
	klog.InfoS("sandbox-net ingress bridge listening", "addr", ln.Addr().String(), "tls", s.tlsConfig != nil)
	return ln.Addr(), nil
}

// Close stops accepting new connections, closes active ingress tunnels, and waits
// for all connection goroutines to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	s.ln = nil
	var closers []func()
	for uid, conns := range s.active {
		for c, cancel := range conns {
			closers = append(closers, func() {
				cancel()
				_ = c.Close()
			})
		}
		delete(s.active, uid)
	}
	s.mu.Unlock()

	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, fn := range closers {
		fn()
	}
	s.wg.Wait()
	return err
}

// Revoke immediately closes all active ingress connections for podUID.
func (s *Server) Revoke(podUID types.UID) {
	s.mu.Lock()
	conns := s.active[podUID]
	delete(s.active, podUID)
	s.mu.Unlock()

	for c, cancel := range conns {
		cancel()
		_ = c.Close()
	}
}

func (s *Server) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.wg.Go(func() {
			defer func() { _ = conn.Close() }()
			s.serveConn(conn)
		})
	}
}

func (s *Server) trackConn(podUID types.UID, client net.Conn, cancel func()) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		_ = client.Close()
		return
	}
	if s.active[podUID] == nil {
		s.active[podUID] = make(map[net.Conn]func())
	}
	s.active[podUID][client] = cancel
	s.mu.Unlock()
}

func (s *Server) untrackConn(podUID types.UID, client net.Conn) {
	s.mu.Lock()
	if conns := s.active[podUID]; conns != nil {
		delete(conns, client)
		if len(conns) == 0 {
			delete(s.active, podUID)
		}
	}
	s.mu.Unlock()
}

func (s *Server) serveConn(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(s.headTimeout))
	br := bufio.NewReader(io.LimitReader(conn, maxHeadBytes))
	podUID, port, status, reason := readConnectHead(br)
	if status != 0 {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "malformed").Inc()
		s.writeError(conn, status, reason)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	cfg, ok := s.store.Get(podUID)
	if !ok {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "unknown_sandbox").Inc()
		s.writeError(conn, http.StatusNotFound, "unknown-sandbox")
		return
	}
	if !isTCPPortAllowed(cfg.Parameters.IngressPorts, port) {
		metrics.IngressConnectionsTotal.WithLabelValues("deny", "port_denied").Inc()
		s.writeError(conn, http.StatusForbidden, "ingress-port-denied")
		return
	}

	backend, err := s.dialPod(cfg, port)
	if err != nil {
		if errors.Is(err, errPodNotReady) {
			metrics.IngressConnectionsTotal.WithLabelValues("error", "not_ready").Inc()
			s.writeError(conn, http.StatusServiceUnavailable, "sandbox-not-ready")
			return
		}
		klog.V(2).InfoS("sandbox-net ingress dial failed", "podUID", podUID, "port", port, "err", err)
		metrics.IngressConnectionsTotal.WithLabelValues("error", "dial_failed").Inc()
		s.writeError(conn, http.StatusBadGateway, "ingress-dial-failed")
		return
	}
	defer func() { _ = backend.Close() }()

	s.trackConn(podUID, conn, func() { _ = backend.Close() })
	defer s.untrackConn(podUID, conn)

	_ = conn.SetWriteDeadline(time.Now().Add(s.headTimeout))
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})

	metrics.IngressConnectionsTotal.WithLabelValues("allow", "allowed").Inc()

	// Drain any bytes buffered by bufio.Reader before switching directly to conn.
	clientReader := io.Reader(conn)
	if br.Buffered() > 0 {
		buffered := make([]byte, br.Buffered())
		if n, _ := io.ReadFull(br, buffered); n > 0 {
			clientReader = io.MultiReader(strings.NewReader(string(buffered[:n])), conn)
		}
	}

	relayBidirectional(clientReader, conn, backend)
}

var errPodNotReady = errors.New("sandbox network namespace not ready")

func (s *Server) dialPod(cfg store.PodConfig, port int32) (net.Conn, error) {
	// Prefer the agents.net ingress.sock when present (TunSidecar / TunVM mode).
	if sock := cfg.SocketPaths.IngressSocketPath; sock != "" {
		if _, err := os.Stat(sock); err == nil {
			return s.dialIngressSocket(sock, port)
		}
	}
	if cfg.NetNS == "" {
		return nil, errPodNotReady
	}
	return s.dialNetNS(cfg.NetNS, "tcp", net.JoinHostPort("127.0.0.1", strconv.FormatInt(int64(port), 10)), s.dialTimeout)
}

func (s *Server) dialIngressSocket(sockPath string, port int32) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", sockPath, s.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial ingress.sock %q: %w", sockPath, err)
	}
	_ = conn.SetDeadline(time.Now().Add(s.dialTimeout))
	target := net.JoinHostPort("127.0.0.1", strconv.FormatInt(int64(port), 10))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT to ingress.sock: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response from ingress.sock: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("ingress.sock rejected CONNECT with HTTP %d", resp.StatusCode)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (s *Server) writeError(conn net.Conn, status int, reason string) {
	_ = conn.SetWriteDeadline(time.Now().Add(s.headTimeout))
	text := http.StatusText(status)
	if text == "" {
		text = "Error"
	}
	clean := strings.ReplaceAll(strings.ReplaceAll(reason, "\r", ""), "\n", "")
	_, _ = fmt.Fprintf(conn,
		"HTTP/1.1 %d %s\r\nBoundary-Reason: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
		status, text, clean,
	)
}

func readConnectHead(br *bufio.Reader) (types.UID, int32, int, string) {
	line, err := br.ReadString('\n')
	if err != nil || !strings.HasSuffix(line, "\r\n") {
		return "", 0, http.StatusBadRequest, "malformed-request-line"
	}
	parts := strings.Split(strings.TrimSuffix(line, "\r\n"), " ")
	if len(parts) != 3 {
		return "", 0, http.StatusBadRequest, "malformed-request-line"
	}
	method, target, version := parts[0], parts[1], parts[2]
	if version != "HTTP/1.1" {
		return "", 0, http.StatusHTTPVersionNotSupported, "unsupported-http-version"
	}
	if method != http.MethodConnect {
		return "", 0, http.StatusMethodNotAllowed, "method-not-allowed"
	}

	var hostHeader string
	hostCount := 0
	for {
		hline, err := br.ReadString('\n')
		if err != nil || !strings.HasSuffix(hline, "\r\n") {
			return "", 0, http.StatusBadRequest, "malformed-header"
		}
		trimmed := strings.TrimSuffix(hline, "\r\n")
		if trimmed == "" {
			break
		}
		k, v, ok := strings.Cut(trimmed, ":")
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			return "", 0, http.StatusBadRequest, "malformed-header"
		}
		if strings.EqualFold(k, "host") {
			hostCount++
			hostHeader = strings.TrimSpace(v)
		}
	}
	if hostCount != 1 || !strings.EqualFold(hostHeader, target) {
		return "", 0, http.StatusBadRequest, "authority-mismatch"
	}

	rawUID, rawPort, err := net.SplitHostPort(target)
	if err != nil || rawUID == "" || rawPort == "" {
		return "", 0, http.StatusBadRequest, "malformed-authority"
	}
	portNum, err := strconv.ParseInt(rawPort, 10, 32)
	if err != nil || portNum < 1 || portNum > 65535 {
		return "", 0, http.StatusBadRequest, "invalid-port"
	}
	return types.UID(rawUID), int32(portNum), 0, ""
}

func isTCPPortAllowed(ports []sandboxv1beta1.SandboxIngressPort, port int32) bool {
	for _, p := range ports {
		proto := p.Protocol
		if proto == "" {
			proto = sandboxv1beta1.SandboxIngressProtocolTCP
		}
		if proto == sandboxv1beta1.SandboxIngressProtocolTCP && p.Port == port {
			return true
		}
	}
	return false
}

type closeWriter interface {
	CloseWrite() error
}

func relayBidirectional(clientR io.Reader, clientW net.Conn, backend net.Conn) {
	var wg sync.WaitGroup
	wg.Go(func() {
		_, _ = io.Copy(backend, clientR)
		if cw, ok := backend.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = backend.Close()
		}
	})
	_, _ = io.Copy(clientW, backend)
	if cw, ok := clientW.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	_ = clientW.Close()
	wg.Wait()
}
