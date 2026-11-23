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

// Package tunnel implements the per-node agents.net UDS listener manager that
// accepts intercepted HTTP CONNECT and RFC 9298 connect-udp streams from sandbox
// Pods and forwards them over authenticated TLS/mTLS/SPIFFE/JWT tunnels to the
// configured upstream gateway or portal.
package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/auth"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/metrics"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/store"
)

const (
	// EgressSocketName is the standardized agents.net egress UDS filename.
	EgressSocketName = "egress.sock"

	// IngressSocketName is the standardized agents.net ingress UDS filename.
	IngressSocketName = "ingress.sock"

	defaultDialTimeout = 10 * time.Second
	defaultHeadTimeout = 10 * time.Second
	defaultMaxConns    = 1024
	defaultIdleSecs    = 300
)

// AuditRecord is a structured agents.net JSONL audit entry emitted per tunnel request.
type AuditRecord struct {
	Timestamp      string `json:"ts"`
	Sandbox        string `json:"sandbox"`
	PodUID         string `json:"pod_uid"`
	Connection     string `json:"conn"`
	Transport      string `json:"transport"`
	Target         string `json:"target,omitempty"`
	AuthMode       string `json:"auth_mode"`
	Decision       string `json:"decision"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	Reason         string `json:"reason,omitempty"`
	BytesOut       int64  `json:"bytes_out,omitempty"`
	BytesIn        int64  `json:"bytes_in,omitempty"`
	DurationMS     int64  `json:"duration_ms,omitempty"`
}

// ListenerConfig configures a single Pod's agents.net egress UDS listener and its
// authenticated upstream forwarding channel.
type ListenerConfig struct {
	Identity           auth.WorkloadIdentity
	Upstream           *sandboxv1beta1.SandboxNetworkUpstream
	PodCertVolumeName  string
	SATokenVolumeName  string
	HasIngress         bool
	MaxConnections     int
	IdleTimeoutSeconds int
}

// ManagerOption customizes a tunnel Manager.
type ManagerOption func(*Manager)

// WithAuditWriter sets the JSONL audit destination (defaults to os.Stderr).
func WithAuditWriter(w io.Writer) ManagerOption {
	return func(m *Manager) {
		if w != nil {
			m.auditOut = w
		}
	}
}

// WithDialContext overrides raw network dialing for offline tests.
func WithDialContext(fn func(ctx context.Context, network, addr string) (net.Conn, error)) ManagerOption {
	return func(m *Manager) { m.dialNet = fn }
}

// WithTimeouts overrides dial and request-head read timeouts.
func WithTimeouts(dialTimeout, headTimeout time.Duration) ManagerOption {
	return func(m *Manager) {
		if dialTimeout > 0 {
			m.dialTimeout = dialTimeout
		}
		if headTimeout > 0 {
			m.headTimeout = headTimeout
		}
	}
}

// Manager owns per-Pod agents.net Unix domain socket listeners on a node.
type Manager struct {
	rootDir     string
	authRes     *auth.Resolver
	dialTimeout time.Duration
	headTimeout time.Duration
	dialNet     func(ctx context.Context, network, addr string) (net.Conn, error)

	auditMu  sync.Mutex
	auditOut io.Writer

	mu        sync.Mutex
	listeners map[types.UID]*sandboxListener
	connSeq   atomic.Uint64
}

// NewManager creates a Manager storing per-Pod sockets under rootDir.
func NewManager(rootDir string, authResolver *auth.Resolver, opts ...ManagerOption) (*Manager, error) {
	if rootDir == "" {
		return nil, errors.New("rootDir is required")
	}
	if authResolver == nil {
		authResolver = auth.NewResolver(auth.ResolverConfig{})
	}
	if err := os.MkdirAll(rootDir, 0o711); err != nil {
		return nil, fmt.Errorf("create tunnel socket root %q: %w", rootDir, err)
	}
	m := &Manager{
		rootDir:     rootDir,
		authRes:     authResolver,
		dialTimeout: defaultDialTimeout,
		headTimeout: defaultHeadTimeout,
		auditOut:    os.Stderr,
		listeners:   make(map[types.UID]*sandboxListener),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m, nil
}

// EnsureListener creates host socket directories, resolves upstream auth material,
// starts the per-Pod egress.sock listener, and probes socket readiness before returning.
func (m *Manager) EnsureListener(ctx context.Context, podUID types.UID, cfg ListenerConfig) (store.SocketPaths, error) {
	if podUID == "" {
		return store.SocketPaths{}, errors.New("podUID is required")
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = defaultMaxConns
	}
	if cfg.IdleTimeoutSeconds <= 0 {
		cfg.IdleTimeoutSeconds = defaultIdleSecs
	}

	m.mu.Lock()
	if existing, ok := m.listeners[podUID]; ok {
		paths := existing.paths
		m.mu.Unlock()
		existing.updateIdentity(cfg.Identity, false)
		return paths, nil
	}
	m.mu.Unlock()

	var dialer *upstreamDialer
	authMode := auth.AuthModeNone
	if cfg.Upstream != nil && cfg.Upstream.Address != "" {
		clientCfg, err := m.authRes.Resolve(ctx, auth.ResolveRequest{
			Upstream:          cfg.Upstream,
			PodNamespace:      cfg.Identity.Namespace,
			PodUID:            podUID,
			PodCertVolumeName: cfg.PodCertVolumeName,
			SATokenVolumeName: cfg.SATokenVolumeName,
		})
		if err != nil {
			return store.SocketPaths{}, fmt.Errorf("resolve upstream auth for pod %s: %w", podUID, err)
		}
		d, err := newUpstreamDialer(cfg.Upstream, clientCfg, m.dialTimeout, m.dialNet)
		if err != nil {
			_ = clientCfg.Close()
			return store.SocketPaths{}, fmt.Errorf("configure upstream dialer for pod %s: %w", podUID, err)
		}
		dialer = d
		authMode = clientCfg.AuthMode
	}

	podRoot := filepath.Join(m.rootDir, string(podUID))
	egressDir := filepath.Join(podRoot, "egress")
	if err := os.MkdirAll(egressDir, 0o711); err != nil {
		if dialer != nil {
			_ = dialer.Close()
		}
		return store.SocketPaths{}, fmt.Errorf("mkdir egress dir %q: %w", egressDir, err)
	}
	paths := store.SocketPaths{
		PodRootDir:       podRoot,
		EgressDir:        egressDir,
		EgressSocketPath: filepath.Join(egressDir, EgressSocketName),
	}
	if cfg.HasIngress {
		ingressDir := filepath.Join(podRoot, "ingress")
		if err := os.MkdirAll(ingressDir, 0o777); err != nil {
			if dialer != nil {
				_ = dialer.Close()
			}
			return store.SocketPaths{}, fmt.Errorf("mkdir ingress dir %q: %w", ingressDir, err)
		}
		paths.IngressDir = ingressDir
		paths.IngressSocketPath = filepath.Join(ingressDir, IngressSocketName)
	}

	_ = os.Remove(paths.EgressSocketPath)
	ln, err := net.Listen("unix", paths.EgressSocketPath)
	if err != nil {
		if dialer != nil {
			_ = dialer.Close()
		}
		return store.SocketPaths{}, fmt.Errorf("listen %q: %w", paths.EgressSocketPath, err)
	}
	if err := os.Chmod(paths.EgressSocketPath, 0o666); err != nil {
		_ = ln.Close()
		if dialer != nil {
			_ = dialer.Close()
		}
		return store.SocketPaths{}, fmt.Errorf("chmod %q: %w", paths.EgressSocketPath, err)
	}

	revokeCtx, revokeCancel := context.WithCancel(context.Background())
	sl := &sandboxListener{
		manager:      m,
		podUID:       podUID,
		paths:        paths,
		ln:           ln,
		dialer:       dialer,
		authMode:     authMode,
		maxConns:     cfg.MaxConnections,
		idleTimeout:  time.Duration(cfg.IdleTimeoutSeconds) * time.Second,
		revokeCtx:    revokeCtx,
		revokeCancel: revokeCancel,
		identity:     cfg.Identity,
		active:       make(map[net.Conn]func()),
	}

	m.mu.Lock()
	if existing, ok := m.listeners[podUID]; ok {
		m.mu.Unlock()
		revokeCancel()
		_ = ln.Close()
		if dialer != nil {
			_ = dialer.Close()
		}
		return existing.paths, nil
	}
	m.listeners[podUID] = sl
	metrics.ActiveSandboxes.Set(float64(len(m.listeners)))
	m.mu.Unlock()

	sl.wg.Go(func() { sl.acceptLoop(ln) })

	if err := probeUnixSocket(paths.EgressSocketPath, 2*time.Second); err != nil {
		_ = m.Remove(podUID)
		return store.SocketPaths{}, fmt.Errorf("readiness probe failed for %q: %w", paths.EgressSocketPath, err)
	}

	return paths, nil
}

// AttachListener attaches an additional net.Listener (such as a Pod-loopback TCP listener
// created via socketat.ListenAtPath during NRI RunPodSandbox for ExplicitProxy mode) to
// podUID's tunnel pipeline so both listeners share upstream auth, limits, metrics, and Revoke.
func (m *Manager) AttachListener(podUID types.UID, ln net.Listener) error {
	if ln == nil {
		return errors.New("listener is required")
	}
	m.mu.Lock()
	sl := m.listeners[podUID]
	m.mu.Unlock()
	if sl == nil {
		_ = ln.Close()
		return fmt.Errorf("no sandbox listener found for pod %s", podUID)
	}
	return sl.attachListener(ln)
}

// UpdateIdentity refreshes the attested Pod/Sandbox/Claim metadata for podUID.
// When revokeActive is true (for example on warm pool claim adoption), existing
// tunnels are immediately closed so new tunnels carry the updated identity.
func (m *Manager) UpdateIdentity(podUID types.UID, id auth.WorkloadIdentity, revokeActive bool) {
	m.mu.Lock()
	sl := m.listeners[podUID]
	m.mu.Unlock()
	if sl != nil {
		sl.updateIdentity(id, revokeActive)
	}
}

// Revoke immediately blocks new connections and closes all active tunnels for podUID.
func (m *Manager) Revoke(podUID types.UID) {
	m.mu.Lock()
	sl := m.listeners[podUID]
	m.mu.Unlock()
	if sl != nil {
		sl.revoke()
	}
}

// Remove stops the listener, kills active tunnels, closes upstream auth resources,
// and deletes the Pod's host socket directory.
func (m *Manager) Remove(podUID types.UID) error {
	m.mu.Lock()
	sl, ok := m.listeners[podUID]
	if ok {
		delete(m.listeners, podUID)
		metrics.ActiveSandboxes.Set(float64(len(m.listeners)))
	}
	m.mu.Unlock()

	if ok {
		sl.stop()
	}
	podRoot := filepath.Join(m.rootDir, string(podUID))
	if err := os.RemoveAll(podRoot); err != nil {
		return fmt.Errorf("remove socket dir %q: %w", podRoot, err)
	}
	return nil
}

// Close shuts down all active listeners cleanly.
func (m *Manager) Close() {
	m.mu.Lock()
	all := make([]*sandboxListener, 0, len(m.listeners))
	for _, sl := range m.listeners {
		all = append(all, sl)
	}
	m.listeners = make(map[types.UID]*sandboxListener)
	metrics.ActiveSandboxes.Set(0)
	m.mu.Unlock()

	for _, sl := range all {
		sl.stop()
	}
}

func (m *Manager) emitAudit(rec AuditRecord) {
	rec.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	data = append(data, '\n')
	m.auditMu.Lock()
	defer m.auditMu.Unlock()
	_, _ = m.auditOut.Write(data)
}

func probeUnixSocket(path string, timeout time.Duration) error {
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

type sandboxListener struct {
	manager      *Manager
	podUID       types.UID
	paths        store.SocketPaths
	ln           net.Listener
	dialer       *upstreamDialer
	authMode     string
	maxConns     int
	idleTimeout  time.Duration
	revokeCtx    context.Context
	revokeCancel context.CancelFunc

	mu             sync.RWMutex
	identity       auth.WorkloadIdentity
	revoked        bool
	stopped        bool
	extraListeners []net.Listener
	active         map[net.Conn]func()

	stopOnce sync.Once
	wg       sync.WaitGroup
}

func (l *sandboxListener) attachListener(ln net.Listener) error {
	l.mu.Lock()
	if l.stopped || l.revoked {
		l.mu.Unlock()
		_ = ln.Close()
		return errors.New("sandbox listener is already revoked or stopped")
	}
	l.extraListeners = append(l.extraListeners, ln)
	l.mu.Unlock()

	l.wg.Go(func() { l.acceptLoop(ln) })
	return nil
}

func (l *sandboxListener) updateIdentity(id auth.WorkloadIdentity, revokeActive bool) {
	l.mu.Lock()
	l.identity = id
	var closers []func()
	if revokeActive {
		for conn, closeFn := range l.active {
			closers = append(closers, closeFn)
			_ = conn.Close()
		}
	}
	l.mu.Unlock()
	for _, fn := range closers {
		fn()
	}
}

func (l *sandboxListener) revoke() {
	l.revokeCancel()
	l.mu.Lock()
	l.revoked = true
	closers := make([]func(), 0, len(l.active))
	for conn, closeFn := range l.active {
		closers = append(closers, closeFn)
		_ = conn.Close()
	}
	l.mu.Unlock()
	for _, fn := range closers {
		fn()
	}
}

func (l *sandboxListener) stop() {
	l.stopOnce.Do(func() {
		l.mu.Lock()
		l.stopped = true
		extras := append([]net.Listener(nil), l.extraListeners...)
		l.extraListeners = nil
		l.mu.Unlock()

		l.revoke()
		_ = l.ln.Close()
		for _, eln := range extras {
			_ = eln.Close()
		}
		l.wg.Wait()
		if l.dialer != nil {
			_ = l.dialer.Close()
		}
	})
}

func (l *sandboxListener) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		l.mu.Lock()
		if l.revoked {
			l.mu.Unlock()
			metrics.TunnelsTotal.WithLabelValues("tcp", l.authMode, "deny", "listener_revoked").Inc()
			writeH1Deny(conn, l.manager.headTimeout, http.StatusServiceUnavailable, "listener-revoked")
			_ = conn.Close()
			continue
		}
		if len(l.active) >= l.maxConns {
			l.mu.Unlock()
			metrics.TunnelsTotal.WithLabelValues("tcp", l.authMode, "deny", "max_connections").Inc()
			writeH1Deny(conn, l.manager.headTimeout, http.StatusTooManyRequests, "max-connections-exceeded")
			_ = conn.Close()
			continue
		}
		l.active[conn] = func() {}
		metrics.ActiveTunnels.Inc()
		l.mu.Unlock()

		l.wg.Go(func() {
			defer func() {
				l.mu.Lock()
				delete(l.active, conn)
				l.mu.Unlock()
				metrics.ActiveTunnels.Dec()
				_ = conn.Close()
			}()
			l.serveConn(conn)
		})
	}
}

func (l *sandboxListener) setConnCloser(conn net.Conn, fn func()) bool {
	l.mu.Lock()
	if l.revoked {
		l.mu.Unlock()
		return false
	}
	if _, ok := l.active[conn]; ok {
		l.active[conn] = fn
	}
	l.mu.Unlock()
	return true
}

func (l *sandboxListener) snapshotIdentity() auth.WorkloadIdentity {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.identity
}

func (l *sandboxListener) serveConn(conn net.Conn) {
	start := time.Now()
	connID := strconv.FormatUint(l.manager.connSeq.Add(1), 10)
	_ = conn.SetReadDeadline(time.Now().Add(l.manager.headTimeout))
	limiter := &boundedReader{r: conn, remaining: maxHeadBytes}
	br := bufio.NewReader(limiter)

	h, err := readHead(br)
	if err != nil {
		if he, ok := errors.AsType[*headError](err); ok {
			metrics.TunnelsTotal.WithLabelValues("tcp", l.authMode, "deny", "malformed").Inc()
			l.emitAudit(AuditRecord{
				Connection: connID,
				Transport:  "tcp",
				Decision:   "deny",
				Reason:     he.reason,
			})
			writeH1Deny(conn, l.manager.headTimeout, he.status, he.reason)
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	limiter.remaining = -1

	transport := "tcp"
	if h.isUDP {
		transport = "udp"
	}
	target := net.JoinHostPort(h.host, h.port)

	if l.dialer == nil {
		metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "deny", "upstream_unavailable").Inc()
		l.emitAudit(AuditRecord{
			Connection: connID,
			Transport:  transport,
			Target:     target,
			Decision:   "deny",
			Reason:     "upstream-unconfigured",
		})
		writeH1Deny(conn, l.manager.headTimeout, http.StatusServiceUnavailable, "upstream-unconfigured")
		return
	}

	dialCtx, cancel := context.WithTimeout(l.revokeCtx, l.manager.dialTimeout)
	defer cancel()

	id := l.snapshotIdentity()
	dialStart := time.Now()
	var up *upstreamTunnel
	if h.isUDP {
		up, err = l.dialer.dialUDP(dialCtx, h.host, h.port, id)
	} else {
		up, err = l.dialer.dialTCP(dialCtx, h.host, h.port, id)
	}
	metrics.TunnelDialDurationSeconds.WithLabelValues(string(l.dialer.protocol), l.authMode).Observe(time.Since(dialStart).Seconds())

	if err != nil {
		if denied, ok := errors.AsType[*upstreamDeniedError](err); ok {
			metricReason := "upstream_denied"
			if denied.reason == "upstream-auth-failed" || denied.status == http.StatusProxyAuthRequired {
				metricReason = "upstream_auth_failed"
			}
			metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "deny", metricReason).Inc()
			l.emitAudit(AuditRecord{
				Connection:     connID,
				Transport:      transport,
				Target:         target,
				Decision:       "deny",
				UpstreamStatus: denied.status,
				Reason:         denied.reason,
				DurationMS:     time.Since(start).Milliseconds(),
			})
			if denied.proxyStatus != "" {
				writeH1RawDeny(conn, l.manager.headTimeout, denied.status, denied.proxyStatus)
			} else {
				writeH1Deny(conn, l.manager.headTimeout, denied.status, denied.reason)
			}
			return
		}
		klog.ErrorS(err, "upstream tunnel dial failed",
			"podUID", l.podUID,
			"sandbox", id.Namespace+"/"+id.SandboxName,
			"target", target,
			"upstream", l.dialer.target.address,
			"authMode", l.authMode,
		)
		metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "error", "upstream_unavailable").Inc()
		l.emitAudit(AuditRecord{
			Connection: connID,
			Transport:  transport,
			Target:     target,
			Decision:   "error",
			Reason:     "upstream-connect-failed",
			DurationMS: time.Since(start).Milliseconds(),
		})
		writeH1Deny(conn, l.manager.headTimeout, http.StatusBadGateway, "upstream-connect-failed")
		return
	}
	defer up.close()
	if !l.setConnCloser(conn, up.close) {
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(l.manager.headTimeout))
	switch {
	case h.isUDP:
		_, err = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n")
	case h.isHTTPProxy:
		_, err = io.WriteString(up.w, h.originReqHead)
	default:
		_, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	}
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return
	}

	metrics.TunnelsTotal.WithLabelValues(transport, l.authMode, "allow", "allowed").Inc()
	outN, inN := relayStream(br, conn, up, l.idleTimeout, func() { _ = conn.Close() })
	l.emitAudit(AuditRecord{
		Connection:     connID,
		Transport:      transport,
		Target:         target,
		Decision:       "allow",
		UpstreamStatus: http.StatusOK,
		Reason:         "allowed",
		BytesOut:       outN,
		BytesIn:        inN,
		DurationMS:     time.Since(start).Milliseconds(),
	})
}

func (l *sandboxListener) emitAudit(rec AuditRecord) {
	id := l.snapshotIdentity()
	rec.PodUID = string(l.podUID)
	rec.AuthMode = l.authMode
	if id.Namespace != "" && id.SandboxName != "" {
		rec.Sandbox = id.Namespace + "/" + id.SandboxName
	} else if id.Namespace != "" && id.PodName != "" {
		rec.Sandbox = id.Namespace + "/" + id.PodName
	}
	l.manager.emitAudit(rec)
}
