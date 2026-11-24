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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"sigs.k8s.io/agent-sandbox/sandbox-router/config"
)

const (
	agentsNetIngressHandshakeTimeout = 10 * time.Second
	maxIngressConnectResponseBytes   = 8 * 1024
)

type agentsNetIngressContextKey struct{}

// agentsNetIngressTarget identifies the node-local agents.net ingress bridge
// endpoint and target Pod UID + port for a single proxied request.
type agentsNetIngressTarget struct {
	BridgeAddr string
	PodUID     string
	Port       int
}

func withAgentsNetIngressTarget(ctx context.Context, target agentsNetIngressTarget) context.Context {
	return context.WithValue(ctx, agentsNetIngressContextKey{}, target)
}

func agentsNetIngressTargetFromContext(ctx context.Context) (agentsNetIngressTarget, bool) {
	t, ok := ctx.Value(agentsNetIngressContextKey{}).(agentsNetIngressTarget)
	return t, ok
}

// agentsNetIngressDeniedError represents an explicit 4xx HTTP rejection from the
// node-local agents.net ingress bridge (for example, 403 ingress-port-denied
// or 404 unknown-sandbox). It is intentionally NOT retried by retryTransport
// and does not trigger cache invalidation.
type agentsNetIngressDeniedError struct {
	Status int
	Reason string
}

func (e *agentsNetIngressDeniedError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("agents.net ingress rejected connection with HTTP %d (%s)", e.Status, e.Reason)
	}
	return fmt.Sprintf("agents.net ingress rejected connection with HTTP %d", e.Status)
}

// agentsNetIngressTransientError represents a retriable 5xx error from the
// node-local agents.net ingress bridge (for example, 503 sandbox-not-ready or
// 502 ingress-dial-failed while a freshly-started sandbox listener is binding).
// retryTransport retries it without evicting the node's cache entry.
type agentsNetIngressTransientError struct {
	Status int
	Reason string
}

func (e *agentsNetIngressTransientError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("agents.net ingress temporarily unavailable with HTTP %d (%s)", e.Status, e.Reason)
	}
	return fmt.Sprintf("agents.net ingress temporarily unavailable with HTTP %d", e.Status)
}

type closeWriter interface {
	CloseWrite() error
}

type boundedIngressConnReader struct {
	r         io.Reader
	remaining int
}

func (b *boundedIngressConnReader) Read(p []byte) (int, error) {
	if b.remaining < 0 {
		return b.r.Read(p)
	}
	if b.remaining == 0 {
		return 0, errors.New("agents.net ingress CONNECT response header exceeded maximum size")
	}
	if len(p) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.r.Read(p)
	b.remaining -= n
	return n, err
}

type bufferedIngressConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedIngressConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *bufferedIngressConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

type tlsFileStamp struct {
	mtime time.Time
	size  int64
	ino   uint64
}

func statTLSFile(path string) (tlsFileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return tlsFileStamp{}, err
	}
	st := tlsFileStamp{mtime: info.ModTime(), size: info.Size()}
	if sys, ok := info.Sys().(*syscall.Stat_t); ok && sys != nil {
		st.ino = sys.Ino
	}
	return st, nil
}

// agentsNetIngressTLSLoader caches and hot-reloads the client TLS configuration
// for the node-local agents.net ingress bridge without latching transient load errors.
type agentsNetIngressTLSLoader struct {
	cfg *config.Config

	mu        sync.Mutex
	tlsCfg    *tls.Config
	caStamp   tlsFileStamp
	certStamp tlsFileStamp
	keyStamp  tlsFileStamp
}

func (l *agentsNetIngressTLSLoader) get() (*tls.Config, error) {
	if l.cfg == nil || (l.cfg.AgentsNetIngressCAFile == "" && l.cfg.AgentsNetIngressCertFile == "" && l.cfg.AgentsNetIngressKeyFile == "") {
		return nil, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	var caStamp, certStamp, keyStamp tlsFileStamp
	var err error
	if l.cfg.AgentsNetIngressCAFile != "" {
		if caStamp, err = statTLSFile(l.cfg.AgentsNetIngressCAFile); err != nil {
			return nil, fmt.Errorf("stat agents.net ingress CA %q: %w", l.cfg.AgentsNetIngressCAFile, err)
		}
	}
	if l.cfg.AgentsNetIngressCertFile != "" || l.cfg.AgentsNetIngressKeyFile != "" {
		if l.cfg.AgentsNetIngressCertFile == "" || l.cfg.AgentsNetIngressKeyFile == "" {
			return nil, errors.New("both agents.net ingress client cert and key files are required")
		}
		if certStamp, err = statTLSFile(l.cfg.AgentsNetIngressCertFile); err != nil {
			return nil, fmt.Errorf("stat agents.net ingress client cert %q: %w", l.cfg.AgentsNetIngressCertFile, err)
		}
		if keyStamp, err = statTLSFile(l.cfg.AgentsNetIngressKeyFile); err != nil {
			return nil, fmt.Errorf("stat agents.net ingress client key %q: %w", l.cfg.AgentsNetIngressKeyFile, err)
		}
	}

	if l.tlsCfg != nil && caStamp == l.caStamp && certStamp == l.certStamp && keyStamp == l.keyStamp {
		return l.tlsCfg, nil
	}

	tcfg, err := buildAgentsNetIngressTLS(l.cfg)
	if err != nil {
		return nil, err
	}
	l.tlsCfg = tcfg
	l.caStamp = caStamp
	l.certStamp = certStamp
	l.keyStamp = keyStamp
	return l.tlsCfg, nil
}

func wrapAgentsNetDialer(
	baseDial func(ctx context.Context, network, addr string) (net.Conn, error),
	cfg *config.Config,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	tlsLoader := &agentsNetIngressTLSLoader{cfg: cfg}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, ok := agentsNetIngressTargetFromContext(ctx)
		if !ok {
			return baseDial(ctx, network, addr)
		}

		tcfg, err := tlsLoader.get()
		if err != nil {
			return nil, err
		}

		conn, err := baseDial(ctx, "tcp", target.BridgeAddr)
		if err != nil {
			return nil, err
		}

		if tcfg != nil {
			clone := tcfg.Clone()
			if cfg != nil && cfg.AgentsNetIngressServerName != "" {
				clone.ServerName = cfg.AgentsNetIngressServerName
			} else if host, _, err := net.SplitHostPort(target.BridgeAddr); err == nil {
				clone.ServerName = host
			}
			tlsConn := tls.Client(conn, clone)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("tls handshake with agents.net ingress %s: %w", target.BridgeAddr, err)
			}
			conn = tlsConn
		}

		handshakeDeadline := time.Now().Add(agentsNetIngressHandshakeTimeout)
		if ctxDeadline, hasDeadline := ctx.Deadline(); hasDeadline && ctxDeadline.Before(handshakeDeadline) {
			handshakeDeadline = ctxDeadline
		}
		_ = conn.SetDeadline(handshakeDeadline)
		stopCancel := context.AfterFunc(ctx, func() {
			_ = conn.SetDeadline(time.Now())
		})

		authority := net.JoinHostPort(target.PodUID, strconv.Itoa(target.Port))
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
			stopCancel()
			_ = conn.Close()
			return nil, fmt.Errorf("write CONNECT to agents.net ingress: %w", err)
		}

		limited := &boundedIngressConnReader{r: conn, remaining: maxIngressConnectResponseBytes}
		br := bufio.NewReader(limited)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			stopCancel()
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("read CONNECT response from agents.net ingress: %w", err)
		}
		_ = resp.Body.Close()
		if !stopCancel() {
			_ = conn.Close()
			return nil, ctx.Err()
		}
		_ = conn.SetDeadline(time.Time{})
		limited.remaining = -1

		if resp.StatusCode != http.StatusOK {
			reason := resp.Header.Get("Boundary-Reason")
			_ = conn.Close()
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return nil, &agentsNetIngressDeniedError{
					Status: resp.StatusCode,
					Reason: reason,
				}
			}
			status := resp.StatusCode
			if status < 500 || status > 599 {
				status = http.StatusBadGateway
			}
			return nil, &agentsNetIngressTransientError{
				Status: status,
				Reason: reason,
			}
		}

		if br.Buffered() > 0 {
			return &bufferedIngressConn{Conn: conn, r: br}, nil
		}
		return conn, nil
	}
}

func buildAgentsNetIngressTLS(cfg *config.Config) (*tls.Config, error) {
	if cfg == nil || (cfg.AgentsNetIngressCAFile == "" && cfg.AgentsNetIngressCertFile == "") {
		return nil, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.AgentsNetIngressCAFile != "" {
		caBytes, err := os.ReadFile(cfg.AgentsNetIngressCAFile)
		if err != nil {
			return nil, fmt.Errorf("read agents.net ingress CA %q: %w", cfg.AgentsNetIngressCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("no valid CA certificates in %q", cfg.AgentsNetIngressCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.AgentsNetIngressCertFile != "" || cfg.AgentsNetIngressKeyFile != "" {
		if cfg.AgentsNetIngressCertFile == "" || cfg.AgentsNetIngressKeyFile == "" {
			return nil, errors.New("both agents.net ingress client cert and key files are required")
		}
		pair, err := tls.LoadX509KeyPair(cfg.AgentsNetIngressCertFile, cfg.AgentsNetIngressKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load agents.net ingress client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	return tlsCfg, nil
}
