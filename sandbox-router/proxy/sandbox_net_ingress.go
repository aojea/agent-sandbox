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
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"sigs.k8s.io/agent-sandbox/sandbox-router/config"
)

type sandboxNetIngressContextKey struct{}

// sandboxNetIngressTarget identifies the node-local sandbox-net ingress bridge
// endpoint and target Pod UID + port for a single proxied request.
type sandboxNetIngressTarget struct {
	BridgeAddr string
	PodUID     string
	Port       int
}

func withSandboxNetIngressTarget(ctx context.Context, target sandboxNetIngressTarget) context.Context {
	return context.WithValue(ctx, sandboxNetIngressContextKey{}, target)
}

func sandboxNetIngressTargetFromContext(ctx context.Context) (sandboxNetIngressTarget, bool) {
	t, ok := ctx.Value(sandboxNetIngressContextKey{}).(sandboxNetIngressTarget)
	return t, ok
}

// sandboxNetIngressDeniedError represents an explicit HTTP rejection from the
// node-local sandbox-net ingress bridge (for example, 403 ingress-port-denied
// or 404 unknown-sandbox). It is intentionally NOT retried by retryTransport
// and does not trigger cache invalidation.
type sandboxNetIngressDeniedError struct {
	Status int
	Reason string
}

func (e *sandboxNetIngressDeniedError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("sandbox-net ingress rejected connection with HTTP %d (%s)", e.Status, e.Reason)
	}
	return fmt.Sprintf("sandbox-net ingress rejected connection with HTTP %d", e.Status)
}

type bufferedIngressConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedIngressConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func wrapSandboxNetDialer(
	baseDial func(ctx context.Context, network, addr string) (net.Conn, error),
	cfg *config.Config,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var (
		tlsOnce sync.Once
		tlsCfg  *tls.Config
		tlsErr  error
	)
	getTLSConfig := func() (*tls.Config, error) {
		tlsOnce.Do(func() {
			tlsCfg, tlsErr = buildSandboxNetIngressTLS(cfg)
		})
		return tlsCfg, tlsErr
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, ok := sandboxNetIngressTargetFromContext(ctx)
		if !ok {
			return baseDial(ctx, network, addr)
		}

		tcfg, err := getTLSConfig()
		if err != nil {
			return nil, err
		}

		conn, err := baseDial(ctx, "tcp", target.BridgeAddr)
		if err != nil {
			return nil, err
		}

		if tcfg != nil {
			clone := tcfg.Clone()
			if host, _, err := net.SplitHostPort(target.BridgeAddr); err == nil {
				clone.ServerName = host
			}
			tlsConn := tls.Client(conn, clone)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("tls handshake with sandbox-net ingress %s: %w", target.BridgeAddr, err)
			}
			conn = tlsConn
		}

		if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
			_ = conn.SetDeadline(deadline)
		} else {
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		}
		stopCancel := context.AfterFunc(ctx, func() {
			_ = conn.SetDeadline(time.Now())
		})

		authority := net.JoinHostPort(target.PodUID, strconv.Itoa(target.Port))
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", authority, authority); err != nil {
			stopCancel()
			_ = conn.Close()
			return nil, fmt.Errorf("write CONNECT to sandbox-net ingress: %w", err)
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			stopCancel()
			_ = conn.Close()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("read CONNECT response from sandbox-net ingress: %w", err)
		}
		_ = resp.Body.Close()
		if !stopCancel() {
			_ = conn.Close()
			return nil, ctx.Err()
		}
		_ = conn.SetDeadline(time.Time{})

		if resp.StatusCode != http.StatusOK {
			reason := resp.Header.Get("Boundary-Reason")
			_ = conn.Close()
			return nil, &sandboxNetIngressDeniedError{
				Status: resp.StatusCode,
				Reason: reason,
			}
		}

		if br.Buffered() > 0 {
			return &bufferedIngressConn{Conn: conn, r: br}, nil
		}
		return conn, nil
	}
}

func buildSandboxNetIngressTLS(cfg *config.Config) (*tls.Config, error) {
	if cfg == nil || (cfg.SandboxNetIngressCAFile == "" && cfg.SandboxNetIngressCertFile == "") {
		return nil, nil
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.SandboxNetIngressCAFile != "" {
		caBytes, err := os.ReadFile(cfg.SandboxNetIngressCAFile)
		if err != nil {
			return nil, fmt.Errorf("read sandbox-net ingress CA %q: %w", cfg.SandboxNetIngressCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("no valid CA certificates in %q", cfg.SandboxNetIngressCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.SandboxNetIngressCertFile != "" || cfg.SandboxNetIngressKeyFile != "" {
		if cfg.SandboxNetIngressCertFile == "" || cfg.SandboxNetIngressKeyFile == "" {
			return nil, errors.New("both sandbox-net ingress client cert and key files are required")
		}
		pair, err := tls.LoadX509KeyPair(cfg.SandboxNetIngressCertFile, cfg.SandboxNetIngressKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load sandbox-net ingress client keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	return tlsCfg, nil
}
