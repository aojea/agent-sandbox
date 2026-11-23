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

package auth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// rotatingPairLoader caches a TLS keypair loaded from certPath and keyPath,
// reloading automatically when either file's modification time or size changes.
type rotatingPairLoader struct {
	certPath string
	keyPath  string

	mu        sync.Mutex
	cert      *tls.Certificate
	certMtime time.Time
	keyMtime  time.Time
	certSize  int64
	keySize   int64
}

func (l *rotatingPairLoader) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	certInfo, err := os.Stat(l.certPath)
	if err != nil {
		return nil, fmt.Errorf("stat mTLS client cert %q: %w", l.certPath, err)
	}
	keyInfo, err := os.Stat(l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat mTLS client key %q: %w", l.keyPath, err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cert != nil &&
		certInfo.ModTime().Equal(l.certMtime) &&
		keyInfo.ModTime().Equal(l.keyMtime) &&
		certInfo.Size() == l.certSize &&
		keyInfo.Size() == l.keySize {
		return l.cert, nil
	}

	pair, err := tls.LoadX509KeyPair(l.certPath, l.keyPath)
	if err != nil {
		return nil, fmt.Errorf("load mTLS keypair (%q, %q): %w", l.certPath, l.keyPath, err)
	}
	l.cert = &pair
	l.certMtime = certInfo.ModTime()
	l.keyMtime = keyInfo.ModTime()
	l.certSize = certInfo.Size()
	l.keySize = keyInfo.Size()
	return l.cert, nil
}

func (r *Resolver) resolveMTLS(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	mtlsSpec := req.Upstream.Auth.MTLS
	if mtlsSpec == nil {
		return nil, errors.New("mtls auth config is required when auth.type is MTLS")
	}

	tlsCfg, err := r.buildServerTLSConfig(ctx, req.Upstream.TLS, req.PodNamespace)
	if err != nil {
		return nil, err
	}

	if mtlsSpec.CertDir != "" {
		loader := &rotatingPairLoader{
			certPath: filepath.Join(mtlsSpec.CertDir, "tls.crt"),
			keyPath:  filepath.Join(mtlsSpec.CertDir, "tls.key"),
		}
		// Validate initial load eagerly so broken configurations fail fast.
		if _, err := loader.GetClientCertificate(nil); err != nil {
			return nil, err
		}
		tlsCfg.GetClientCertificate = loader.GetClientCertificate
		return &ClientConfig{
			AuthMode:  AuthModeMTLS,
			TLSConfig: tlsCfg,
		}, nil
	}

	if mtlsSpec.SecretRef != nil && mtlsSpec.SecretRef.Name != "" {
		if r.kubeClient == nil {
			return nil, errors.New("kubernetes client is required to read mtls.secretRef")
		}
		secret, err := r.kubeClient.CoreV1().Secrets(req.PodNamespace).Get(ctx, mtlsSpec.SecretRef.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("get mTLS Secret %s/%s: %w", req.PodNamespace, mtlsSpec.SecretRef.Name, err)
		}
		certPEM := secret.Data["tls.crt"]
		keyPEM := secret.Data["tls.key"]
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			return nil, fmt.Errorf("mTLS Secret %s/%s must contain tls.crt and tls.key", req.PodNamespace, secret.Name)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse mTLS Secret %s/%s keypair: %w", req.PodNamespace, secret.Name, err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
		return &ClientConfig{
			AuthMode:  AuthModeMTLS,
			TLSConfig: tlsCfg,
		}, nil
	}

	return nil, errors.New("mtls auth requires either certDir or secretRef")
}
