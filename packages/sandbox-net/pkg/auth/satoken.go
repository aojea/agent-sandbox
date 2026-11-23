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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
)

// PodSATokenPath returns the host kubelet projected volume path for a Pod's
// audience-bound ServiceAccount token (isolated to the tun2connect sidecar).
func PodSATokenPath(kubeletRoot string, podUID types.UID, volumeName string) string {
	if volumeName == "" {
		volumeName = sandboxv1beta1.SandboxNetSATokenVolumeName
	}
	return filepath.Join(
		kubeletRoot,
		"pods",
		string(podUID),
		"volumes",
		"kubernetes.io~projected",
		volumeName,
		sandboxv1beta1.SandboxNetSATokenFile,
	)
}

// rotatingTokenLoader caches a projected ServiceAccount JWT file and reloads
// automatically whenever kubelet rotates the token on disk.
type rotatingTokenLoader struct {
	tokenPath string

	mu    sync.Mutex
	token string
	mtime time.Time
	size  int64
}

func (l *rotatingTokenLoader) BearerHeader(_ context.Context) (string, error) {
	info, err := os.Stat(l.tokenPath)
	if err != nil {
		return "", fmt.Errorf("stat ServiceAccount token %q: %w", l.tokenPath, err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.token != "" && info.ModTime().Equal(l.mtime) && info.Size() == l.size {
		return "Bearer " + l.token, nil
	}

	raw, err := os.ReadFile(l.tokenPath)
	if err != nil {
		return "", fmt.Errorf("read ServiceAccount token %q: %w", l.tokenPath, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("ServiceAccount token file %q is empty", l.tokenPath)
	}
	l.token = tok
	l.mtime = info.ModTime()
	l.size = info.Size()
	return "Bearer " + tok, nil
}

func (r *Resolver) resolveServiceAccountToken(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	saSpec := req.Upstream.Auth.ServiceAccountToken
	if saSpec == nil || strings.TrimSpace(saSpec.Audience) == "" {
		return nil, errors.New("serviceAccountToken.audience is required when auth.type is ServiceAccountToken")
	}

	tlsCfg, err := r.buildServerTLSConfig(ctx, req.Upstream.TLS, req.PodNamespace)
	if err != nil {
		return nil, err
	}

	mode := saSpec.Mode
	if mode == "" {
		mode = sandboxv1beta1.SandboxServiceAccountTokenModeNode
	}

	var tokenPath string
	switch mode {
	case sandboxv1beta1.SandboxServiceAccountTokenModeNode:
		tokenPath = r.defaultNodeTokenPath
	case sandboxv1beta1.SandboxServiceAccountTokenModePod:
		if req.PodUID == "" {
			return nil, errors.New("podUID is required for Pod-mode ServiceAccountToken auth")
		}
		tokenPath = PodSATokenPath(r.kubeletRootDir, req.PodUID, req.SATokenVolumeName)
	default:
		return nil, fmt.Errorf("unsupported serviceAccountToken.mode %q", mode)
	}

	loader := &rotatingTokenLoader{tokenPath: tokenPath}
	return &ClientConfig{
		AuthMode:           AuthModeServiceAccountToken,
		TLSConfig:          tlsCfg,
		ProxyAuthorization: loader.BearerHeader,
	}, nil
}
