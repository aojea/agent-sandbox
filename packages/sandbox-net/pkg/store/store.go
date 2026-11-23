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

// Package store provides the in-memory and BoltDB tmpfs checkpoint store that
// bridges DRA slow-path PrepareResourceClaims and NRI fast-path hooks across
// sandbox-net DaemonSet restarts.
package store

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/catrust"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/params"
)

// SocketPaths holds the per-Pod host directories and Unix socket paths created
// during DRA PrepareResourceClaims and bind-mounted by NRI CreateContainer.
type SocketPaths struct {
	PodRootDir        string `json:"podRootDir"`
	EgressDir         string `json:"egressDir"`
	EgressSocketPath  string `json:"egressSocketPath"`
	IngressDir        string `json:"ingressDir,omitempty"`
	IngressSocketPath string `json:"ingressSocketPath,omitempty"`
}

// PodConfig holds the checkpointed plumbing state for one sandbox Pod on this node.
type PodConfig struct {
	PodUID           types.UID                  `json:"podUID"`
	PodName          string                     `json:"podName,omitempty"`
	PodNamespace     string                     `json:"podNamespace,omitempty"`
	ServiceAccount   string                     `json:"serviceAccount,omitempty"`
	SandboxName      string                     `json:"sandboxName,omitempty"`
	ClaimUID         types.UID                  `json:"claimUID"`
	ClaimNamespace   string                     `json:"claimNamespace"`
	ClaimName        string                     `json:"claimName"`
	SandboxClaimUID  string                     `json:"sandboxClaimUID,omitempty"`
	SandboxClaimName string                     `json:"sandboxClaimName,omitempty"`
	DeviceName       string                     `json:"deviceName"`
	PoolName         string                     `json:"poolName"`
	NetNS            string                     `json:"netNS,omitempty"`
	Parameters       params.NetworkParameters   `json:"parameters"`
	SocketPaths      SocketPaths                `json:"socketPaths"`
	CABundle         catrust.MaterializedBundle `json:"caBundle,omitzero"`
	LastNRIActivity  time.Time                  `json:"lastNRIActivity,omitzero"`
}

// Backend abstracts persistent checkpoint storage (BoltDB on tmpfs in production, nil in memory-only tests).
type Backend interface {
	Put(podUID types.UID, data []byte) error
	Delete(podUID types.UID) error
	LoadAll() (map[types.UID][]byte, error)
	Close() error
}

// PodConfigStore is a concurrency-safe cache of active sandbox Pod plumbing state
// backed by an optional persistent checkpoint Backend.
type PodConfigStore struct {
	mu      sync.RWMutex
	byPod   map[types.UID]PodConfig
	byClaim map[types.UID]types.UID
	backend Backend
}

// New creates a PodConfigStore and hydrates any checkpointed records from backend.
func New(backend Backend) (*PodConfigStore, error) {
	s := &PodConfigStore{
		byPod:   make(map[types.UID]PodConfig),
		byClaim: make(map[types.UID]types.UID),
		backend: backend,
	}
	if backend != nil {
		raws, err := backend.LoadAll()
		if err != nil {
			return nil, fmt.Errorf("load checkpointed pod configs: %w", err)
		}
		for uid, data := range raws {
			var cfg PodConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				return nil, fmt.Errorf("unmarshal checkpoint for pod %s: %w", uid, err)
			}
			if cfg.PodUID == "" {
				cfg.PodUID = uid
			}
			s.byPod[cfg.PodUID] = cfg
			if cfg.ClaimUID != "" {
				s.byClaim[cfg.ClaimUID] = cfg.PodUID
			}
		}
	}
	return s, nil
}

// Upsert stores cfg in memory and persists it to the checkpoint backend.
func (s *PodConfigStore) Upsert(cfg PodConfig) error {
	if cfg.PodUID == "" {
		return fmt.Errorf("podUID is required")
	}
	cloned := clonePodConfig(cfg)
	if s.backend != nil {
		data, err := json.Marshal(cloned)
		if err != nil {
			return fmt.Errorf("marshal pod config: %w", err)
		}
		if err := s.backend.Put(cloned.PodUID, data); err != nil {
			return fmt.Errorf("checkpoint pod config %s: %w", cloned.PodUID, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byPod[cloned.PodUID]; ok && prev.ClaimUID != "" && prev.ClaimUID != cloned.ClaimUID {
		delete(s.byClaim, prev.ClaimUID)
	}
	s.byPod[cloned.PodUID] = cloned
	if cloned.ClaimUID != "" {
		s.byClaim[cloned.ClaimUID] = cloned.PodUID
	}
	return nil
}

// Get returns a defensive copy of the PodConfig for podUID.
func (s *PodConfigStore) Get(podUID types.UID) (PodConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cfg, ok := s.byPod[podUID]
	if !ok {
		return PodConfig{}, false
	}
	return clonePodConfig(cfg), true
}

// GetByClaimUID looks up a PodConfig using its DRA ResourceClaim UID.
func (s *PodConfigStore) GetByClaimUID(claimUID types.UID) (PodConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	podUID, ok := s.byClaim[claimUID]
	if !ok {
		return PodConfig{}, false
	}
	cfg, ok := s.byPod[podUID]
	if !ok {
		return PodConfig{}, false
	}
	return clonePodConfig(cfg), true
}

// UpdateNetNS records the Pod network namespace path and NRI activity timestamp.
func (s *PodConfigStore) UpdateNetNS(podUID types.UID, netNS string, now time.Time) error {
	s.mu.Lock()
	cfg, ok := s.byPod[podUID]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	cfg.NetNS = netNS
	cfg.LastNRIActivity = now
	s.byPod[podUID] = cfg
	cloned := clonePodConfig(cfg)
	s.mu.Unlock()

	if s.backend != nil {
		data, err := json.Marshal(cloned)
		if err != nil {
			return err
		}
		return s.backend.Put(podUID, data)
	}
	return nil
}

// UpdateIdentity refreshes the attested Pod/Sandbox/Claim metadata for podUID.
func (s *PodConfigStore) UpdateIdentity(podUID types.UID, podName, podNamespace, sa, sandboxName, claimUID, claimName string) error {
	s.mu.Lock()
	cfg, ok := s.byPod[podUID]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	if podName != "" {
		cfg.PodName = podName
	}
	if podNamespace != "" {
		cfg.PodNamespace = podNamespace
	}
	if sa != "" {
		cfg.ServiceAccount = sa
	}
	if sandboxName != "" {
		cfg.SandboxName = sandboxName
	}
	cfg.SandboxClaimUID = claimUID
	cfg.SandboxClaimName = claimName
	s.byPod[podUID] = cfg
	cloned := clonePodConfig(cfg)
	s.mu.Unlock()

	if s.backend != nil {
		data, err := json.Marshal(cloned)
		if err != nil {
			return err
		}
		return s.backend.Put(podUID, data)
	}
	return nil
}

// TouchNRIActivity updates the in-memory NRI activity timestamp for podUID.
func (s *PodConfigStore) TouchNRIActivity(podUID types.UID, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg, ok := s.byPod[podUID]; ok {
		cfg.LastNRIActivity = now
		s.byPod[podUID] = cfg
	}
}

// Delete removes podUID from memory and the checkpoint backend.
func (s *PodConfigStore) Delete(podUID types.UID) error {
	s.mu.Lock()
	cfg, existed := s.byPod[podUID]
	delete(s.byPod, podUID)
	if existed && cfg.ClaimUID != "" {
		delete(s.byClaim, cfg.ClaimUID)
	}
	s.mu.Unlock()

	if s.backend != nil {
		if err := s.backend.Delete(podUID); err != nil {
			return fmt.Errorf("delete checkpoint for pod %s: %w", podUID, err)
		}
	}
	return nil
}

// ListPodUIDs returns all tracked Pod UIDs.
func (s *PodConfigStore) ListPodUIDs() []types.UID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]types.UID, 0, len(s.byPod))
	for uid := range s.byPod {
		out = append(out, uid)
	}
	return out
}

// Close closes the underlying checkpoint backend if configured.
func (s *PodConfigStore) Close() error {
	if s.backend == nil {
		return nil
	}
	return s.backend.Close()
}

func clonePodConfig(cfg PodConfig) PodConfig {
	out := cfg
	if cfg.Parameters.Upstream != nil {
		out.Parameters.Upstream = cfg.Parameters.Upstream.DeepCopy()
	}
	if cfg.Parameters.CATrust != nil {
		out.Parameters.CATrust = cfg.Parameters.CATrust.DeepCopy()
	}
	if cfg.Parameters.Proxy != nil {
		out.Parameters.Proxy = cfg.Parameters.Proxy.DeepCopy()
	}
	out.Parameters.IngressPorts = slices.Clone(cfg.Parameters.IngressPorts)
	if cfg.Parameters.MaxConnections != nil {
		out.Parameters.MaxConnections = new(*cfg.Parameters.MaxConnections)
	}
	if cfg.Parameters.IdleTimeoutSeconds != nil {
		out.Parameters.IdleTimeoutSeconds = new(*cfg.Parameters.IdleTimeoutSeconds)
	}
	if cfg.Parameters.Custom != nil {
		out.Parameters.Custom = maps.Clone(cfg.Parameters.Custom)
	}
	if cfg.Parameters.Opaque != nil {
		out.Parameters.Opaque = make(map[string]json.RawMessage, len(cfg.Parameters.Opaque))
		for k, v := range cfg.Parameters.Opaque {
			out.Parameters.Opaque[k] = slices.Clone(v)
		}
	}
	return out
}
