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

// Package params decodes and layers DRA OpaqueDeviceConfiguration parameters
// (DeviceClass cluster defaults merged with per-ResourceClaim settings) for
// the sandbox-net node plumbing.
package params

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	resourceapi "k8s.io/api/resource/v1"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
)

const (
	// DefaultMaxConnections is the default per-Pod concurrent tunnel limit.
	DefaultMaxConnections int32 = 1024

	// DefaultIdleTimeoutSeconds is the default idle timeout for forwarded tunnels.
	DefaultIdleTimeoutSeconds int32 = 300
)

// NetworkParameters is the JSON payload carried in Kubernetes DRA
// OpaqueDeviceConfiguration (DeviceClass.spec.config and ResourceClaim.spec.devices.config)
// for driver sandbox-net.agents.x-k8s.io.
type NetworkParameters struct {
	ConfinementMode    sandboxv1beta1.SandboxConfinementMode      `json:"confinementMode,omitempty"`
	AdapterMode        sandboxv1beta1.SandboxAdapterMode          `json:"adapterMode,omitempty"`
	Upstream           *sandboxv1beta1.SandboxNetworkUpstream     `json:"upstream,omitempty"`
	CATrust            *sandboxv1beta1.SandboxCATrustSpec         `json:"caTrust,omitempty"`
	Proxy              *sandboxv1beta1.SandboxExplicitProxyConfig `json:"proxy,omitempty"`
	IngressPorts       []sandboxv1beta1.SandboxIngressPort        `json:"ingressPorts,omitempty"`
	PodCertVolumeName  string                                     `json:"podCertVolumeName,omitempty"`
	SATokenVolumeName  string                                     `json:"saTokenVolumeName,omitempty"`
	MaxConnections     *int32                                     `json:"maxConnections,omitempty"`
	IdleTimeoutSeconds *int32                                     `json:"idleTimeoutSeconds,omitempty"`
	// Custom holds string key-value parameters forwarded as attested metadata or driver config.
	Custom map[string]string `json:"custom,omitempty"`
	// Opaque holds arbitrary private JSON configuration objects supplied via DRA Opaque config.
	Opaque map[string]json.RawMessage `json:"opaque,omitempty"`
}

// EffectiveProxyPort returns the configured ExplicitProxy loopback port or the default (15001).
func (p NetworkParameters) EffectiveProxyPort() int32 {
	if p.Proxy != nil && p.Proxy.Port != nil && *p.Proxy.Port > 0 {
		return *p.Proxy.Port
	}
	return sandboxv1beta1.DefaultSandboxNetProxyPort
}

// Defaults returns a NetworkParameters initialized with safe defaults.
func Defaults() NetworkParameters {
	return NetworkParameters{
		ConfinementMode:    sandboxv1beta1.SandboxConfinementModePodNetworkIsolated,
		AdapterMode:        sandboxv1beta1.SandboxAdapterModeTunSidecar,
		MaxConnections:     new(DefaultMaxConnections),
		IdleTimeoutSeconds: new(DefaultIdleTimeoutSeconds),
	}
}

// Decode merges all matching OpaqueDeviceConfiguration entries from a DRA allocation
// in order (DeviceClass defaults first, then ResourceClaim overrides).
func Decode(configs []resourceapi.DeviceAllocationConfiguration, driverName string) (NetworkParameters, error) {
	out := Defaults()
	for _, cfg := range configs {
		if cfg.Opaque == nil || cfg.Opaque.Driver != driverName || len(cfg.Opaque.Parameters.Raw) == 0 {
			continue
		}
		var layer NetworkParameters
		if err := json.Unmarshal(cfg.Opaque.Parameters.Raw, &layer); err != nil {
			return out, fmt.Errorf("unmarshal opaque parameters for driver %q: %w", driverName, err)
		}
		Merge(&out, &layer)
	}
	return out, nil
}

// Merge overlays non-empty fields from src onto dst.
func Merge(dst, src *NetworkParameters) {
	if dst == nil || src == nil {
		return
	}
	if src.ConfinementMode != "" {
		dst.ConfinementMode = src.ConfinementMode
	}
	if src.AdapterMode != "" {
		dst.AdapterMode = src.AdapterMode
	}
	if src.Upstream != nil {
		dst.Upstream = mergeUpstream(dst.Upstream, src.Upstream)
	}
	if src.CATrust != nil {
		dst.CATrust = mergeCATrust(dst.CATrust, src.CATrust)
	}
	if src.Proxy != nil {
		dst.Proxy = mergeProxy(dst.Proxy, src.Proxy)
	}
	if len(src.IngressPorts) > 0 {
		dst.IngressPorts = slices.Clone(src.IngressPorts)
	}
	if src.PodCertVolumeName != "" {
		dst.PodCertVolumeName = src.PodCertVolumeName
	}
	if src.SATokenVolumeName != "" {
		dst.SATokenVolumeName = src.SATokenVolumeName
	}
	if src.MaxConnections != nil {
		dst.MaxConnections = new(*src.MaxConnections)
	}
	if src.IdleTimeoutSeconds != nil {
		dst.IdleTimeoutSeconds = new(*src.IdleTimeoutSeconds)
	}
	if len(src.Custom) > 0 {
		if dst.Custom == nil {
			dst.Custom = make(map[string]string, len(src.Custom))
		}
		maps.Copy(dst.Custom, src.Custom)
	}
	if len(src.Opaque) > 0 {
		if dst.Opaque == nil {
			dst.Opaque = make(map[string]json.RawMessage, len(src.Opaque))
		}
		for k, v := range src.Opaque {
			dst.Opaque[k] = slices.Clone(v)
		}
	}
}

func mergeCATrust(base, overlay *sandboxv1beta1.SandboxCATrustSpec) *sandboxv1beta1.SandboxCATrustSpec {
	if base == nil {
		return overlay.DeepCopy()
	}
	out := base.DeepCopy()
	if overlay.Mode != "" {
		out.Mode = overlay.Mode
	}
	if overlay.BundleMode != "" {
		out.BundleMode = overlay.BundleMode
	}
	if len(overlay.Sources) > 0 {
		out.Sources = append(out.Sources, overlay.Sources...)
	}
	return out
}

func mergeProxy(base, overlay *sandboxv1beta1.SandboxExplicitProxyConfig) *sandboxv1beta1.SandboxExplicitProxyConfig {
	if base == nil {
		return overlay.DeepCopy()
	}
	out := base.DeepCopy()
	if overlay.Port != nil {
		out.Port = new(*overlay.Port)
	}
	if len(overlay.NoProxy) > 0 {
		out.NoProxy = append(out.NoProxy, overlay.NoProxy...)
	}
	return out
}

func mergeUpstream(base, overlay *sandboxv1beta1.SandboxNetworkUpstream) *sandboxv1beta1.SandboxNetworkUpstream {
	if base == nil {
		return overlay.DeepCopy()
	}
	out := base.DeepCopy()
	if overlay.Address != "" {
		out.Address = overlay.Address
	}
	if overlay.Protocol != "" {
		out.Protocol = overlay.Protocol
	}
	if overlay.TLS != nil {
		if out.TLS == nil {
			out.TLS = overlay.TLS.DeepCopy()
		} else {
			if overlay.TLS.ServerName != "" {
				out.TLS.ServerName = overlay.TLS.ServerName
			}
			if len(overlay.TLS.CACertificateRefs) > 0 {
				out.TLS.CACertificateRefs = make([]sandboxv1beta1.SandboxCASource, len(overlay.TLS.CACertificateRefs))
				for i := range overlay.TLS.CACertificateRefs {
					overlay.TLS.CACertificateRefs[i].DeepCopyInto(&out.TLS.CACertificateRefs[i])
				}
			}
			if overlay.TLS.TrustDomain != "" {
				out.TLS.TrustDomain = overlay.TLS.TrustDomain
			}
			if len(overlay.TLS.AcceptedSPIFFEIDs) > 0 {
				out.TLS.AcceptedSPIFFEIDs = slices.Clone(overlay.TLS.AcceptedSPIFFEIDs)
			}
		}
	}
	if overlay.Auth != nil {
		out.Auth = overlay.Auth.DeepCopy()
	}
	return out
}
