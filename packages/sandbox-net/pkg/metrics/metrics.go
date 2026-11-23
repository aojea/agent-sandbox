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

// Package metrics defines Prometheus instrumentation for the sandbox-net
// node plumbing DaemonSet using strictly bounded-cardinality enum labels.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const subsystem = "sandbox_net"

var (
	// TunnelsTotal counts intercepted agents.net CONNECT and connect-udp requests
	// forwarded to the upstream proxy.
	// Labels are strictly bounded enums:
	//   transport: tcp | udp
	//   auth_mode: none | mtls | spiffe | pod_certificate | service_account_token
	//   decision:  allow | deny | error
	//   reason:    allowed | malformed | upstream_denied | upstream_auth_failed |
	//              upstream_unavailable | listener_revoked | max_connections
	TunnelsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "tunnels_total",
			Help:      "Total agents.net tunnel requests processed by sandbox-net.",
		},
		[]string{"transport", "auth_mode", "decision", "reason"},
	)

	// ActiveTunnels tracks the number of currently open upstream tunnels on this node.
	ActiveTunnels = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "active_tunnels",
			Help:      "Current number of active agents.net tunnels forwarded by this node.",
		},
	)

	// ActiveSandboxes tracks the number of sandbox Pods currently plumbed on this node.
	ActiveSandboxes = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: subsystem,
			Name:      "active_sandboxes",
			Help:      "Current number of sandbox Pods with an active agents.net listener on this node.",
		},
	)

	// DriverHookRequestsTotal counts DRA and NRI lifecycle hook calls.
	// Labels: hook (PrepareResourceClaims | UnprepareResourceClaims | Synchronize |
	//   RunPodSandbox | CreateContainer | StopPodSandbox | RemovePodSandbox),
	// result (success | failed).
	DriverHookRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: subsystem,
			Name:      "driver_hook_requests_total",
			Help:      "Total DRA and NRI lifecycle hook invocations.",
		},
		[]string{"hook", "result"},
	)

	// TunnelDialDurationSeconds measures upstream tunnel establishment latency.
	TunnelDialDurationSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Subsystem: subsystem,
			Name:      "tunnel_dial_duration_seconds",
			Help:      "Latency of establishing an authenticated tunnel to the upstream agents.net proxy.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"protocol", "auth_mode"},
	)
)
