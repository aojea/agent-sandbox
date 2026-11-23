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

// Package auth implements all four native Kubernetes upstream authentication
// mechanisms for the sandbox-net agents.net node plumbing:
//   - MTLS (rotated PEM client certificate from host directory or Secret)
//   - SPIFFE (Workload API Node SVID and SPIRE Delegated Identity per-Pod SVID)
//   - PodCertificate (KEP-4317 kubelet-projected PKCS#8+chain credential bundle)
//   - ServiceAccountToken (audience-bound JWT in Proxy-Authorization, Node or Pod mode)
package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	sandboxv1beta1 "sigs.k8s.io/agent-sandbox/api/v1beta1"
	"sigs.k8s.io/agent-sandbox/packages/sandbox-net/pkg/catrust"
)

const (
	// DefaultKubeletRootDir is the default host kubelet data directory.
	DefaultKubeletRootDir = "/var/lib/kubelet"

	// DefaultNodeTokenPath is the default projected ServiceAccount token path
	// mounted on the sandbox-net DaemonSet for ServiceAccountToken Node mode.
	DefaultNodeTokenPath = "/var/run/secrets/sandbox-net/token"

	// DefaultSPIFFEWorkloadSocket is the default SPIFFE Workload API UDS path.
	DefaultSPIFFEWorkloadSocket = "/run/spire/agent-sockets/spire-agent.sock"

	// DefaultSPIREDelegatedSocket is the default SPIRE Agent Delegated Identity UDS path.
	DefaultSPIREDelegatedSocket = "/run/spire/agent-sockets/admin.sock"

	// Standardized agents.net attested workload identity headers forwarded on
	// authenticated upstream CONNECT and connect-udp requests.
	HeaderSandboxNamespace = "Agents-Net-Sandbox-Namespace"
	HeaderSandboxName      = "Agents-Net-Sandbox-Name"
	HeaderPodName          = "Agents-Net-Pod-Name"
	HeaderPodUID           = "Agents-Net-Pod-Uid"
	HeaderServiceAccount   = "Agents-Net-Service-Account"
	HeaderNodeName         = "Agents-Net-Node-Name"
	HeaderClaimUID         = "Agents-Net-Claim-Uid"
	HeaderClaimName        = "Agents-Net-Claim-Name"
	HeaderCustomPrefix     = "Agents-Net-Param-"
)

// AuthMode metric label values (strictly bounded enum).
const (
	AuthModeNone                = "none"
	AuthModeMTLS                = "mtls"
	AuthModeSPIFFE              = "spiffe"
	AuthModePodCertificate      = "pod_certificate"
	AuthModeServiceAccountToken = "service_account_token"
)

// WorkloadIdentity holds the unforgeable Pod, Sandbox, and Claim metadata
// attested by the node plumbing from kubelet, DRA, NRI, and the local Pod watch.
type WorkloadIdentity struct {
	Namespace      string
	PodName        string
	PodUID         types.UID
	ServiceAccount string
	NodeName       string
	SandboxName    string
	ClaimUID       string
	ClaimName      string
	Custom         map[string]string
}

// AttestedHeaders formats the WorkloadIdentity into standardized Agents-Net-* HTTP headers.
func (id WorkloadIdentity) AttestedHeaders() http.Header {
	h := make(http.Header, 8+len(id.Custom))
	if id.Namespace != "" {
		h.Set(HeaderSandboxNamespace, id.Namespace)
	}
	if id.SandboxName != "" {
		h.Set(HeaderSandboxName, id.SandboxName)
	}
	if id.PodName != "" {
		h.Set(HeaderPodName, id.PodName)
	}
	if id.PodUID != "" {
		h.Set(HeaderPodUID, string(id.PodUID))
	}
	if id.ServiceAccount != "" {
		h.Set(HeaderServiceAccount, id.ServiceAccount)
	}
	if id.NodeName != "" {
		h.Set(HeaderNodeName, id.NodeName)
	}
	if id.ClaimUID != "" {
		h.Set(HeaderClaimUID, id.ClaimUID)
	}
	if id.ClaimName != "" {
		h.Set(HeaderClaimName, id.ClaimName)
	}
	for k, v := range id.Custom {
		if safeKey := sanitizeHeaderToken(k); safeKey != "" && !strings.ContainsAny(v, "\r\n") {
			h.Set(HeaderCustomPrefix+safeKey, v)
		}
	}
	return h
}

func sanitizeHeaderToken(raw string) string {
	var b strings.Builder
	b.Grow(len(raw))
	for i := range len(raw) {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// ClientConfig holds resolved TLS and Proxy-Authorization material for dialing an upstream.
type ClientConfig struct {
	// AuthMode is the bounded metric label identifying the active authentication mode.
	AuthMode string

	// TLSConfig is used to establish the TLS or mTLS transport connection to the upstream.
	TLSConfig *tls.Config

	// ProxyAuthorization optionally returns a Proxy-Authorization header value
	// (for example "Bearer <jwt>") for each upstream CONNECT or connect-udp request.
	ProxyAuthorization func(ctx context.Context) (string, error)

	closeFn func() error
}

// Close releases any per-Pod streaming resources (such as a delegated SPIFFE stream).
func (c *ClientConfig) Close() error {
	if c == nil || c.closeFn == nil {
		return nil
	}
	return c.closeFn()
}

// ResolverConfig configures the node-wide upstream authentication resolver.
type ResolverConfig struct {
	KubeletRootDir              string
	DefaultNodeTokenPath        string
	DefaultSPIFFEWorkloadSocket string
	DefaultSPIREDelegatedSocket string
	KubeClient                  kubernetes.Interface
}

// Resolver produces live-rotating ClientConfigs for upstream connections across all four
// native authentication modes and caches shared node-level SPIFFE Workload API sources.
type Resolver struct {
	kubeletRootDir              string
	defaultNodeTokenPath        string
	defaultSPIFFEWorkloadSocket string
	defaultSPIREDelegatedSocket string
	kubeClient                  kubernetes.Interface

	mu            sync.Mutex
	spiffeSources map[string]*workloadapi.X509Source
}

// NewResolver constructs a node-wide upstream auth Resolver.
func NewResolver(cfg ResolverConfig) *Resolver {
	kubeletRoot := cfg.KubeletRootDir
	if kubeletRoot == "" {
		kubeletRoot = DefaultKubeletRootDir
	}
	nodeTok := cfg.DefaultNodeTokenPath
	if nodeTok == "" {
		nodeTok = DefaultNodeTokenPath
	}
	spiffeSock := cfg.DefaultSPIFFEWorkloadSocket
	if spiffeSock == "" {
		if env := os.Getenv("SPIFFE_ENDPOINT_SOCKET"); env != "" {
			spiffeSock = env
		} else {
			spiffeSock = DefaultSPIFFEWorkloadSocket
		}
	}
	delegatedSock := cfg.DefaultSPIREDelegatedSocket
	if delegatedSock == "" {
		delegatedSock = DefaultSPIREDelegatedSocket
	}
	return &Resolver{
		kubeletRootDir:              kubeletRoot,
		defaultNodeTokenPath:        nodeTok,
		defaultSPIFFEWorkloadSocket: spiffeSock,
		defaultSPIREDelegatedSocket: delegatedSock,
		kubeClient:                  cfg.KubeClient,
		spiffeSources:               make(map[string]*workloadapi.X509Source),
	}
}

// Close shuts down cached node-level SPIFFE Workload API sources.
func (r *Resolver) Close() error {
	r.mu.Lock()
	sources := r.spiffeSources
	r.spiffeSources = make(map[string]*workloadapi.X509Source)
	r.mu.Unlock()

	var errs []error
	for _, src := range sources {
		if err := src.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ResolveRequest identifies the target upstream, Pod namespace/UID, and optional kubelet
// projected volume names for PodCertificate and Pod-mode ServiceAccountToken auth.
type ResolveRequest struct {
	Upstream          *sandboxv1beta1.SandboxNetworkUpstream
	PodNamespace      string
	PodUID            types.UID
	PodCertVolumeName string
	SATokenVolumeName string
}

// Resolve builds the ClientConfig (TLS/mTLS + optional Proxy-Authorization) for req.
func (r *Resolver) Resolve(ctx context.Context, req ResolveRequest) (*ClientConfig, error) {
	if req.Upstream == nil || strings.TrimSpace(req.Upstream.Address) == "" {
		return nil, errors.New("upstream address is required")
	}

	if req.Upstream.Auth == nil {
		tlsCfg, err := r.buildServerTLSConfig(ctx, req.Upstream.TLS, req.PodNamespace)
		if err != nil {
			return nil, err
		}
		return &ClientConfig{
			AuthMode:  AuthModeNone,
			TLSConfig: tlsCfg,
		}, nil
	}

	switch req.Upstream.Auth.Type {
	case sandboxv1beta1.SandboxUpstreamAuthTypeMTLS:
		return r.resolveMTLS(ctx, req)
	case sandboxv1beta1.SandboxUpstreamAuthTypeSPIFFE:
		return r.resolveSPIFFE(ctx, req)
	case sandboxv1beta1.SandboxUpstreamAuthTypePodCertificate:
		return r.resolvePodCertificate(ctx, req)
	case sandboxv1beta1.SandboxUpstreamAuthTypeServiceAccountToken:
		return r.resolveServiceAccountToken(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported upstream auth type %q", req.Upstream.Auth.Type)
	}
}

// buildServerTLSConfig constructs a tls.Config verifying the upstream server certificate
// against the configured CA bundle (or system roots) and optional SPIFFE ID constraints.
func (r *Resolver) buildServerTLSConfig(ctx context.Context, tlsSpec *sandboxv1beta1.SandboxUpstreamTLS, namespace string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if tlsSpec == nil {
		return cfg, nil
	}
	cfg.ServerName = tlsSpec.ServerName

	if len(tlsSpec.CACertificateRefs) > 0 {
		pemBytes, err := catrust.LoadSourcesPEM(ctx, r.kubeClient, tlsSpec.CACertificateRefs, namespace)
		if err != nil {
			return nil, fmt.Errorf("load upstream TLS caCertificateRefs: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("no valid CA certificates in upstream TLS caCertificateRefs")
		}
		cfg.RootCAs = pool
	}

	if tlsSpec.TrustDomain != "" || len(tlsSpec.AcceptedSPIFFEIDs) > 0 {
		allowedIDs, allowedDomain, err := parseSPIFFEConstraints(tlsSpec)
		if err != nil {
			return nil, err
		}
		// When verifying by SPIFFE URI SAN without DNS hostname match, perform chain
		// verification explicitly against RootCAs and validate the peer's SPIFFE ID.
		cfg.InsecureSkipVerify = true
		roots := cfg.RootCAs
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifySPIFFEPeerChain(rawCerts, roots, allowedDomain, allowedIDs)
		}
	}

	return cfg, nil
}

func parseSPIFFEConstraints(tlsSpec *sandboxv1beta1.SandboxUpstreamTLS) ([]spiffeid.ID, spiffeid.TrustDomain, error) {
	var allowedDomain spiffeid.TrustDomain
	if tlsSpec.TrustDomain != "" {
		td, err := spiffeid.TrustDomainFromString(tlsSpec.TrustDomain)
		if err != nil {
			return nil, spiffeid.TrustDomain{}, fmt.Errorf("invalid trustDomain %q: %w", tlsSpec.TrustDomain, err)
		}
		allowedDomain = td
	}
	var allowedIDs []spiffeid.ID
	for _, raw := range tlsSpec.AcceptedSPIFFEIDs {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return nil, spiffeid.TrustDomain{}, fmt.Errorf("invalid accepted SPIFFE ID %q: %w", raw, err)
		}
		allowedIDs = append(allowedIDs, id)
	}
	return allowedIDs, allowedDomain, nil
}

func verifySPIFFEPeerChain(rawCerts [][]byte, roots *x509.CertPool, allowedDomain spiffeid.TrustDomain, allowedIDs []spiffeid.ID) error {
	if len(rawCerts) == 0 {
		return errors.New("upstream presented no certificates")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse upstream certificate: %w", err)
		}
		certs = append(certs, c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("verify upstream certificate chain: %w", err)
	}

	peerID, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		return fmt.Errorf("extract upstream SPIFFE ID: %w", err)
	}
	if len(allowedIDs) > 0 {
		if !slices.Contains(allowedIDs, peerID) {
			return fmt.Errorf("upstream SPIFFE ID %q is not in acceptedSPIFFEIDs", peerID.String())
		}
	}
	if !allowedDomain.IsZero() && peerID.TrustDomain() != allowedDomain {
		return fmt.Errorf("upstream SPIFFE trust domain %q does not match %q", peerID.TrustDomain().Name(), allowedDomain.Name())
	}
	return nil
}
