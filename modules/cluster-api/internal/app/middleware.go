// Copyright 2024 The Kubetail Authors
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

package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/kubetail-org/kubetail/modules/shared/k8shelpers"
)

// setImpersonateOnRequest writes the authenticated identity to the Go
// request context so the in-cluster ImpersonatingRoundTripper can attach
// Impersonate-* headers on each downstream Kubernetes API call.
func setImpersonateOnRequest(c *gin.Context, info *k8shelpers.ImpersonateInfo) {
	ctx := context.WithValue(c.Request.Context(), k8shelpers.K8SImpersonateCtxKey, info)
	c.Request = c.Request.WithContext(ctx)
}

// gin context keys populated by the aggregation auth middleware. Downstream
// handlers (impersonation when constructing k8s clients) read these instead
// of touching the bearer-token path.
const (
	aggUserKey   = "aggUser"
	aggGroupsKey = "aggGroups"
	aggExtrasKey = "aggExtras"
)

// aggregationAuthConfig holds the parsed contents of kube-system's
// extension-apiserver-authentication ConfigMap plus the operator-supplied
// client CA. Built once at startup so each request only does cert verification.
type aggregationAuthConfig struct {
	// ClientCAs verifies certs for callers connecting directly with mTLS
	// (e.g. operators using kubectl --client-certificate against the
	// cluster-api Service). When matched, the cert CN becomes the user.
	ClientCAs *x509.CertPool

	// ProxyCAs verifies certs presented by the kube-apiserver front-proxy.
	// When matched, identity is read from request headers.
	ProxyCAs *x509.CertPool

	// AllowedNames is the list of CNs the front-proxy cert may present
	// (`requestheader-allowed-names`). Empty means any CN is accepted.
	AllowedNames []string

	UsernameHeaders      []string
	GroupHeaders         []string
	ExtraHeadersPrefixes []string
}

// newAggregationAuthMiddleware authenticates the caller using either the
// client CA (direct mTLS) or the front-proxy CA (kube-apiserver aggregation).
// Identity (user/groups/extras) is stored in the gin context for downstream
// impersonation.
func newAggregationAuthMiddleware(cfg *aggregationAuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		r := c.Request

		// Reject requests that did not present a client cert. With mTLS
		// configured at the listener (ClientAuth=RequireAndVerifyClientCert)
		// this should be unreachable, but we guard anyway.
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "client certificate required"})
			return
		}

		now := time.Now()

		// Direct-mTLS path: verify the leaf against the client CA pool. On
		// success the cert CN is the authenticated user; groups/extras come
		// from the cert itself only via the CN, so we leave them empty.
		leaf := r.TLS.PeerCertificates[0]
		if cfg.ClientCAs != nil {
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:       cfg.ClientCAs,
				CurrentTime: now,
				KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}); err == nil {
				user := leaf.Subject.CommonName
				c.Set(aggUserKey, user)
				setImpersonateOnRequest(c, &k8shelpers.ImpersonateInfo{User: user})
				c.Next()
				return
			}
		}

		// Front-proxy path: any cert in the chain that verifies against the
		// proxy CA is accepted as the kube-apiserver's outbound cert.
		var proxyCert *x509.Certificate
		if cfg.ProxyCAs != nil {
			intermediates := x509.NewCertPool()
			for _, cert := range r.TLS.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			opts := x509.VerifyOptions{
				Roots:         cfg.ProxyCAs,
				Intermediates: intermediates,
				CurrentTime:   now,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			for _, cert := range r.TLS.PeerCertificates {
				if _, err := cert.Verify(opts); err == nil {
					proxyCert = cert
					break
				}
			}
		}
		if proxyCert == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no valid certificate found"})
			return
		}

		// `requestheader-allowed-names` gates which front-proxy CNs we trust.
		// Empty list means any CN is accepted (matches kube-apiserver behavior).
		if len(cfg.AllowedNames) > 0 {
			cn := proxyCert.Subject.CommonName
			if !slices.Contains(cfg.AllowedNames, cn) {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": fmt.Sprintf("proxy CN %q not in allowed list", cn),
				})
				return
			}
		}

		// Pull user out of the configured username headers; first non-empty wins.
		var user string
		for _, h := range cfg.UsernameHeaders {
			if v := c.GetHeader(h); v != "" {
				user = v
				break
			}
		}
		if user == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user header"})
			return
		}
		c.Set(aggUserKey, user)

		// Groups: first non-empty header, comma-split.
		var groups []string
		for _, h := range cfg.GroupHeaders {
			if v := c.GetHeader(h); v != "" {
				groups = append(groups, strings.Split(v, ",")...)
				break
			}
		}
		c.Set(aggGroupsKey, groups)

		// Extras: any header whose name has a configured prefix becomes an
		// entry in the extras map under the suffix portion.
		extras := map[string][]string{}
		for name, vals := range r.Header {
			for _, prefix := range cfg.ExtraHeadersPrefixes {
				if after, ok := strings.CutPrefix(name, prefix); ok {
					extras[after] = vals
				}
			}
		}
		c.Set(aggExtrasKey, extras)

		setImpersonateOnRequest(c, &k8shelpers.ImpersonateInfo{
			User:   user,
			Groups: groups,
			Extras: extras,
		})

		c.Next()
	}
}

// loadAggregationAuthConfig reads kube-system's
// extension-apiserver-authentication ConfigMap and returns a parsed
// aggregationAuthConfig. The kube-apiserver maintains this ConfigMap; any
// service registered as an APIService is expected to read it for its
// front-proxy CA + request-header configuration.
func loadAggregationAuthConfig(ctx context.Context, cs kubernetes.Interface) (*aggregationAuthConfig, error) {
	cm, err := cs.CoreV1().ConfigMaps("kube-system").Get(ctx, "extension-apiserver-authentication", metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read extension-apiserver-authentication: %w", err)
	}

	clientCAs := x509.NewCertPool()
	if pemBytes := cm.Data["client-ca-file"]; pemBytes != "" {
		if !clientCAs.AppendCertsFromPEM([]byte(pemBytes)) {
			return nil, fmt.Errorf("client-ca-file in extension-apiserver-authentication is not valid PEM")
		}
	}

	proxyCAs := x509.NewCertPool()
	if pemBytes := cm.Data["requestheader-client-ca-file"]; pemBytes != "" {
		if !proxyCAs.AppendCertsFromPEM([]byte(pemBytes)) {
			return nil, fmt.Errorf("requestheader-client-ca-file in extension-apiserver-authentication is not valid PEM")
		}
	}

	out := &aggregationAuthConfig{ClientCAs: clientCAs, ProxyCAs: proxyCAs}
	for _, f := range []struct {
		key string
		dst *[]string
	}{
		{"requestheader-allowed-names", &out.AllowedNames},
		{"requestheader-username-headers", &out.UsernameHeaders},
		{"requestheader-group-headers", &out.GroupHeaders},
		{"requestheader-extra-headers-prefix", &out.ExtraHeadersPrefixes},
	} {
		if raw := cm.Data[f.key]; raw != "" {
			if err := json.Unmarshal([]byte(raw), f.dst); err != nil {
				return nil, fmt.Errorf("parse %s: %w", f.key, err)
			}
		}
	}
	return out, nil
}
