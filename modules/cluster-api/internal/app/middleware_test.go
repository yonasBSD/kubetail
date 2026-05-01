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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubetail-org/kubetail/modules/cluster-api/graph"
	"github.com/kubetail-org/kubetail/modules/shared/grpchelpers"
	"github.com/kubetail-org/kubetail/modules/shared/httphelpers"
	"github.com/kubetail-org/kubetail/modules/shared/k8shelpers"
)

func TestAuthenticationMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		setHeaders map[string]string
		wantToken  interface{}
	}{
		{
			"authorization header",
			map[string]string{
				"Authorization": "Bearer xxx",
			},
			"xxx",
		},
		{
			"x-forwarded-authorization header",
			map[string]string{
				"X-Forwarded-Authorization": "Bearer xxx",
			},
			"xxx",
		},
		{
			"prefers x-forwarded-authorization header",
			map[string]string{
				"Authorization":             "Bearer yyy",
				"X-Forwarded-Authorization": "Bearer zzz",
			},
			"zzz",
		},
		{
			"empty token",
			map[string]string{
				"Authorization": "",
			},
			nil,
		},
		{
			"malformed token",
			map[string]string{
				"Authorization": "xxx",
			},
			nil,
		},
		{
			"whitespace-only bearer is treated as absent",
			map[string]string{
				"Authorization": "Bearer    ",
			},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Init router
			router := gin.New()

			// Add middleware
			router.Use(authenticationMiddleware)

			// Add route for testing
			router.GET("/", func(c *gin.Context) {
				// Check token
				ctx := c.Request.Context()

				// Check token for kubernetes requests
				val1 := ctx.Value(k8shelpers.K8STokenCtxKey)
				assert.Equal(t, tt.wantToken, val1)

				// Check token for gRPC requests
				val2 := ctx.Value(grpchelpers.K8STokenCtxKey)
				assert.Equal(t, tt.wantToken, val2)

				c.String(http.StatusOK, "ok")
			})

			// Build request
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)

			for key, val := range tt.setHeaders {
				r.Header.Add(key, val)
			}

			// Execute request
			router.ServeHTTP(w, r)

			// Check response
			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	}
}

func TestForwardedCSRFTokenMiddleware(t *testing.T) {
	tests := []struct {
		name        string
		headerSet   bool
		headerValue string
		isUpgrade   bool
		wantValue   any
	}{
		{"upgrade with header", true, "abc123", true, "abc123"},
		{"upgrade without header", false, "", true, nil},
		{"upgrade with empty header is not propagated", true, "", true, nil},
		{"non-upgrade ignores header", true, "abc123", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(forwardedCSRFTokenMiddleware)
			router.GET("/", func(c *gin.Context) {
				val := c.Request.Context().Value(graph.SessionCSRFTokenCtxKey)
				assert.Equal(t, tt.wantValue, val)
				c.String(http.StatusOK, "ok")
			})

			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			if tt.isUpgrade {
				r.Header.Set("Connection", "Upgrade")
				r.Header.Set("Upgrade", "websocket")
			}
			if tt.headerSet {
				r.Header.Set(httphelpers.HeaderForwardedCSRFToken, tt.headerValue)
			}
			router.ServeHTTP(w, r)
			assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		})
	}
}

// testCA is a minimal in-memory CA for issuing client certs in tests.
type testCA struct {
	cert *x509.Certificate
	key  ed25519.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &testCA{cert: cert, key: priv, pool: pool}
}

// issue signs a leaf cert with the given CN. The returned cert satisfies
// ExtKeyUsageClientAuth so x509 verification accepts it for client auth.
func (ca *testCA) issue(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// requestWithCert builds an HTTP request whose TLS.PeerCertificates contains
// the given chain (leaf first). Headers can be passed in to simulate the
// kube-apiserver front-proxy.
func requestWithCert(certs []*x509.Certificate, headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/apis/api.kubetail.com/v1/anything", nil)
	if certs != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: certs}
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// runMiddleware executes mw against r and returns the recorder plus the gin
// context values captured in a downstream handler.
func runMiddleware(mw gin.HandlerFunc, r *http.Request) (*httptest.ResponseRecorder, gin.H) {
	captured := gin.H{}
	router := gin.New()
	router.Use(mw)
	router.Any("/*any", func(c *gin.Context) {
		for _, k := range []string{aggUserKey, aggGroupsKey, aggExtrasKey} {
			if v, ok := c.Get(k); ok {
				captured[k] = v
			}
		}
		c.String(http.StatusOK, "ok")
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w, captured
}

func TestAggregationAuth_RejectsRequestWithoutPeerCert(t *testing.T) {
	clientCA := newTestCA(t, "client-ca")
	proxyCA := newTestCA(t, "proxy-ca")

	mw := newAggregationAuthMiddleware(&aggregationAuthConfig{
		ClientCAs:            clientCA.pool,
		ProxyCAs:             proxyCA.pool,
		UsernameHeaders:      []string{"X-Remote-User"},
		GroupHeaders:         []string{"X-Remote-Group"},
		ExtraHeadersPrefixes: []string{"X-Remote-Extra-"},
	})

	w, _ := runMiddleware(mw, requestWithCert(nil, nil))
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestAggregationAuth_DirectClientCert(t *testing.T) {
	clientCA := newTestCA(t, "client-ca")
	proxyCA := newTestCA(t, "proxy-ca")
	leaf := clientCA.issue(t, "alice")

	mw := newAggregationAuthMiddleware(&aggregationAuthConfig{
		ClientCAs:            clientCA.pool,
		ProxyCAs:             proxyCA.pool,
		UsernameHeaders:      []string{"X-Remote-User"},
		GroupHeaders:         []string{"X-Remote-Group"},
		ExtraHeadersPrefixes: []string{"X-Remote-Extra-"},
	})

	w, captured := runMiddleware(mw, requestWithCert([]*x509.Certificate{leaf}, nil))
	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.Equal(t, "alice", captured[aggUserKey])
}

func TestAggregationAuth_FrontProxyHeadersExtractIdentity(t *testing.T) {
	clientCA := newTestCA(t, "client-ca")
	proxyCA := newTestCA(t, "proxy-ca")
	proxyLeaf := proxyCA.issue(t, "front-proxy-client")

	mw := newAggregationAuthMiddleware(&aggregationAuthConfig{
		ClientCAs:            clientCA.pool,
		ProxyCAs:             proxyCA.pool,
		AllowedNames:         []string{"front-proxy-client"},
		UsernameHeaders:      []string{"X-Remote-User"},
		GroupHeaders:         []string{"X-Remote-Group"},
		ExtraHeadersPrefixes: []string{"X-Remote-Extra-"},
	})

	r := requestWithCert([]*x509.Certificate{proxyLeaf}, map[string]string{
		"X-Remote-User":         "bob",
		"X-Remote-Group":        "devs,sre",
		"X-Remote-Extra-Scopes": "openid",
	})
	w, captured := runMiddleware(mw, r)
	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.Equal(t, "bob", captured[aggUserKey])
	assert.Equal(t, []string{"devs", "sre"}, captured[aggGroupsKey])

	extras, _ := captured[aggExtrasKey].(map[string][]string)
	assert.Equal(t, []string{"openid"}, extras["Scopes"])
}

func TestAggregationAuth_FrontProxyCNNotAllowed(t *testing.T) {
	clientCA := newTestCA(t, "client-ca")
	proxyCA := newTestCA(t, "proxy-ca")
	proxyLeaf := proxyCA.issue(t, "stranger")

	mw := newAggregationAuthMiddleware(&aggregationAuthConfig{
		ClientCAs:            clientCA.pool,
		ProxyCAs:             proxyCA.pool,
		AllowedNames:         []string{"front-proxy-client"},
		UsernameHeaders:      []string{"X-Remote-User"},
		GroupHeaders:         []string{"X-Remote-Group"},
		ExtraHeadersPrefixes: []string{"X-Remote-Extra-"},
	})

	r := requestWithCert([]*x509.Certificate{proxyLeaf}, map[string]string{
		"X-Remote-User": "bob",
	})
	w, _ := runMiddleware(mw, r)
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

func TestAggregationAuth_FrontProxyMissingUsernameHeader(t *testing.T) {
	clientCA := newTestCA(t, "client-ca")
	proxyCA := newTestCA(t, "proxy-ca")
	proxyLeaf := proxyCA.issue(t, "front-proxy-client")

	mw := newAggregationAuthMiddleware(&aggregationAuthConfig{
		ClientCAs:            clientCA.pool,
		ProxyCAs:             proxyCA.pool,
		AllowedNames:         []string{"front-proxy-client"},
		UsernameHeaders:      []string{"X-Remote-User"},
		GroupHeaders:         []string{"X-Remote-Group"},
		ExtraHeadersPrefixes: []string{"X-Remote-Extra-"},
	})

	w, _ := runMiddleware(mw, requestWithCert([]*x509.Certificate{proxyLeaf}, nil))
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}
