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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/kubetail-org/kubetail/modules/shared/k8shelpers"
)

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

// runMiddleware executes mw against r and returns the recorder, the gin
// context values, and the *ImpersonateInfo (if any) propagated onto the Go
// request context for downstream RoundTrippers.
func runMiddleware(mw gin.HandlerFunc, r *http.Request) (*httptest.ResponseRecorder, gin.H, *k8shelpers.ImpersonateInfo) {
	captured := gin.H{}
	var impersonate *k8shelpers.ImpersonateInfo
	router := gin.New()
	router.Use(mw)
	router.Any("/*any", func(c *gin.Context) {
		for _, k := range []string{aggUserKey, aggGroupsKey, aggExtrasKey} {
			if v, ok := c.Get(k); ok {
				captured[k] = v
			}
		}
		if v, ok := c.Request.Context().Value(k8shelpers.K8SImpersonateCtxKey).(*k8shelpers.ImpersonateInfo); ok {
			impersonate = v
		}
		c.String(http.StatusOK, "ok")
	})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w, captured, impersonate
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

	w, _, _ := runMiddleware(mw, requestWithCert(nil, nil))
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

	w, captured, impersonate := runMiddleware(mw, requestWithCert([]*x509.Certificate{leaf}, nil))
	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.Equal(t, "alice", captured[aggUserKey])
	require.NotNil(t, impersonate)
	assert.Equal(t, "alice", impersonate.User)
	assert.Empty(t, impersonate.Groups)
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
	w, captured, impersonate := runMiddleware(mw, r)
	require.Equal(t, http.StatusOK, w.Result().StatusCode)
	assert.Equal(t, "bob", captured[aggUserKey])
	assert.Equal(t, []string{"devs", "sre"}, captured[aggGroupsKey])

	extras, _ := captured[aggExtrasKey].(map[string][]string)
	assert.Equal(t, []string{"openid"}, extras["Scopes"])

	require.NotNil(t, impersonate)
	assert.Equal(t, "bob", impersonate.User)
	assert.Equal(t, []string{"devs", "sre"}, impersonate.Groups)
	assert.Equal(t, []string{"openid"}, impersonate.Extras["Scopes"])
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
	w, _, _ := runMiddleware(mw, r)
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

	w, _, _ := runMiddleware(mw, requestWithCert([]*x509.Certificate{proxyLeaf}, nil))
	assert.Equal(t, http.StatusUnauthorized, w.Result().StatusCode)
}

// caPEM returns the PEM encoding of ca.cert. Used to populate the ConfigMap
// data in loadAggregationAuthConfig tests.
func (ca *testCA) pem(t *testing.T) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
}

func TestLoadAggregationAuthConfig(t *testing.T) {
	clientCA := newTestCA(t, "client-ca")
	proxyCA := newTestCA(t, "proxy-ca")

	cs := fake.NewClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "extension-apiserver-authentication",
			Namespace: "kube-system",
		},
		Data: map[string]string{
			"client-ca-file":                     clientCA.pem(t),
			"requestheader-client-ca-file":       proxyCA.pem(t),
			"requestheader-allowed-names":        `["front-proxy-client"]`,
			"requestheader-username-headers":     `["X-Remote-User"]`,
			"requestheader-group-headers":        `["X-Remote-Group"]`,
			"requestheader-extra-headers-prefix": `["X-Remote-Extra-"]`,
		},
	})

	got, err := loadAggregationAuthConfig(context.Background(), cs)
	require.NoError(t, err)

	require.NotNil(t, got.ClientCAs)
	require.NotNil(t, got.ProxyCAs)
	assert.Equal(t, []string{"front-proxy-client"}, got.AllowedNames)
	assert.Equal(t, []string{"X-Remote-User"}, got.UsernameHeaders)
	assert.Equal(t, []string{"X-Remote-Group"}, got.GroupHeaders)
	assert.Equal(t, []string{"X-Remote-Extra-"}, got.ExtraHeadersPrefixes)

	// Sanity: a leaf signed by clientCA verifies against the loaded pool.
	leaf := clientCA.issue(t, "alice")
	_, verr := leaf.Verify(x509.VerifyOptions{Roots: got.ClientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	require.NoError(t, verr)
}

func TestLoadAggregationAuthConfigMissingConfigMap(t *testing.T) {
	cs := fake.NewClientset()
	_, err := loadAggregationAuthConfig(context.Background(), cs)
	require.Error(t, err)
}

func TestLoadAggregationAuthConfigBadJSON(t *testing.T) {
	clientCA := newTestCA(t, "client-ca")
	proxyCA := newTestCA(t, "proxy-ca")

	cs := fake.NewClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "extension-apiserver-authentication", Namespace: "kube-system"},
		Data: map[string]string{
			"client-ca-file":                     clientCA.pem(t),
			"requestheader-client-ca-file":       proxyCA.pem(t),
			"requestheader-allowed-names":        `not json`,
			"requestheader-username-headers":     `["X-Remote-User"]`,
			"requestheader-group-headers":        `["X-Remote-Group"]`,
			"requestheader-extra-headers-prefix": `["X-Remote-Extra-"]`,
		},
	})
	_, err := loadAggregationAuthConfig(context.Background(), cs)
	require.Error(t, err)
}
