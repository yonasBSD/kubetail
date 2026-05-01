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

package helpers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kubetail-org/kubetail/modules/cluster-api/pkg/config"
)

// writeTestCA generates a self-signed CA cert and writes it as PEM to a temp
// file. Returns the path. Used so the `file` validator passes and the
// builder has real PEM to load.
func writeTestCA(t *testing.T) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	require.NoError(t, err)

	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func TestBuildTLSConfigDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TLS.Enabled = false

	got, err := BuildTLSConfig(cfg)
	require.NoError(t, err)
	assert.Nil(t, got, "no TLS config should be built when TLS is disabled")
}

func TestBuildTLSConfigNoMTLS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.TLS.Enabled = true

	got, err := BuildTLSConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)
	assert.Equal(t, tls.NoClientCert, got.ClientAuth)
	assert.Nil(t, got.ClientCAs)
}

func TestBuildTLSConfigClientAuthTypes(t *testing.T) {
	caPath := writeTestCA(t)

	cases := map[string]tls.ClientAuthType{
		"none":               tls.NoClientCert,
		"request":            tls.RequestClientCert,
		"require":            tls.RequireAnyClientCert,
		"verify-if-given":    tls.VerifyClientCertIfGiven,
		"require-and-verify": tls.RequireAndVerifyClientCert,
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.TLS.Enabled = true
			cfg.TLS.ClientCAFile = caPath
			cfg.TLS.ClientAuthType = name

			got, err := BuildTLSConfig(cfg)
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, want, got.ClientAuth)
			require.NotNil(t, got.ClientCAs, "ClientCAs must be loaded when client-ca-file is set")
		})
	}
}

func TestBuildTLSConfigInvalidCAFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(path, []byte("not a pem"), 0o600))

	cfg := config.DefaultConfig()
	cfg.TLS.Enabled = true
	cfg.TLS.ClientCAFile = path
	cfg.TLS.ClientAuthType = "require-and-verify"

	_, err := BuildTLSConfig(cfg)
	require.Error(t, err)
}
