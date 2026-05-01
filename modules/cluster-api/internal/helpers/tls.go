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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/kubetail-org/kubetail/modules/cluster-api/pkg/config"
)

// clientAuthTypes maps the validated config strings to the crypto/tls
// constants. Keep in sync with the `oneof` validator on Config.TLS.ClientAuthType.
var clientAuthTypes = map[string]tls.ClientAuthType{
	"":                   tls.NoClientCert,
	"none":               tls.NoClientCert,
	"request":            tls.RequestClientCert,
	"require":            tls.RequireAnyClientCert,
	"verify-if-given":    tls.VerifyClientCertIfGiven,
	"require-and-verify": tls.RequireAndVerifyClientCert,
}

// BuildTLSConfig assembles a *tls.Config from the cluster-api TLS settings,
// or returns nil when TLS is disabled. Cert/key are loaded by the http.Server
// itself; this only handles MinVersion + mTLS client auth.
func BuildTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if !cfg.TLS.Enabled {
		return nil, nil
	}

	clientAuth, ok := clientAuthTypes[cfg.TLS.ClientAuthType]
	if !ok {
		return nil, fmt.Errorf("unknown client-auth-type %q", cfg.TLS.ClientAuthType)
	}

	out := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: clientAuth,
	}

	if cfg.TLS.ClientCAFile != "" {
		pem, err := os.ReadFile(cfg.TLS.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client-ca-file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client-ca-file %q contains no valid PEM certificates", cfg.TLS.ClientCAFile)
		}
		out.ClientCAs = pool
	}

	return out, nil
}
