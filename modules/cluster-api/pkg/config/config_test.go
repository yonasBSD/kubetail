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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestDefaultMTLSFields(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "", cfg.TLS.ClientCAFile)
	assert.Equal(t, "", cfg.TLS.ClientAuthType)
}

func TestLoadMTLSFields(t *testing.T) {
	// Write a CA file so client-ca-file passes the `file` validator.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, []byte("dummy"), 0o600))

	path := writeConfig(t, `
tls:
  client-ca-file: `+caPath+`
  client-auth-type: require-and-verify
`)
	cfg, err := NewConfig(path, viper.New())
	require.NoError(t, err)
	assert.Equal(t, caPath, cfg.TLS.ClientCAFile)
	assert.Equal(t, "require-and-verify", cfg.TLS.ClientAuthType)
}

func TestRejectsInvalidClientAuthType(t *testing.T) {
	path := writeConfig(t, `
tls:
  client-auth-type: bogus
`)
	_, err := NewConfig(path, viper.New())
	require.Error(t, err)
}
