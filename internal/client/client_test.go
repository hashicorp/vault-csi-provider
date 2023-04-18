// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var caPath = filepath.Join("testdata", "ca.pem")

func TestNew(t *testing.T) {
	err := os.Mkdir("testdata", 0o755)
	if err != nil && !os.IsExist(err) {
		t.Fatal("failed to make testdata folder", err)
	}
	defer func() {
		require.NoError(t, os.RemoveAll("testdata"))
	}()
	generateCA(t, caPath)

	for _, tc := range []struct {
		name string
		cfg  api.TLSConfig
	}{
		{
			name: "file",
			cfg: api.TLSConfig{
				CACert: caPath,
			},
		},
		{
			name: "directory",
			cfg: api.TLSConfig{
				CAPath: "testdata",
			},
		},
	} {
		_, err = New(hclog.NewNullLogger(), config.Parameters{
			VaultTLSConfig: tc.cfg,
		}, config.FlagsConfig{})
		require.NoError(t, err, tc.name)
	}
}

func TestConfigPrecedence(t *testing.T) {
	if originalVaultAddr, isSet := os.LookupEnv(api.EnvVaultAddress); isSet {
		defer os.Setenv(api.EnvVaultAddress, originalVaultAddr)
	}
	t.Setenv(api.EnvVaultAddress, "from-env")

	client, err := New(hclog.NewNullLogger(), config.Parameters{}, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, "from-env", client.inner.Address())

	client, err = New(hclog.NewNullLogger(), config.Parameters{}, config.FlagsConfig{
		VaultAddr: "from-flags",
	})
	require.NoError(t, err)
	assert.Equal(t, "from-flags", client.inner.Address())

	client, err = New(hclog.NewNullLogger(), config.Parameters{
		VaultAddress: "from-parameters",
	}, config.FlagsConfig{
		VaultAddr: "from-flags",
	})
	require.NoError(t, err)
	assert.Equal(t, "from-parameters", client.inner.Address())
}

func TestNew_Error(t *testing.T) {
	_, err := New(hclog.NewNullLogger(), config.Parameters{
		VaultTLSConfig: api.TLSConfig{
			CAPath: "bad_directory",
		},
	}, config.FlagsConfig{})
	require.Error(t, err)
}

func generateCA(t *testing.T, path string) {
	// Based on https://golang.org/src/crypto/tls/generate_cert.go.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt32))
	require.NoError(t, err)
	caTemplate := x509.Certificate{
		IsCA:         true,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Tests'R'Us"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	bytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &key.PublicKey, key)
	require.NoError(t, err)
	certOut, err := os.Create(path)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, certOut.Close())
	}()
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: bytes})
	require.NoError(t, err)
}

func TestEnsureV1Prefix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected string
	}{
		{"no prefix", "secret/foo", "/v1/secret/foo"},
		{"leading slash", "/secret/foo", "/v1/secret/foo"},
		{"leading v1", "v1/secret/foo", "/v1/secret/foo"},
		{"leading /v1/", "/v1/secret/foo", "/v1/secret/foo"},
		// These will mostly be invalid paths, but testing reasonable behaviour.
		{"empty string", "", "/v1/"},
		{"just /v1/", "/v1/", "/v1/"},
		{"leading 1", "1/secret/foo", "/v1/1/secret/foo"},
		{"2* /v1/", "/v1/v1/", "/v1/v1/"},
		{"v2", "/v2/secret/foo", "/v1/v2/secret/foo"},
	} {
		assert.Equal(t, tc.expected, ensureV1Prefix(tc.input), tc.name)
	}
}

func TestGenerateRequest(t *testing.T) {
	type expected struct {
		method string
		path   string
		params string
		body   string
	}
	client, err := New(hclog.NewNullLogger(), config.Parameters{}, config.FlagsConfig{})
	require.NoError(t, err)
	for _, tc := range []struct {
		name     string
		secret   config.Secret
		expected expected
	}{
		{
			name: "base case",
			secret: config.Secret{
				SecretPath: "secret/foo",
			},
			expected: expected{http.MethodGet, "/v1/secret/foo", "", ""},
		},
		{
			name: "zero-length query string",
			secret: config.Secret{
				SecretPath: "secret/foo?",
			},
			expected: expected{http.MethodGet, "/v1/secret/foo", "", ""},
		},
		{
			name: "query string",
			secret: config.Secret{
				SecretPath: "secret/foo?bar=true&baz=maybe&zap=0",
			},
			expected: expected{http.MethodGet, "/v1/secret/foo", "bar=true&baz=maybe&zap=0", ""},
		},
		{
			name: "method specified",
			secret: config.Secret{
				SecretPath: "secret/foo",
				Method:     "PUT",
			},
			expected: expected{"PUT", "/v1/secret/foo", "", ""},
		},
		{
			name: "body specified",
			secret: config.Secret{
				SecretPath: "secret/foo",
				Method:     http.MethodPost,
				SecretArgs: map[string]interface{}{
					"bar": true,
					"baz": 10,
					"zap": "a string",
				},
			},
			expected: expected{http.MethodPost, "/v1/secret/foo", "", `{"bar":true,"baz":10,"zap":"a string"}`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := client.generateSecretRequest(tc.secret)
			require.NoError(t, err)
			assert.Equal(t, tc.expected.method, req.Method)
			assert.Equal(t, tc.expected.path, req.URL.Path)
			assert.Equal(t, tc.expected.params, req.Params.Encode())
			assert.Equal(t, tc.expected.body, string(req.BodyBytes))
		})
	}
}
