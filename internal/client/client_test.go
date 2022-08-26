package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

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
		_, err = New(config.Parameters{
			VaultTLSConfig: tc.cfg,
		}, config.FlagsConfig{})
		require.NoError(t, err, tc.name)
	}
}

func TestConfigPrecedence(t *testing.T) {
	if originalVaultAddr, isSet := os.LookupEnv(api.EnvVaultAddress); isSet {
		defer os.Setenv(api.EnvVaultAddress, originalVaultAddr)
	}
	err := os.Setenv(api.EnvVaultAddress, "from-env")
	require.NoError(t, err)

	client, err := New(config.Parameters{}, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, "from-env", client.Address())

	client, err = New(config.Parameters{}, config.FlagsConfig{
		VaultAddr: "from-flags",
	})
	require.NoError(t, err)
	assert.Equal(t, "from-flags", client.Address())

	client, err = New(config.Parameters{
		VaultAddress: "from-parameters",
	}, config.FlagsConfig{
		VaultAddr: "from-flags",
	})
	require.NoError(t, err)
	assert.Equal(t, "from-parameters", client.Address())
}

func TestNew_Error(t *testing.T) {
	_, err := New(config.Parameters{
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
