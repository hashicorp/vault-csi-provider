package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/config"
	"github.com/stretchr/testify/require"
)

var caPath = filepath.Join("testdata", "ca.pem")

func TestGetRootCAsPools(t *testing.T) {
	generateCA(t, caPath)
	defer func() {
		require.NoError(t, os.Remove(caPath))
	}()
	ca, err := ioutil.ReadFile(caPath)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		cfg  config.TLSConfig
	}{
		{
			name: "PEM encoded",
			cfg: config.TLSConfig{
				VaultCAPEM: string(ca),
			},
		},
		{
			name: "file",
			cfg: config.TLSConfig{
				VaultCACertPath: caPath,
			},
		},
		{
			name: "directory",
			cfg: config.TLSConfig{
				VaultCADirectory: "testdata",
			},
		},
		{
			name: "system",
			cfg:  config.TLSConfig{},
		},
	} {
		pool, err := getRootCAsPools(tc.cfg)
		require.NoError(t, err, tc.name)
		require.True(t, len(pool.Subjects()) > 0)
	}
}

func TestGetRootCAsAsPoolsError(t *testing.T) {
	generateCA(t, caPath)
	defer func() {
		require.NoError(t, os.Remove(caPath))
	}()
	ca, err := ioutil.ReadFile(path.Join("testdata", "bad_directory", "not-a-ca.pem"))
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		cfg  config.TLSConfig
	}{
		{
			name: "PEM encoded error",
			cfg: config.TLSConfig{
				VaultCAPEM: string(ca),
			},
		},
		{
			name: "file error",
			cfg: config.TLSConfig{
				VaultCACertPath: path.Join("testdata", "bad_directory", "not-a-ca.pem"),
			},
		},
		{
			name: "directory error",
			cfg: config.TLSConfig{
				VaultCADirectory: path.Join("testdata", "bad_directory"),
			},
		},
	} {
		_, err := getRootCAsPools(tc.cfg)
		require.Error(t, err, tc.name)
	}
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
