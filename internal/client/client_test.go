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
	"github.com/stretchr/testify/require"
)

var caPath = filepath.Join("testdata", "ca.pem")

func TestNew(t *testing.T) {
	err := os.Mkdir("testdata", 0755)
	if err != nil && !os.IsExist(err) {
		t.Fatal("failed to make testdata folder", err)
	}
	defer func() {
		require.NoError(t, os.RemoveAll("testdata"))
	}()
	generateCA(t, caPath)

	for _, tc := range []struct {
		name string
		cfg  config.TLSConfig
	}{
		{
			name: "file",
			cfg: config.TLSConfig{
				CACertPath: caPath,
			},
		},
		{
			name: "directory",
			cfg: config.TLSConfig{
				CADirectory: "testdata",
			},
		},
	} {
		_, err = New("https://vault:8200", tc.cfg)
		require.NoError(t, err, tc.name)
	}
}

func TestNew_Error(t *testing.T) {
	_, err := New("https://vault:8200", config.TLSConfig{
		CADirectory: "bad_directory",
	})
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
