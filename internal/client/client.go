package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/config"
	"github.com/hashicorp/vault/api"
	"github.com/pkg/errors"
	"golang.org/x/net/http2"
)

func Do(ctx context.Context, c *api.Client, req *api.Request) (*api.Secret, error) {
	resp, err := c.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received empty response from %q", req.URL.Path)
	}

	defer resp.Body.Close()
	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}

	return secret, nil
}

func CreateHTTPClient(tlsConfig config.TLSConfig) (*http.Client, error) {
	rootCAs, err := getRootCAsPools(tlsConfig)
	if err != nil {
		return nil, err
	}

	tlsClientConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}

	if tlsConfig.VaultSkipTLSVerify {
		tlsClientConfig.InsecureSkipVerify = true
	}

	if tlsConfig.VaultTLSServerName != "" {
		tlsClientConfig.ServerName = tlsConfig.VaultTLSServerName
	}

	transport := &http.Transport{
		TLSClientConfig: tlsClientConfig,
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, errors.New("failed to configure http2")
	}

	return &http.Client{
		Transport: transport,
	}, nil
}

func getRootCAsPools(tlsConfig config.TLSConfig) (*x509.CertPool, error) {
	switch {
	case tlsConfig.VaultCAPEM != "":
		certPool := x509.NewCertPool()
		if err := loadCert(certPool, []byte(tlsConfig.VaultCAPEM)); err != nil {
			return nil, err
		}
		return certPool, nil
	case tlsConfig.VaultCADirectory != "":
		certPool := x509.NewCertPool()
		if err := loadCertFolder(certPool, tlsConfig.VaultCADirectory); err != nil {
			return nil, err
		}
		return certPool, nil
	case tlsConfig.VaultCACertPath != "":
		certPool := x509.NewCertPool()
		if err := loadCertFile(certPool, tlsConfig.VaultCACertPath); err != nil {
			return nil, err
		}
		return certPool, nil
	default:
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, errors.Wrapf(err, "couldn't load system certs")
		}
		return certPool, err
	}
}

// loadCert loads a single pem-encoded certificate into the given pool.
func loadCert(pool *x509.CertPool, pem []byte) error {
	if ok := pool.AppendCertsFromPEM(pem); !ok {
		return fmt.Errorf("failed to parse PEM")
	}
	return nil
}

// loadCertFile loads the certificate at the given path into the given pool.
func loadCertFile(pool *x509.CertPool, p string) error {
	pem, err := ioutil.ReadFile(p)
	if err != nil {
		return errors.Wrapf(err, "couldn't read CA file from disk")
	}

	if err := loadCert(pool, pem); err != nil {
		return errors.Wrapf(err, "couldn't load CA at %s", p)
	}

	return nil
}

// loadCertFolder iterates exactly one level below the given directory path and
// loads all certificates in that path. It does not recurse.
func loadCertFolder(pool *x509.CertPool, root string) error {
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if path != root {
				return filepath.SkipDir
			}

			return nil
		}

		return loadCertFile(pool, path)
	}); err != nil {
		return errors.Wrapf(err, "failed to load CAs at %s", root)
	}
	return nil
}
