package client

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
)

func New(vaultAddress string, tlsConfig config.TLSConfig) (*api.Client, error) {
	cfg := api.DefaultConfig()
	err := cfg.ConfigureTLS(&api.TLSConfig{
		CACert:        tlsConfig.CACertPath,
		CAPath:        tlsConfig.CADirectory,
		ClientCert:    tlsConfig.ClientCertPath,
		ClientKey:     tlsConfig.ClientKeyPath,
		TLSServerName: tlsConfig.TLSServerName,
		Insecure:      tlsConfig.SkipVerify,
	})
	if err != nil {
		return nil, err
	}
	if vaultAddress != "" {
		cfg.Address = vaultAddress
	}

	return api.NewClient(cfg)
}

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
