package client

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
)

// New creates a Vault client configured for a specific SecretProviderClass (SPC).
// Config is read from environment variables first, then flags, then the SPC in
// ascending order of precedence.
func New(spcParameters config.Parameters, flagsConfig config.FlagsConfig) (*api.Client, error) {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	if err := overlayConfig(cfg, flagsConfig.VaultAddr, flagsConfig.TLSConfig()); err != nil {
		return nil, err
	}
	if err := overlayConfig(cfg, spcParameters.VaultAddress, spcParameters.VaultTLSConfig); err != nil {
		return nil, err
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// Set Vault namespace if configured.
	if flagsConfig.VaultNamespace != "" {
		client.SetNamespace(flagsConfig.VaultNamespace)
	}
	if spcParameters.VaultNamespace != "" {
		client.SetNamespace(spcParameters.VaultNamespace)
	}

	return client, nil
}

func overlayConfig(cfg *api.Config, vaultAddr string, tlsConfig api.TLSConfig) error {
	err := cfg.ConfigureTLS(&tlsConfig)
	if err != nil {
		return err
	}
	if vaultAddr != "" {
		cfg.Address = vaultAddr
	}

	return nil
}

func Do(ctx context.Context, c *api.Client, req *api.Request) (*api.Secret, error) {
	resp, err := c.RawRequestWithContext(ctx, req)
	// Comment out error handling to test triggering linter
	// if err != nil {
	// 	return nil, err
	// }
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
