// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
	vaultapi "github.com/hashicorp/vault/api"
)

var (
	ErrPermissionDenied = errors.New("permission denied")
)

type Client struct {
	logger hclog.Logger
	inner  *vaultapi.Client

	k8sAuthMountPath string
	roleName         string
}

// New creates a Vault client configured for a specific SecretProviderClass (SPC).
// Config is read from environment variables first, then flags, then the SPC in
// ascending order of precedence.
func New(logger hclog.Logger, spcParameters config.Parameters, flagsConfig config.FlagsConfig) (*Client, error) {
	cfg := vaultapi.DefaultConfig()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	if err := overlayConfig(cfg, flagsConfig.VaultAddr, flagsConfig.TLSConfig()); err != nil {
		return nil, err
	}
	if err := overlayConfig(cfg, spcParameters.VaultAddress, spcParameters.VaultTLSConfig); err != nil {
		return nil, err
	}

	client, err := vaultapi.NewClient(cfg)
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
	k8sAuthMountPath := spcParameters.VaultKubernetesMountPath
	if k8sAuthMountPath == "" {
		k8sAuthMountPath = flagsConfig.VaultMount
	}

	return &Client{
		logger: logger,
		inner:  client,

		k8sAuthMountPath: k8sAuthMountPath,
		roleName:         spcParameters.VaultRoleName,
	}, nil
}

func overlayConfig(cfg *vaultapi.Config, vaultAddr string, tlsConfig vaultapi.TLSConfig) error {
	err := cfg.ConfigureTLS(&tlsConfig)
	if err != nil {
		return err
	}
	if vaultAddr != "" {
		cfg.Address = vaultAddr
	}

	return nil
}

func (c *Client) Login(ctx context.Context, jwt string) error {
	req := c.inner.NewRequest(http.MethodPost, "/v1/auth/"+c.k8sAuthMountPath+"/login")
	if err := req.SetJSONBody(map[string]string{
		"jwt":  jwt,
		"role": c.roleName,
	}); err != nil {
		return err
	}

	resp, err := c.doInternal(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}
	secret, err := vaultapi.ParseSecret(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse login response: %w", err)
	}

	c.inner.SetToken(secret.Auth.ClientToken)

	return nil
}

func (c *Client) RequestSecret(ctx context.Context, secretConfig config.Secret) (*vaultapi.Secret, error) {
	req, err := c.generateRequest(secretConfig)
	if err != nil {
		return nil, err
	}

	c.logger.Debug("Requesting secret", "secretConfig", secretConfig, "method", req.Method, "path", req.URL.Path, "params", req.Params)

	resp, err := c.doInternal(ctx, req)
	if err != nil && resp != nil && resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: %w", ErrPermissionDenied, err)
	}
	if err != nil {
		return nil, fmt.Errorf("error requesting secret: %w", err)
	}

	return vaultapi.ParseSecret(resp.Body)
}

func (c *Client) doInternal(ctx context.Context, req *vaultapi.Request) (*vaultapi.Response, error) {
	resp, err := c.inner.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received empty response from %q", req.URL.Path)
	}

	return resp, nil
}

func (c *Client) generateRequest(secret config.Secret) (*api.Request, error) {
	secretPath := ensureV1Prefix(secret.SecretPath)
	queryIndex := strings.Index(secretPath, "?")
	var queryParams map[string][]string
	if queryIndex != -1 {
		var err error
		queryParams, err = url.ParseQuery(secretPath[queryIndex+1:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse query parameters from secretPath %q for objectName %q: %w", secretPath, secret.ObjectName, err)
		}
		secretPath = secretPath[:queryIndex]
	}
	method := http.MethodGet
	if secret.Method != "" {
		method = secret.Method
	}

	req := c.inner.NewRequest(method, secretPath)
	if queryParams != nil {
		req.Params = queryParams
	}
	if secret.SecretArgs != nil {
		err := req.SetJSONBody(secret.SecretArgs)
		if err != nil {
			return nil, err
		}
	}

	return req, nil
}

func ensureV1Prefix(s string) string {
	switch {
	case strings.HasPrefix(s, "/v1/"):
		return s
	case strings.HasPrefix(s, "v1/"):
		return "/" + s
	case strings.HasPrefix(s, "/"):
		return "/v1" + s
	default:
		return "/v1/" + s
	}
}
