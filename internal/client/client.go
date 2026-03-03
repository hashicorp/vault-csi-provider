// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/auth"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
)

type Client struct {
	logger hclog.Logger
	inner  *api.Client

	mtx sync.Mutex
}

// New creates a Vault client configured for a specific SecretProviderClass (SPC).
// Config is read from environment variables first, then flags, then the SPC in
// ascending order of precedence.
func New(logger hclog.Logger, spcParameters config.Parameters, flagsConfig config.FlagsConfig) (*Client, error) {
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

	inner, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// Set Vault namespace if configured.
	if flagsConfig.VaultNamespace != "" {
		inner.SetNamespace(flagsConfig.VaultNamespace)
	}
	if spcParameters.VaultNamespace != "" {
		inner.SetNamespace(spcParameters.VaultNamespace)
	}

	return &Client{
		logger: logger,
		inner:  inner,
	}, nil
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

// RequestSecret fetches a single secret response from Vault. It will trigger
// an initial authentication attempt if the client doesn't already have a Vault
// token. Otherwise, if it gets a 403 response from Vault it will attempt
// to reauthenticate and retry fetching the secret, on the assumption that
// the pre-existing token may have expired.
//
// We follow this pattern because we assume Vault Agent is caching and renewing
// our auth token, and we have no universal way to check it's still valid and
// in the Agent's cache before making a request.
func (c *Client) RequestSecret(ctx context.Context, authMethod *auth.KubernetesJWTAuth, secretConfig config.Secret) (*api.Secret, error) {
	// Ensure we have a token available.
	authed, err := c.auth(ctx, authMethod, "")
	if err != nil {
		return nil, err
	}

	req, err := c.generateSecretRequest(secretConfig)
	if err != nil {
		return nil, err
	}

	c.logger.Debug("Requesting secret", "secretConfig", secretConfig, "method", req.Method, "path", req.URL.Path, "params", req.Params)

	var resp *api.Response
	for i := 0; i < 2; i++ {
		resp, err = c.doInternal(ctx, req)
		if err != nil {
			var apiErr *api.ResponseError
			if !authed && i == 0 && errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
				// This may just mean our token has expired.
				// Retry and ensure the next request uses a new token.
				if _, authErr := c.auth(ctx, authMethod, req.ClientToken); authErr != nil {
					return nil, fmt.Errorf("failed to fetch secret: %w; and failed to reauthenticate: %w", err, authErr)
				}
				req.ClientToken = c.inner.Token()
				continue
			}
			return nil, fmt.Errorf("error requesting secret: %w", err)
		}

		break
	}

	if resp == nil {
		return nil, fmt.Errorf("failed to fetch secret object %s", secretConfig.ObjectName)
	}
	return api.ParseSecret(resp.Body)
}

// auth handles authenticating to Vault and setting the client's token.
// All requests from one client share the same token. This function serializes
// authentications so that when a token expires, multiple consumers asking it
// to reauthenticate at the same time only trigger one new authentication with
// Vault.
func (c *Client) auth(ctx context.Context, authMethod *auth.KubernetesJWTAuth, failedToken string) (authed bool, err error) {
	c.mtx.Lock()
	defer c.mtx.Unlock()

	// If we already have a token and it's not the failed one we've been told
	// to replace, then there's no work to do.
	if c.inner.Token() != "" && c.inner.Token() != failedToken {
		return false, nil
	}

	c.logger.Debug("performing vault login")
	path, body, err := authMethod.AuthRequest(ctx)
	if err != nil {
		return false, err
	}

	req := c.inner.NewRequest(http.MethodPost, path)
	if err := req.SetJSONBody(body); err != nil {
		return false, err
	}

	resp, err := c.doInternal(ctx, req)
	if err != nil {
		return false, fmt.Errorf("failed to login: %w", err)
	}
	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to parse login response: %w", err)
	}

	c.logger.Debug("vault login successful")
	c.inner.SetToken(secret.Auth.ClientToken)

	return true, nil
}

func (c *Client) doInternal(ctx context.Context, req *api.Request) (*api.Response, error) {
	resp, err := c.inner.RawRequestWithContext(ctx, req)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("received empty response from %q", req.URL.Path)
	}

	return resp, nil
}

func (c *Client) generateSecretRequest(secret config.Secret) (*api.Request, error) {
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
