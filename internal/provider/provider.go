package provider

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/go-hclog"
	vaultclient "github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/client"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/config"
	"github.com/hashicorp/vault/api"
)

func readJWTToken(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read jwt token: %w", err)
	}

	return string(bytes.TrimSpace(data)), nil
}

// provider implements the secrets-store-csi-driver provider interface
// and communicates with the Vault API.
type provider struct {
	logger hclog.Logger
}

func NewProvider(logger hclog.Logger) *provider {
	p := &provider{
		logger: logger,
	}

	return p
}

func (p *provider) getMountInfo(_ context.Context, client *api.Client, mountName string) (string, string, error) {
	p.logger.Debug("vault: checking mount info", "mountName", mountName)
	// TODO: Don't ignore ctx
	resp, err := client.Logical().Read("sys/mounts")
	if err != nil {
		return "", "", fmt.Errorf("failed to query mounts endpoint: %w", err)
	}

	p.logger.Debug("v1/sys/mounts response received", "response", *resp)

	mount := resp.Data[mountName+"/"].(map[string]interface{})
	typ := mount["type"].(string)
	options := mount["options"].(map[string]interface{})

	// TODO: Defend against panics here.
	return typ, options["version"].(string), nil
}

func generateSecretEndpoint(secretMountType string, secretMountVersion string, secretPrefix string, secretSuffix string, secretVersion string) (string, error) {
	addr := ""
	errMessage := fmt.Errorf("Only mount types KV/1 and KV/2 are supported")
	switch secretMountType {
	case "kv":
		switch secretMountVersion {
		case "1":
			addr = secretPrefix + "/" + secretSuffix
		case "2":
			addr = secretPrefix + "/data/" + secretSuffix // + "?version=" + secretVersion
		default:
			return "", errMessage
		}
	default:
		return "", errMessage
	}
	return addr, nil
}

func (p *provider) login(_ context.Context, client *api.Client, vaultKubernetesMountPath, roleName, jwt string) (string, error) {
	p.logger.Debug("vault: performing vault login...")

	// TODO: Don't ignore ctx
	resp, err := client.Logical().Write("auth/"+vaultKubernetesMountPath+"/login", map[string]interface{}{
		"role": roleName,
		"jwt":  jwt,
	})
	if err != nil {
		return "", fmt.Errorf("couldn't login: %w", err)
	}

	client.SetToken(resp.Auth.ClientToken)

	return resp.Auth.ClientToken, nil
}

func (p *provider) getSecret(ctx context.Context, client *api.Client, secret config.Secret) (content string, err error) {
	p.logger.Debug("vault: getting secrets from vault...")

	secretVersion := secret.ObjectVersion
	if secretVersion == "" {
		secretVersion = "0"
	}

	s := regexp.MustCompile("/+").Split(secret.ObjectPath, 3)
	if len(s) < 3 {
		return "", fmt.Errorf("unable to parse secret path %q", secret.ObjectPath)
	}
	secretPrefix := s[1]
	secretSuffix := s[2]

	secretMountType, secretMountVersion, err := p.getMountInfo(ctx, client, secretPrefix)
	if err != nil {
		return "", err
	}

	endpoint, err := generateSecretEndpoint(secretMountType, secretMountVersion, secretPrefix, secretSuffix, secretVersion)
	if err != nil {
		return "", err
	}

	p.logger.Debug("vault: Requesting valid secret mounted", "endpoint", endpoint)

	// TODO: Don't ignore ctx
	resp, err := client.Logical().Read(endpoint)
	if err != nil {
		return "", fmt.Errorf("couldn't get secret: %w", err)
	}
	if resp == nil {
		return "", fmt.Errorf("no secret found at %s", endpoint)
	}

	p.logger.Debug("Received response from secret read", "response", *resp)
	switch secretMountType {
	case "kv":
		switch secretMountVersion {
		case "1":
			return resp.Data[secret.ObjectName].(string), nil

		case "2":
			data := resp.Data["data"].(map[string]interface{})
			return data[secret.ObjectName].(string), nil
		}
	}

	return "", fmt.Errorf("failed to get secret value")
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) MountSecretsStoreObjectContent(ctx context.Context, cfg config.Config) (map[string]string, error) {
	versions := make(map[string]string)
	for _, secret := range cfg.Parameters.Secrets {
		content, err := p.getSecretContent(ctx, cfg.Parameters, secret)
		if err != nil {
			return nil, err
		}
		versions[fmt.Sprintf("%s:%s:%s", secret.ObjectName, secret.ObjectPath, secret.ObjectVersion)] = secret.ObjectVersion
		err = writeSecret(p.logger, cfg.TargetPath, secret.ObjectName, content, cfg.FilePermission)
		if err != nil {
			return nil, err
		}
	}

	return versions, nil
}

func writeSecret(logger hclog.Logger, directory string, file string, content string, permission os.FileMode) error {
	objectContent := []byte(content)
	if err := validateFilePath(file); err != nil {
		return err
	}
	if filepath.Base(file) != file {
		err := os.MkdirAll(filepath.Join(directory, filepath.Dir(file)), 0755)
		if err != nil {
			return err
		}
	}
	if err := ioutil.WriteFile(filepath.Join(directory, file), objectContent, permission); err != nil {
		return fmt.Errorf("secrets-store csi driver failed to write %s at %s: %w", file, directory, err)
	}
	logger.Info("secrets-store csi driver wrote secret", "directory", directory, "file", file)

	return nil
}

func validateFilePath(path string) error {
	segments := strings.Split(strings.ReplaceAll(path, `\`, "/"), "/")
	for _, segment := range segments {
		if segment == ".." {
			return fmt.Errorf("ObjectName %q invalid, must not contain any .. segments", path)
		}
	}

	return nil
}

// getSecretContent get content and version of the vault object
func (p *provider) getSecretContent(ctx context.Context, params config.Parameters, secret config.Secret) (content string, err error) {
	// Read the jwt token from disk
	jwt, err := readJWTToken(params.KubernetesServiceAccountPath)
	if err != nil {
		return "", err
	}

	config := api.DefaultConfig()
	if params.VaultAddress != "" {
		config.Address = params.VaultAddress
	}
	if params.TLSConfig.CertificatesConfigured() {
		config.HttpClient, err = vaultclient.CreateHTTPClient(params.TLSConfig)
		if err != nil {
			return "", err
		}
	} else if params.TLSConfig.VaultSkipTLSVerify {
		err = config.ConfigureTLS(&api.TLSConfig{
			Insecure: true,
		})
		if err != nil {
			return "", err
		}
	}
	client, err := api.NewClient(config)

	// Authenticate to vault using the jwt token
	_, err = p.login(ctx, client, params.VaultKubernetesMountPath, params.VaultRoleName, jwt)
	if err != nil {
		return "", err
	}

	// Get Secret
	value, err := p.getSecret(ctx, client, secret)
	if err != nil {
		return "", err
	}

	return value, nil
}
