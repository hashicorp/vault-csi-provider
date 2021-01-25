package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hashicorp/go-hclog"
	vaultclient "github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/client"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/config"
	"github.com/pkg/errors"
)

func readJWTToken(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", errors.Wrap(err, "failed to read jwt token")
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

func (p *provider) getMountInfo(ctx context.Context, client *http.Client, vaultAddress, mountName, token string) (string, string, error) {
	p.logger.Debug(fmt.Sprintf("vault: checking mount info for %q", mountName))

	addr := vaultAddress + "/v1/sys/mounts"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return "", "", errors.Wrapf(err, "couldn't generate request")
	}
	// Set vault token.
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("X-Vault-Request", "true")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", errors.Wrapf(err, "couldn't get sys mounts")
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var b bytes.Buffer
		_, err := io.Copy(&b, resp.Body)
		if err != nil {
			return "", "", fmt.Errorf("failed to copy reponse body to byte buffer")
		}
		return "", "", fmt.Errorf("failed to get successful response reading mount info: %#v, %s",
			resp, b.String())
	}

	var mount struct {
		Data map[string]struct {
			Type    string            `json:"type"`
			Options map[string]string `json:"options"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&mount); err != nil {
		return "", "", err
	}

	return mount.Data[mountName+"/"].Type, mount.Data[mountName+"/"].Options["version"], nil
}

func generateSecretEndpoint(vaultAddress string, secretMountType string, secretMountVersion string, secretPrefix string, secretSuffix string, secretVersion string) (string, error) {
	addr := ""
	errMessage := fmt.Errorf("Only mount types KV/1 and KV/2 are supported")
	switch secretMountType {
	case "kv":
		switch secretMountVersion {
		case "1":
			addr = vaultAddress + "/v1/" + secretPrefix + "/" + secretSuffix
		case "2":
			addr = vaultAddress + "/v1/" + secretPrefix + "/data/" + secretSuffix + "?version=" + secretVersion
		default:
			return "", errMessage
		}
	default:
		return "", errMessage
	}
	return addr, nil
}

func (p *provider) login(ctx context.Context, client *http.Client, vaultAddress, vaultKubernetesMountPath, roleName, jwt string) (string, error) {
	p.logger.Debug(fmt.Sprintf("vault: performing vault login....."))

	addr := vaultAddress + "/v1/auth/" + vaultKubernetesMountPath + "/login"
	body := fmt.Sprintf(`{"role": "%s", "jwt": "%s"}`, roleName, jwt)

	p.logger.Debug(fmt.Sprintf("vault: vault address: %s\n", addr))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, strings.NewReader(body))
	if err != nil {
		return "", errors.Wrapf(err, "couldn't generate request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, "couldn't login")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var b bytes.Buffer
		_, err := io.Copy(&b, resp.Body)
		if err != nil {
			return "", fmt.Errorf("failed to copy reponse body to byte buffer")
		}
		return "", fmt.Errorf("failed to get successful response logging in: %#v, %s",
			resp, b.String())
	}

	var s struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return "", errors.Wrapf(err, "failed to read body")
	}

	return s.Auth.ClientToken, nil
}

func (p *provider) getSecret(ctx context.Context, client *http.Client, vaultAddress string, token string, secret config.Secret) (content string, version int, err error) {
	p.logger.Debug(fmt.Sprintf("vault: getting secrets from vault....."))

	secretVersion := secret.ObjectVersion
	if secretVersion == "" {
		secretVersion = "0"
	}

	s := regexp.MustCompile("/+").Split(secret.ObjectPath, 3)
	if len(s) < 3 {
		return "", 0, fmt.Errorf("unable to parse secret path %q", secret.ObjectPath)
	}
	secretPrefix := s[1]
	secretSuffix := s[2]

	secretMountType, secretMountVersion, err := p.getMountInfo(ctx, client, vaultAddress, secretPrefix, token)
	if err != nil {
		return "", 0, err
	}

	addr, err := generateSecretEndpoint(vaultAddress, secretMountType, secretMountVersion, secretPrefix, secretSuffix, secretVersion)
	if err != nil {
		return "", 0, err
	}

	p.logger.Debug(fmt.Sprintf("vault: Requesting valid secret mounted at %q", addr))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	// Set vault token.
	req.Header.Set("X-Vault-Token", token)
	if err != nil {
		return "", 0, errors.Wrapf(err, "couldn't generate request")
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, errors.Wrapf(err, "couldn't get secret")
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var b bytes.Buffer
		_, err := io.Copy(&b, resp.Body)
		if err != nil {
			return "", 0, fmt.Errorf("failed to copy reponse body to byte buffer")
		}
		return "", 0, fmt.Errorf("failed to get successful response reading secret: %#v, %s",
			resp, b.String())
	}

	switch secretMountType {
	case "kv":
		switch secretMountVersion {
		case "1":
			var d struct {
				Data map[string]string `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
				return "", 0, errors.Wrapf(err, "failed to read body")
			}
			return d.Data[secret.ObjectName], 0, nil

		case "2":
			var d struct {
				Data struct {
					Data     map[string]string `json:"data"`
					Metadata struct {
						Version int `json:"version"`
					} `json:"metadata"`
				} `json:"data"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
				return "", 0, errors.Wrapf(err, "failed to read body")
			}
			return d.Data.Data[secret.ObjectName], d.Data.Metadata.Version, nil
		}
	}

	return "", 0, fmt.Errorf("failed to get secret value")
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) MountSecretsStoreObjectContent(ctx context.Context, cfg config.Config) (map[string]int, error) {
	versions := make(map[string]int)
	for _, secret := range cfg.Parameters.Secrets {
		content, version, err := p.getSecretContent(ctx, cfg.Parameters, secret)
		if err != nil {
			return nil, err
		}
		versions[fmt.Sprintf("%s:%s:%s", secret.ObjectName, secret.ObjectPath, secret.ObjectVersion)] = version
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
		return errors.Wrapf(err, "secrets-store csi driver failed to write %s at %s", file, directory)
	}
	logger.Info(fmt.Sprintf("secrets-store csi driver wrote %s at %s", file, directory))

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
func (p *provider) getSecretContent(ctx context.Context, params config.Parameters, secret config.Secret) (content string, version int, err error) {
	// Read the jwt token from disk
	jwt, err := readJWTToken(params.KubernetesServiceAccountPath)
	if err != nil {
		return "", 0, err
	}

	client, err := vaultclient.CreateHTTPClient(params.TLSConfig)
	if err != nil {
		return "", 0, err
	}

	// Authenticate to vault using the jwt token
	token, err := p.login(ctx, client, params.VaultAddress, params.VaultKubernetesMountPath, params.VaultRoleName, jwt)
	if err != nil {
		return "", 0, err
	}

	// Get Secret
	value, version, err := p.getSecret(ctx, client, params.VaultAddress, token, secret)
	if err != nil {
		return "", 0, err
	}

	return value, version, nil
}
