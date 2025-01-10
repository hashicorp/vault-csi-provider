// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/auth"
	vaultclient "github.com/hashicorp/vault-csi-provider/internal/client"
	"github.com/hashicorp/vault-csi-provider/internal/clientcache"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	hmacgen "github.com/hashicorp/vault-csi-provider/internal/hmac"
	"github.com/hashicorp/vault/api"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// provider implements the secrets-store-csi-driver provider interface
// and communicates with the Vault API.
type provider struct {
	logger             hclog.Logger
	vaultResponseCache map[vaultResponseCacheKey]*api.Secret

	// Allows mocking Kubernetes API for tests.
	authMethod    auth.Auth
	hmacGenerator *hmacgen.HMACGenerator
	clientCache   *clientcache.ClientCache
}

func NewProvider(logger hclog.Logger, authMethod auth.Auth, hmacGenerator *hmacgen.HMACGenerator, clientCache *clientcache.ClientCache) *provider {
	p := &provider{
		logger:             logger,
		vaultResponseCache: make(map[vaultResponseCacheKey]*api.Secret),

		authMethod:    authMethod,
		hmacGenerator: hmacGenerator,
		clientCache:   clientCache,
	}

	return p
}

type vaultResponseCacheKey struct {
	secretPath string
	method     string
}

const (
	EncodingBase64 string = "base64"
	EncodingHex    string = "hex"
	EncodingUtf8   string = "utf-8"
)

func keyFromData(rootData map[string]interface{}, secretKey string) ([]byte, error) {
	// Automatically parse through to embedded .data.data map if it's present
	// and the correct type (e.g. for kv v2).
	var data map[string]interface{}
	d, ok := rootData["data"]
	if ok {
		data, ok = d.(map[string]interface{})
	}
	if !ok {
		data = rootData
	}

	// Fail early if a the key does not exist in the secret
	if _, ok := data[secretKey]; !ok {
		return nil, fmt.Errorf("key %q does not exist at the secret path", secretKey)
	}

	// Special-case the most common format of strings so the contents are
	// returned plainly without quotes that json.Marshal would add.
	if content, ok := data[secretKey].(string); ok {
		return []byte(content), nil
	}

	// Arbitrary data can be returned in the data field of an API secret struct.
	// It's already been Unmarshalled from the response, so in theory,
	// marshalling should never realistically fail, but don't log the error just
	// in case, as it could contain secret contents if it does somehow fail.
	if content, err := json.Marshal(data[secretKey]); err == nil {
		return content, nil
	}

	return nil, fmt.Errorf("failed to extract secret content as string or JSON from key %q", secretKey)
}

func decodeValue(data []byte, encoding string) ([]byte, error) {
	if len(encoding) == 0 || strings.EqualFold(encoding, EncodingUtf8) {
		return data, nil
	} else if strings.EqualFold(encoding, EncodingBase64) {
		return base64.StdEncoding.DecodeString(string(data))
	} else if strings.EqualFold(encoding, EncodingHex) {
		return hex.DecodeString(string(data))
	}

	return nil, fmt.Errorf("invalid encoding type. Should be utf-8, base64, or hex")
}

func (p *provider) getSecret(ctx context.Context, client *vaultclient.Client, secretConfig config.Secret) ([]byte, error) {
	var secret *api.Secret
	var cached bool
	key := vaultResponseCacheKey{secretPath: secretConfig.SecretPath, method: secretConfig.Method}
	if secret, cached = p.vaultResponseCache[key]; !cached {
		var err error
		secret, err = client.RequestSecret(ctx, p.authMethod, secretConfig)
		if err != nil {
			return nil, fmt.Errorf("couldn't read secret %q: %w", secretConfig.ObjectName, err)
		}
		if secret == nil || secret.Data == nil {
			return nil, fmt.Errorf("empty response from %q, warnings: %v", secretConfig.SecretPath, secret.Warnings)
		}

		for _, w := range secret.Warnings {
			p.logger.Warn("Warning in response from Vault API", "warning", w)
		}

		p.vaultResponseCache[key] = secret
	} else {
		p.logger.Debug("Secret fetched from cache", "secretConfig", secretConfig)
	}

	// If no secretKey specified, we return the whole response as a JSON object.
	if secretConfig.SecretKey == "" {
		content, err := json.Marshal(secret)
		if err != nil {
			return nil, err
		}

		return content, nil
	}

	value, err := keyFromData(secret.Data, secretConfig.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("{%s}: {%w}", secretConfig.SecretPath, err)
	}

	decodedVal, decodeErr := decodeValue(value, secretConfig.Encoding)
	if decodeErr != nil {
		return nil, fmt.Errorf("{%s}: {%w}", secretConfig.SecretPath, decodeErr)
	}

	return decodedVal, nil
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) HandleMountRequest(ctx context.Context, cfg config.Config, flagsConfig config.FlagsConfig) (*pb.MountResponse, error) {
	hmacKey, err := p.hmacGenerator.GetOrCreateHMACKey(ctx)
	if err != nil {
		p.logger.Warn("Error generating HMAC key. Mounted secrets will not be assigned a version", "error", err)
	}
	client, err := p.clientCache.GetOrCreateClient(cfg.Parameters, flagsConfig)
	if err != nil {
		return nil, err
	}

	var files []*pb.File
	var objectVersions []*pb.ObjectVersion
	for _, secret := range cfg.Parameters.Secrets {
		content, err := p.getSecret(ctx, client, secret)
		if err != nil {
			return nil, err
		}

		version, err := generateObjectVersion(secret, hmacKey, content)
		if err != nil {
			return nil, fmt.Errorf("failed to generate version for object name %q: %w", secret.ObjectName, err)
		}

		filePermission := int32(cfg.FilePermission)
		if secret.FilePermission != 0 {
			filePermission = int32(secret.FilePermission)
		}
		files = append(files, &pb.File{Path: secret.ObjectName, Mode: filePermission, Contents: content})
		objectVersions = append(objectVersions, version)
		p.logger.Info("secret added to mount response", "directory", cfg.TargetPath, "file", secret.ObjectName)
	}

	return &pb.MountResponse{
		Files:         files,
		ObjectVersion: objectVersions,
	}, nil
}

func generateObjectVersion(secret config.Secret, hmacKey []byte, content []byte) (*pb.ObjectVersion, error) {
	// If something went wrong with generating the HMAC key, we log the error and
	// treat generating the version as best-effort instead, as delivering the secret
	// is generally more critical to workloads than assigning a version for it.
	if hmacKey == nil {
		return &pb.ObjectVersion{
			Id:      secret.ObjectName,
			Version: "",
		}, nil
	}

	// We include the secret config in the hash input to avoid leaking information
	// about different secrets that could have the same content.
	hash := hmac.New(sha256.New, hmacKey)
	cfg, err := json.Marshal(secret)
	if err != nil {
		return nil, err
	}
	if _, err := hash.Write(cfg); err != nil {
		return nil, err
	}
	if _, err := hash.Write(content); err != nil {
		return nil, err
	}

	return &pb.ObjectVersion{
		Id:      secret.ObjectName,
		Version: base64.URLEncoding.EncodeToString(hash.Sum(nil)),
	}, nil
}
