package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	vaultclient "github.com/hashicorp/vault-csi-provider/internal/client"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// provider implements the secrets-store-csi-driver provider interface
// and communicates with the Vault API.
type provider struct {
	logger hclog.Logger
	cache  map[cacheKey]*api.Secret
}

func NewProvider(logger hclog.Logger) *provider {
	p := &provider{
		logger: logger,
		cache:  make(map[cacheKey]*api.Secret),
	}

	return p
}

type cacheKey struct {
	secretPath string
	method     string
}

func (p *provider) createJWTToken(ctx context.Context, podInfo config.PodInfo) (string, error) {
	p.logger.Debug("creating service account token bound to pod",
		"namespace", podInfo.Namespace,
		"serviceAccountName", podInfo.ServiceAccountName,
		"podName", podInfo.Name,
		"podUID", podInfo.UID)

	config, err := rest.InClusterConfig()
	if err != nil {
		return "", err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	ttl := int64((15 * time.Minute).Seconds())
	resp, err := clientset.CoreV1().ServiceAccounts(podInfo.Namespace).CreateToken(ctx, podInfo.ServiceAccountName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &ttl,
			// TODO: Support audiences as a configurable.
			//Audiences:         []string{},
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       "Pod",
				APIVersion: "v1",
				Name:       podInfo.Name,
				UID:        podInfo.UID,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create a service account token for requesting pod %v: %w", podInfo, err)
	}

	p.logger.Debug("service account token creation successful")
	return resp.Status.Token, nil
}

func (p *provider) login(ctx context.Context, client *api.Client, params config.Parameters) (string, error) {
	p.logger.Debug("performing vault login")

	jwt, err := p.createJWTToken(ctx, params.PodInfo)
	if err != nil {
		return "", err
	}

	req := client.NewRequest("POST", "/v1/auth/"+params.VaultKubernetesMountPath+"/login")
	err = req.SetJSONBody(map[string]string{
		"role": params.VaultRoleName,
		"jwt":  jwt,
	})
	if err != nil {
		return "", err
	}
	secret, err := vaultclient.Do(ctx, client, req)
	if err != nil {
		return "", fmt.Errorf("failed to login: %w", err)
	}

	client.SetToken(secret.Auth.ClientToken)

	p.logger.Debug("vault login successful")
	return secret.Auth.ClientToken, nil
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

func generateRequest(client *api.Client, secret config.Secret) (*api.Request, error) {
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
	method := "GET"
	if secret.Method != "" {
		method = secret.Method
	}

	req := client.NewRequest(method, secretPath)
	if queryParams != nil {
		req.Params = queryParams
	}
	if secret.SecretArgs != nil {
		req.SetJSONBody(secret.SecretArgs)
	}

	return req, nil
}

func keyFromData(rootData map[string]interface{}, secretKey string) (string, error) {
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

	content, ok := data[secretKey].(string)
	if !ok {
		return "", fmt.Errorf("failed to get secret content %q as string", secretKey)
	}

	return content, nil
}

func (p *provider) getSecret(ctx context.Context, client *api.Client, secretConfig config.Secret) (string, error) {
	var secret *api.Secret
	var cached bool
	key := cacheKey{secretPath: secretConfig.SecretPath, method: secretConfig.Method}
	if secret, cached = p.cache[key]; !cached {
		req, err := generateRequest(client, secretConfig)
		p.logger.Debug("Requesting secret", "secretConfig", secretConfig, "method", req.Method, "path", req.URL.Path, "params", req.Params)

		if err != nil {
			return "", fmt.Errorf("could not generate request: %v", err)
		}

		secret, err = vaultclient.Do(ctx, client, req)
		if err != nil {
			return "", fmt.Errorf("couldn't read secret %q: %w", secretConfig.ObjectName, err)
		}
		if secret == nil || secret.Data == nil {
			return "", fmt.Errorf("empty response from %q, warnings: %v", req.URL.Path, secret.Warnings)
		}

		p.cache[key] = secret
	} else {
		p.logger.Debug("Secret fetched from cache", "secretConfig", secretConfig)
	}

	// If no secretKey specified, we return the whole response as a JSON object.
	if secretConfig.SecretKey == "" {
		bytes, err := json.Marshal(secret)
		if err != nil {
			return "", err
		}

		return string(bytes), nil
	}

	return keyFromData(secret.Data, secretConfig.SecretKey)
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) MountSecretsStoreObjectContent(ctx context.Context, cfg config.Config, writeSecrets bool) (*pb.MountResponse, error) {
	versions := make(map[string]string)

	client, err := vaultclient.New(cfg.Parameters.VaultAddress, cfg.Parameters.VaultTLSConfig)
	if err != nil {
		return nil, err
	}

	// Set Vault namespace if configured
	if cfg.VaultNamespace != "" {
		p.logger.Debug("setting Vault namespace", "namespace", cfg.VaultNamespace)
		client.SetNamespace(cfg.VaultNamespace)
	}

	// Authenticate to vault using the jwt token
	_, err = p.login(ctx, client, cfg.Parameters)
	if err != nil {
		return nil, err
	}

	var files []*pb.File
	for _, secret := range cfg.Parameters.Secrets {
		content, err := p.getSecret(ctx, client, secret)
		if err != nil {
			return nil, err
		}
		versions[fmt.Sprintf("%s:%s:%s", secret.ObjectName, secret.SecretPath, secret.Method)] = "0"

		if writeSecrets {
			err = writeSecret(p.logger, cfg.TargetPath, secret.ObjectName, content, cfg.FilePermission)
			if err != nil {
				return nil, err
			}
		} else {
			files = append(files, &pb.File{Path: secret.ObjectName, Mode: int32(cfg.FilePermission), Contents: []byte(content)})
			p.logger.Info("secret sent to the secrets-store csi driver", "directory", cfg.TargetPath, "file", secret.ObjectName)
		}
	}

	var ov []*pb.ObjectVersion
	for k, v := range versions {
		ov = append(ov, &pb.ObjectVersion{Id: k, Version: v})
	}

	return &pb.MountResponse{
		ObjectVersion: ov,
		Files:         files,
	}, nil
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
