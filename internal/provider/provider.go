package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	vaultclient "github.com/hashicorp/vault-csi-provider/internal/client"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

// provider implements the secrets-store-csi-driver provider interface
// and communicates with the Vault API.
type provider struct {
	logger hclog.Logger
	cache  map[cacheKey]*api.Secret

	// Allows mocking Kubernetes API for tests.
	k8sClient kubernetes.Interface
}

func NewProvider(logger hclog.Logger, k8sClient kubernetes.Interface) *provider {
	p := &provider{
		logger:    logger,
		cache:     make(map[cacheKey]*api.Secret),
		k8sClient: k8sClient,
	}

	return p
}

type cacheKey struct {
	secretPath string
	method     string
}

func (p *provider) createJWTToken(ctx context.Context, podInfo config.PodInfo, audience string) (string, error) {
	p.logger.Debug("creating service account token bound to pod",
		"namespace", podInfo.Namespace,
		"serviceAccountName", podInfo.ServiceAccountName,
		"podName", podInfo.Name,
		"podUID", podInfo.UID)

	ttl := int64((15 * time.Minute).Seconds())
	audiences := []string{}
	if audience != "" {
		audiences = []string{audience}
	}
	resp, err := p.k8sClient.CoreV1().ServiceAccounts(podInfo.Namespace).CreateToken(ctx, podInfo.ServiceAccountName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &ttl,
			Audiences:         audiences,
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

func (p *provider) login(ctx context.Context, client *api.Client, params config.Parameters) error {
	p.logger.Debug("performing vault login")

	jwt, err := p.createJWTToken(ctx, params.PodInfo, params.Audience)
	if err != nil {
		return err
	}

	req := client.NewRequest(http.MethodPost, "/v1/auth/"+params.VaultKubernetesMountPath+"/login")
	err = req.SetJSONBody(map[string]string{
		"role": params.VaultRoleName,
		"jwt":  jwt,
	})
	if err != nil {
		return err
	}
	secret, err := vaultclient.Do(ctx, client, req)
	if err != nil {
		return fmt.Errorf("failed to login: %w", err)
	}

	client.SetToken(secret.Auth.ClientToken)

	p.logger.Debug("vault login successful")
	return nil
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
	method := http.MethodGet
	if secret.Method != "" {
		method = secret.Method
	}

	req := client.NewRequest(method, secretPath)
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

func (p *provider) getSecret(ctx context.Context, client *api.Client, secretConfig config.Secret) ([]byte, error) {
	var secret *api.Secret
	var cached bool
	key := cacheKey{secretPath: secretConfig.SecretPath, method: secretConfig.Method}
	if secret, cached = p.cache[key]; !cached {
		req, err := generateRequest(client, secretConfig)
		if err != nil {
			return nil, err
		}
		p.logger.Debug("Requesting secret", "secretConfig", secretConfig, "method", req.Method, "path", req.URL.Path, "params", req.Params)

		if err != nil {
			return nil, fmt.Errorf("could not generate request: %v", err)
		}

		secret, err = vaultclient.Do(ctx, client, req)
		if err != nil {
			return nil, fmt.Errorf("couldn't read secret %q: %w", secretConfig.ObjectName, err)
		}
		if secret == nil || secret.Data == nil {
			return nil, fmt.Errorf("empty response from %q, warnings: %v", req.URL.Path, secret.Warnings)
		}

		for _, w := range secret.Warnings {
			p.logger.Warn("warning in response from Vault API", "warning", w)
		}

		p.cache[key] = secret
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

	return value, nil
}

// MountSecretsStoreObjectContent mounts content of the vault object to target path
func (p *provider) HandleMountRequest(ctx context.Context, cfg config.Config, flagsConfig config.FlagsConfig) (*pb.MountResponse, error) {
	client, err := vaultclient.New(cfg.Parameters, flagsConfig)
	if err != nil {
		return nil, err
	}

	// Set default k8s auth path if unset.
	if cfg.Parameters.VaultKubernetesMountPath == "" {
		cfg.Parameters.VaultKubernetesMountPath = flagsConfig.VaultMount
	}

	// Authenticate to vault using the jwt token
	err = p.login(ctx, client, cfg.Parameters)
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

		version, err := generateObjectVersion(secret, content)
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

func generateObjectVersion(secret config.Secret, content []byte) (*pb.ObjectVersion, error) {
	hash := sha256.New()
	// We include the secret config in the hash input to avoid leaking information
	// about different secrets that could have the same content.
	_, err := hash.Write([]byte(fmt.Sprintf("%v:%s", secret, content)))
	if err != nil {
		return nil, err
	}

	return &pb.ObjectVersion{
		Id:      secret.ObjectName,
		Version: base64.URLEncoding.EncodeToString(hash.Sum(nil)),
	}, nil
}
