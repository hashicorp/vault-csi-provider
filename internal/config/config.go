// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/types"
)

// Config represents all of the provider's configurable behaviour from the SecretProviderClass,
// transmitted in the MountRequest proto message:
// * Parameters from the `Attributes` field.
// * Plus the rest of the proto fields we consume.
// See sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1/service.pb.go
type Config struct {
	Parameters     Parameters
	TargetPath     string
	FilePermission os.FileMode
}

type FlagsConfig struct {
	Endpoint            string
	Debug               bool
	LogLevel            string
	Version             bool
	VersionOutputFormat string
	HealthAddr          string

	HMACSecretName string

	CacheSize int

	VaultAddr      string
	VaultMount     string
	VaultNamespace string

	TLSCACertPath  string
	TLSCADirectory string
	TLSServerName  string
	TLSClientCert  string
	TLSClientKey   string
	TLSSkipVerify  bool
}

func (fc FlagsConfig) TLSConfig() api.TLSConfig {
	return api.TLSConfig{
		CACert:        fc.TLSCACertPath,
		CAPath:        fc.TLSCADirectory,
		ClientCert:    fc.TLSClientCert,
		ClientKey:     fc.TLSClientKey,
		TLSServerName: fc.TLSServerName,
		Insecure:      fc.TLSSkipVerify,
	}
}

const (
	AuthTypeKubernetes = "kubernetes"
	AuthTypeAWS        = "aws"

	// DefaultAWSAudience is the default audience for service account tokens
	// exchanged with AWS STS, matching the EKS pod identity webhook default.
	DefaultAWSAudience = "sts.amazonaws.com"

	defaultKubernetesAudience = "vault"
)

// Auth is the optional `auth` parameter of a SecretProviderClass, which
// selects and configures the Vault auth method used to log in.
type Auth struct {
	Type      string  `yaml:"type,omitempty"`
	MountPath string  `yaml:"mountPath,omitempty"`
	Role      string  `yaml:"role,omitempty"`
	AWS       AWSAuth `yaml:"aws,omitempty"`
}

// AWSAuth holds settings that only apply to the "aws" auth type.
type AWSAuth struct {
	Region                 string `yaml:"region,omitempty"`
	IAMServerIDHeaderValue string `yaml:"iamServerIDHeaderValue,omitempty"`
	// STSEndpoint overrides the STS endpoint used for AssumeRoleWithWebIdentity
	// and for the signed GetCallerIdentity login request, for example a FIPS or
	// VPC interface endpoint. It must use https, and Region must be set to the
	// endpoint's region.
	STSEndpoint string `yaml:"stsEndpoint,omitempty"`
}

// Parameters stores the parameters specified in a mount request's `Attributes` field.
// It consists of the parameters section from the SecretProviderClass being mounted
// and pod metadata provided by the driver.
//
// Top-level values that aren't strings are not directly deserialisable because
// they are defined as literal string types:
// https://github.com/kubernetes-sigs/secrets-store-csi-driver/blob/0ba9810d41cc2dc336c68251d45ebac19f2e7f28/apis/v1alpha1/secretproviderclass_types.go#L59
//
// So we just deserialise by hand to avoid complexity and two passes.
type Parameters struct {
	VaultAddress string
	// VaultRoleName is `auth.role` if set, otherwise `roleName`.
	VaultRoleName string
	// VaultAuthMountPath is `auth.mountPath`, `vaultAuthMountPath` or
	// `vaultKubernetesMountPath`, whichever is set. Empty means use the
	// auth method's default.
	VaultAuthMountPath string
	VaultAuthType      string
	VaultAuthAWS       AWSAuth
	VaultNamespace     string
	VaultTLSConfig     api.TLSConfig
	Secrets            []Secret
	PodInfo            PodInfo
	Audience           string
}

type PodInfo struct {
	Name                string
	UID                 types.UID
	Namespace           string
	ServiceAccountName  string
	ServiceAccountToken string
}

type Secret struct {
	ObjectName     string                 `yaml:"objectName,omitempty"`
	SecretPath     string                 `yaml:"secretPath,omitempty"`
	SecretKey      string                 `yaml:"secretKey,omitempty"`
	Method         string                 `yaml:"method,omitempty"`
	SecretArgs     map[string]interface{} `yaml:"secretArgs,omitempty"`
	FilePermission os.FileMode            `yaml:"filePermission,omitempty"`
	Encoding       string                 `yaml:"encoding,omitempty"`
}

func Parse(parametersStr, targetPath, permissionStr string) (Config, error) {
	config := Config{
		TargetPath: targetPath,
	}

	var err error
	config.Parameters, err = parseParameters(parametersStr)
	if err != nil {
		return Config{}, err
	}

	if err := json.Unmarshal([]byte(permissionStr), &config.FilePermission); err != nil {
		return Config{}, err
	}

	if err := config.validate(); err != nil {
		return Config{}, err
	}

	return config, nil
}

func parseParameters(parametersStr string) (Parameters, error) {
	var params map[string]string
	err := json.Unmarshal([]byte(parametersStr), &params)
	if err != nil {
		return Parameters{}, err
	}

	authParams, err := parseAuth(params["auth"])
	if err != nil {
		return Parameters{}, err
	}

	var parameters Parameters
	parameters.VaultAuthType = authParams.Type
	parameters.VaultAuthAWS = authParams.AWS
	parameters.VaultRoleName = params["roleName"]
	if authParams.Role != "" {
		parameters.VaultRoleName = authParams.Role
	}
	parameters.VaultAddress = params["vaultAddress"]
	parameters.VaultNamespace = params["vaultNamespace"]
	parameters.VaultTLSConfig.CACert = params["vaultCACertPath"]
	parameters.VaultTLSConfig.CAPath = params["vaultCADirectory"]
	parameters.VaultTLSConfig.TLSServerName = params["vaultTLSServerName"]
	parameters.VaultTLSConfig.ClientCert = params["vaultTLSClientCertPath"]
	parameters.VaultTLSConfig.ClientKey = params["vaultTLSClientKeyPath"]
	k8sMountPath, k8sSet := params["vaultKubernetesMountPath"]
	authMountPath, authSet := params["vaultAuthMountPath"]
	switch {
	case k8sSet && authSet:
		return Parameters{}, fmt.Errorf("cannot set both vaultKubernetesMountPath and vaultAuthMountPath")
	case authParams.MountPath != "" && (k8sSet || authSet):
		return Parameters{}, fmt.Errorf("cannot set 'mountPath' in the 'auth' parameter together with vaultKubernetesMountPath or vaultAuthMountPath")
	case k8sSet && authParams.Type != AuthTypeKubernetes:
		return Parameters{}, fmt.Errorf("vaultKubernetesMountPath can only be used with the %q auth type, use 'mountPath' in the 'auth' parameter instead", AuthTypeKubernetes)
	case authParams.MountPath != "":
		parameters.VaultAuthMountPath = authParams.MountPath
	case k8sSet:
		parameters.VaultAuthMountPath = k8sMountPath
	case authSet:
		parameters.VaultAuthMountPath = authMountPath
	}
	parameters.PodInfo.Name = params["csi.storage.k8s.io/pod.name"]
	parameters.PodInfo.UID = types.UID(params["csi.storage.k8s.io/pod.uid"])
	parameters.PodInfo.Namespace = params["csi.storage.k8s.io/pod.namespace"]
	parameters.PodInfo.ServiceAccountName = params["csi.storage.k8s.io/serviceAccount.name"]
	parameters.Audience = params["audience"]
	if skipTLS, ok := params["vaultSkipTLSVerify"]; ok {
		value, err := strconv.ParseBool(skipTLS)
		if err == nil {
			parameters.VaultTLSConfig.Insecure = value
		} else {
			return Parameters{}, err
		}
	}

	secretsYaml := params["objects"]
	err = yaml.Unmarshal([]byte(secretsYaml), &parameters.Secrets)
	if err != nil {
		return Parameters{}, err
	}

	tokensJSON := params["csi.storage.k8s.io/serviceAccount.tokens"]
	if tokensJSON != "" {
		// The csi.storage.k8s.io/serviceAccount.tokens field is a JSON object
		// marshalled into a string. The object keys are audience name (string)
		// and the values are embedded objects with "token" and
		// "expirationTimestamp" fields for the corresponding audience.
		var tokens map[string]struct {
			Token               string `json:"token"`
			ExpirationTimestamp string `json:"expirationTimestamp"`
		}
		if err := json.Unmarshal([]byte(tokensJSON), &tokens); err != nil {
			return Parameters{}, fmt.Errorf("failed to unmarshal service account tokens: %w", err)
		}

		audience := defaultKubernetesAudience
		if parameters.VaultAuthType == AuthTypeAWS {
			audience = DefaultAWSAudience
		}
		if parameters.Audience != "" {
			audience = parameters.Audience
		}
		if token, ok := tokens[audience]; ok {
			parameters.PodInfo.ServiceAccountToken = token.Token
		}
	}

	return parameters, nil
}

// parseAuth parses the optional `auth` parameter, which must be a single YAML
// document. Unknown fields and additional documents are rejected so that
// typos or partial configuration don't silently fall back to defaults.
func parseAuth(authYAML string) (Auth, error) {
	var auth Auth
	if strings.TrimSpace(authYAML) != "" {
		decoder := yaml.NewDecoder(strings.NewReader(authYAML))
		decoder.KnownFields(true)
		if err := decoder.Decode(&auth); err != nil && !errors.Is(err, io.EOF) {
			return Auth{}, fmt.Errorf("failed to parse 'auth' parameter: %w", err)
		}
		var extraDocument yaml.Node
		if err := decoder.Decode(&extraDocument); !errors.Is(err, io.EOF) {
			if err != nil {
				return Auth{}, fmt.Errorf("failed to parse 'auth' parameter: %w", err)
			}
			return Auth{}, errors.New("'auth' parameter must contain a single YAML document")
		}
	}

	switch auth.Type {
	case "":
		auth.Type = AuthTypeKubernetes
	case AuthTypeKubernetes, AuthTypeAWS:
	default:
		return Auth{}, fmt.Errorf("unsupported auth type %q in 'auth' parameter, must be one of %q or %q", auth.Type, AuthTypeKubernetes, AuthTypeAWS)
	}

	if auth.Type != AuthTypeAWS && auth.AWS != (AWSAuth{}) {
		return Auth{}, fmt.Errorf("'aws' settings in the 'auth' parameter can only be used with the %q auth type", AuthTypeAWS)
	}

	if auth.AWS.STSEndpoint != "" {
		if err := validateSTSEndpoint(auth.AWS.STSEndpoint); err != nil {
			return Auth{}, fmt.Errorf("invalid 'aws.stsEndpoint' in 'auth' parameter: %w", err)
		}
		// The login request is signed for the region, so it must match the
		// endpoint. Defaulting to us-east-1 for a regional or FIPS endpoint
		// would only surface as an STS signature error at login.
		if auth.AWS.Region == "" {
			return Auth{}, errors.New("'aws.region' in 'auth' parameter must be set when 'aws.stsEndpoint' is set")
		}
	}

	return auth, nil
}

// validateSTSEndpoint checks that endpoint is an absolute https URL without a
// path, query, fragment, or user info, so that it can be used both as the STS
// client base endpoint and as the URL of the signed login request. Plain http
// is rejected because the endpoint receives the service account token and
// returns temporary AWS credentials.
func validateSTSEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%q must use the https scheme", endpoint)
	case u.Host == "":
		return fmt.Errorf("%q must include a host", endpoint)
	case u.User != nil:
		return fmt.Errorf("%q must not include user info", endpoint)
	case u.Path != "" && u.Path != "/":
		return fmt.Errorf("%q must not include a path", endpoint)
	case u.RawQuery != "" || u.ForceQuery:
		return fmt.Errorf("%q must not include a query", endpoint)
	case u.Fragment != "":
		return fmt.Errorf("%q must not include a fragment", endpoint)
	}
	return nil
}

func (c *Config) validate() error {
	// Some basic validation checks.
	if c.TargetPath == "" {
		return errors.New("missing target path field")
	}
	// A Vault role is required for every auth type, including aws. Vault's AWS
	// auth method would otherwise infer the role from the IAM principal's
	// friendly name (the IAM role name for IRSA). Requiring it keeps the Vault
	// role an explicit choice, consistent with Kubernetes auth.
	if c.Parameters.VaultRoleName == "" {
		return errors.New("missing 'roleName' or 'auth.role' in SecretProviderClass definition")
	}
	if len(c.Parameters.Secrets) == 0 {
		return errors.New("no secrets configured - the provider will not read any secret material")
	}

	objectNames := map[string]struct{}{}
	conflicts := []string{}
	for _, secret := range c.Parameters.Secrets {
		if _, exists := objectNames[secret.ObjectName]; exists {
			conflicts = append(conflicts, secret.ObjectName)
		}

		objectNames[secret.ObjectName] = struct{}{}
	}

	if len(conflicts) > 0 {
		return fmt.Errorf("each `objectName` within a SecretProviderClass must be unique, "+
			"but the following keys were duplicated: %s", strings.Join(conflicts, ", "))
	}

	return nil
}
