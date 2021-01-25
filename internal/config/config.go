package config

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

const (
	defaultVaultAddress                 string = "https://127.0.0.1:8200"
	defaultKubernetesServiceAccountPath string = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultVaultKubernetesMountPath     string = "kubernetes"
)

// Config represents all of the provider's configurable behaviour from the MountRequest proto message:
// * `parameters` from the SecretProviderClass (serialised into the `Attributes` field in the proto).
// * Plus the rest of the proto fields we consume.
// See sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1/service.pb.go
type Config struct {
	Parameters
	TargetPath     string
	FilePermission os.FileMode
}

// Parameters stores the parameters specified in the SecretProviderClass.
// Top-level values that aren't strings are not directly deserialisable because
// they are defined as literal string types:
// https://github.com/kubernetes-sigs/secrets-store-csi-driver/blob/0ba9810d41cc2dc336c68251d45ebac19f2e7f28/apis/v1alpha1/secretproviderclass_types.go#L59
//
// So we just deserialise by hand to avoid complexity and two passes.
type Parameters struct {
	VaultRoleName                string
	VaultAddress                 string
	VaultKubernetesMountPath     string
	KubernetesServiceAccountPath string
	TLSConfig                    TLSConfig
	Secrets                      []Secret
}

type TLSConfig struct {
	VaultCAPEM         string
	VaultCACertPath    string
	VaultCADirectory   string
	VaultTLSServerName string
	VaultSkipTLSVerify bool
}

type Secret struct {
	ObjectName    string `yaml:"objectName"`
	ObjectPath    string `yaml:"objectPath"`
	ObjectVersion string `yaml:"objectVersion"`
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

	err = json.Unmarshal([]byte(permissionStr), &config.FilePermission)
	if err != nil {
		return Config{}, err
	}

	err = config.Validate()
	if err != nil {
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

	var parameters Parameters
	parameters.VaultRoleName = params["roleName"]
	parameters.VaultAddress = params["vaultAddress"]
	parameters.TLSConfig.VaultCAPEM = params["vaultCAPem"]
	parameters.TLSConfig.VaultCACertPath = params["vaultCACertPath"]
	parameters.TLSConfig.VaultCADirectory = params["vaultCADirectory"]
	parameters.TLSConfig.VaultTLSServerName = params["vaultTLSServerName"]
	parameters.VaultKubernetesMountPath = params["vaultKubernetesMountPath"]
	parameters.KubernetesServiceAccountPath = params["KubernetesServiceAccountPath"]
	if skipTLS, ok := params["vaultSkipTLSVerify"]; ok {
		value, err := strconv.ParseBool(skipTLS)
		if err == nil {
			parameters.TLSConfig.VaultSkipTLSVerify = value
		} else {
			return Parameters{}, err
		}
	}

	secretsYaml := params["objects"]
	// TODO: There is an unnecessary map under objects, instead of just directly storing an array there.
	// Deserialisation can be simplified a fair bit if we remove it.
	secretsMap := map[string][]string{}
	err = yaml.Unmarshal([]byte(secretsYaml), &secretsMap)
	if err != nil {
		return Parameters{}, err
	}
	secrets, ok := secretsMap["array"]
	if !ok {
		return Parameters{}, errors.New("no secrets to read configured")
	}
	for _, s := range secrets {
		var secret Secret
		err = yaml.Unmarshal([]byte(s), &secret)
		if err != nil {
			return Parameters{}, err
		}
		parameters.Secrets = append(parameters.Secrets, secret)
	}

	// Set default values.
	if parameters.VaultAddress == "" {
		parameters.VaultAddress = defaultVaultAddress
	}

	if parameters.VaultKubernetesMountPath == "" {
		parameters.VaultKubernetesMountPath = defaultVaultKubernetesMountPath
	}
	if parameters.KubernetesServiceAccountPath == "" {
		parameters.KubernetesServiceAccountPath = defaultKubernetesServiceAccountPath
	}

	return parameters, nil
}

func (c *Config) Validate() error {
	// Some basic validation checks.
	if c.TargetPath == "" {
		return errors.New("missing target path field")
	}
	if c.Parameters.VaultRoleName == "" {
		return errors.Errorf("missing 'roleName' in SecretProviderClass definition")
	}
	certificatesConfigured := c.Parameters.TLSConfig.VaultCAPEM != "" ||
		c.Parameters.TLSConfig.VaultCACertPath != "" ||
		c.Parameters.TLSConfig.VaultCADirectory != ""
	if c.Parameters.TLSConfig.VaultSkipTLSVerify && certificatesConfigured == true {
		return errors.New("both vaultSkipTLSVerify and TLS configuration are set")
	}
	if !c.Parameters.TLSConfig.VaultSkipTLSVerify && certificatesConfigured == false {
		return errors.New("no TLS configuration and vaultSkipTLSVerify is false, will use system CA certificates")
	}
	if len(c.Parameters.Secrets) == 0 {
		return errors.New("no secrets configured - the provider will not read any secret material")
	}

	return nil
}
