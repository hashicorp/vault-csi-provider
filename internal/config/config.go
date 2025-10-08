// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"errors"
	"fmt"
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
	Endpoint   string
	Debug      bool
	LogLevel   string
	LogFormat  string
	Version    bool
	HealthAddr string

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
	VaultAddress       string
	VaultRoleName      string
	VaultAuthMountPath string
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

	var parameters Parameters
	parameters.VaultRoleName = params["roleName"]
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

		audience := "vault"
		if parameters.Audience != "" {
			audience = parameters.Audience
		}
		if token, ok := tokens[audience]; ok {
			parameters.PodInfo.ServiceAccountToken = token.Token
		}
	}

	return parameters, nil
}

func (c *Config) validate() error {
	// Some basic validation checks.
	if c.TargetPath == "" {
		return errors.New("missing target path field")
	}
	if c.Parameters.VaultRoleName == "" {
		return errors.New("missing 'roleName' in SecretProviderClass definition")
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
