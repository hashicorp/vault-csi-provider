package config

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	objects      = "-\n  secretPath: \"v1/secret/foo1\"\n  objectName: \"bar1\""
	certsSPCYaml = `apiVersion: secrets-store.csi.x-k8s.io/v1alpha1
kind: SecretProviderClass
metadata:
  name: vault-foo
spec:
  provider: vault
  parameters:
    objects: |
      - objectName: "test-certs"
        secretPath: "pki/issue/example-dot-com"
        secretKey: "certificate"
        secretArgs:
          common_name: "test.example.com"
          ip_sans: "127.0.0.1"
          exclude_cn_from_sans: true
        method: "PUT"
      - objectName: "internal-certs"
        secretPath: "pki/issue/example-dot-com"
        secretArgs:
          common_name: "internal.example.com"
        method: "PUT"
`
)

func TestParseParametersFromYaml(t *testing.T) {
	// Test starts with a minimal simulation of the processing the driver does
	// with each SecretProviderClass yaml.
	var secretProviderClass struct {
		Spec struct {
			Parameters map[string]string `yaml:"parameters"`
		} `yaml:"spec"`
	}
	err := yaml.Unmarshal([]byte(certsSPCYaml), &secretProviderClass)
	require.NoError(t, err)
	paramsBytes, err := json.Marshal(secretProviderClass.Spec.Parameters)

	// This is now the form the provider receives the data in.
	params, err := parseParameters(hclog.NewNullLogger(), string(paramsBytes))
	require.NoError(t, err)

	require.True(t, reflect.DeepEqual(Parameters{
		VaultAddress:             defaultVaultAddress,
		VaultKubernetesMountPath: defaultVaultKubernetesMountPath,
		Secrets: []Secret{
			{
				ObjectName: "test-certs",
				SecretPath: "pki/issue/example-dot-com",
				SecretKey:  "certificate",
				SecretArgs: map[string]interface{}{
					"common_name":          "test.example.com",
					"ip_sans":              "127.0.0.1",
					"exclude_cn_from_sans": true,
				},
				Method: "PUT",
			},
			{
				ObjectName: "internal-certs",
				SecretPath: "pki/issue/example-dot-com",
				SecretArgs: map[string]interface{}{
					"common_name": "internal.example.com",
				},
				Method: "PUT",
			},
		},
	}, params))
}

func TestParseParameters(t *testing.T) {
	// This file's contents are copied directly from a driver mount request.
	parametersStr, err := ioutil.ReadFile(filepath.Join("testdata", "example-parameters-string.txt"))
	require.NoError(t, err)
	actual, err := parseParameters(hclog.NewNullLogger(), string(parametersStr))
	require.NoError(t, err)
	expected := Parameters{
		VaultRoleName: "example-role",
		VaultAddress:  "http://vault:8200",
		VaultTLSConfig: TLSConfig{
			SkipVerify: true,
		},
		Secrets: []Secret{
			{"bar1", "v1/secret/foo1", "", "GET", nil},
			{"bar2", "v1/secret/foo2", "", "", nil},
		},
		VaultKubernetesMountPath: defaultVaultKubernetesMountPath,
		PodInfo: PodInfo{
			Name:               "nginx-secrets-store-inline",
			UID:                "9aeb260f-d64a-426c-9872-95b6bab37e00",
			Namespace:          "test",
			ServiceAccountName: "default",
		},
	}
	require.True(t, reflect.DeepEqual(expected, actual))
}

func TestParseConfig(t *testing.T) {
	const roleName = "example-role"
	const targetPath = "/some/path"
	defaultParams := Parameters{
		VaultAddress:             defaultVaultAddress,
		VaultKubernetesMountPath: defaultVaultKubernetesMountPath,
		VaultNamespace:           "",
	}
	for _, tc := range []struct {
		name       string
		targetPath string
		parameters map[string]string
		expected   Config
	}{
		{
			name:       "defaults",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":           "example-role",
				"vaultSkipTLSVerify": "true",
				"objects":            objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: func() Parameters {
					expected := defaultParams
					expected.VaultRoleName = roleName
					expected.VaultTLSConfig.SkipVerify = true
					expected.Secrets = []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil},
					}
					return expected
				}(),
			},
		},
		{
			name:       "non-defaults can be set",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":                     "example-role",
				"vaultSkipTLSVerify":           "true",
				"vaultAddress":                 "my-vault-address",
				"vaultNamespace":               "my-vault-namespace",
				"vaultKubernetesMountPath":     "my-mount-path",
				"KubernetesServiceAccountPath": "my-account-path",
				"objects":                      objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: func() Parameters {
					expected := defaultParams
					expected.VaultRoleName = roleName
					expected.VaultAddress = "my-vault-address"
					expected.VaultNamespace = "my-vault-namespace"
					expected.VaultKubernetesMountPath = "my-mount-path"
					expected.VaultTLSConfig.SkipVerify = true
					expected.Secrets = []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil},
					}
					return expected
				}(),
			},
		},
	} {
		parametersStr, err := json.Marshal(tc.parameters)
		require.NoError(t, err)
		cfg, err := Parse(hclog.NewNullLogger(), string(parametersStr), tc.targetPath, "420")
		require.NoError(t, err, tc.name)
		require.True(t, reflect.DeepEqual(tc.expected, cfg))
	}
}

func TestParseConfig_Errors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		targetPath string
		parameters map[string]string
	}{
		{
			name: "no roleName",
			parameters: map[string]string{
				"vaultSkipTLSVerify": "true",
				"objects":            objects,
			},
		},
		{
			name: "no secrets configured",
			parameters: map[string]string{
				"roleName":           "example-role",
				"vaultSkipTLSVerify": "true",
				"objects":            "",
			},
		},
	} {
		parametersStr, err := json.Marshal(tc.parameters)
		require.NoError(t, err)
		_, err = Parse(hclog.NewNullLogger(), string(parametersStr), "/some/path", "420")
		require.Error(t, err, tc.name)
	}
}

func TestValidateConfig(t *testing.T) {
	minimumValid := Config{
		TargetPath: "a",
		Parameters: Parameters{
			VaultAddress:  defaultVaultAddress,
			VaultRoleName: "b",
			Secrets:       []Secret{{}},
		},
	}
	for _, tc := range []struct {
		name     string
		cfg      Config
		cfgValid bool
	}{
		{
			name:     "minimum valid",
			cfgValid: true,
			cfg:      minimumValid,
		},
		{
			name: "No role name",
			cfg: func() Config {
				cfg := minimumValid
				cfg.VaultRoleName = ""
				return cfg
			}(),
		},
		{
			name: "No target path",
			cfg: func() Config {
				cfg := minimumValid
				cfg.TargetPath = ""
				return cfg
			}(),
		},
		{
			name: "No secrets configured",
			cfg: func() Config {
				cfg := minimumValid
				cfg.Secrets = []Secret{}
				return cfg
			}(),
		},
	} {
		err := tc.cfg.validate()
		if tc.cfgValid {
			require.NoError(t, err, tc.name)
		} else {
			require.Error(t, err, tc.name)
		}
	}
}
