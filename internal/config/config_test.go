package config

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	objects      = "-\n  secretPath: \"v1/secret/foo1\"\n  objectName: \"bar1\""
	certsSPCYaml = `apiVersion: secrets-store.csi.x-k8s.io/v1
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
	require.NoError(t, err)

	// This is now the form the provider receives the data in.
	params, err := parseParameters(string(paramsBytes))
	require.NoError(t, err)

	require.Equal(t, Parameters{
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
	}, params)
}

func TestParseParameters(t *testing.T) {
	// This file's contents are copied directly from a driver mount request.
	parametersStr, err := ioutil.ReadFile(filepath.Join("testdata", "example-parameters-string.txt"))
	require.NoError(t, err)
	actual, err := parseParameters(string(parametersStr))
	require.NoError(t, err)
	expected := Parameters{
		VaultRoleName: "example-role",
		VaultAddress:  "http://vault:8200",
		VaultTLSConfig: api.TLSConfig{
			Insecure: true,
		},
		Secrets: []Secret{
			{"bar1", "v1/secret/foo1", "", http.MethodGet, nil},
			{"bar2", "v1/secret/foo2", "", "", nil},
		},
		PodInfo: PodInfo{
			Name:               "nginx-secrets-store-inline",
			UID:                "9aeb260f-d64a-426c-9872-95b6bab37e00",
			Namespace:          "test",
			ServiceAccountName: "default",
		},
	}
	require.Equal(t, expected, actual)
}

func TestParseConfig(t *testing.T) {
	const roleName = "example-role"
	const targetPath = "/some/path"
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
					expected := Parameters{}
					expected.VaultRoleName = roleName
					expected.VaultTLSConfig.Insecure = true
					expected.Secrets = []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil},
					}
					return expected
				}(),
			},
		},
		{
			name:       "set all options",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":                               "example-role",
				"vaultSkipTLSVerify":                     "true",
				"vaultAddress":                           "my-vault-address",
				"vaultNamespace":                         "my-vault-namespace",
				"vaultKubernetesMountPath":               "my-mount-path",
				"vaultCACertPath":                        "my-ca-cert-path",
				"vaultCADirectory":                       "my-ca-directory",
				"vaultTLSServerName":                     "mytls-server-name",
				"vaultTLSClientCertPath":                 "my-tls-client-cert-path",
				"vaultTLSClientKeyPath":                  "my-tls-client-key-path",
				"csi.storage.k8s.io/pod.name":            "my-pod-name",
				"csi.storage.k8s.io/pod.uid":             "my-pod-uid",
				"csi.storage.k8s.io/pod.namespace":       "my-pod-namespace",
				"csi.storage.k8s.io/serviceAccount.name": "my-pod-sa-name",
				"objects":                                objects,
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					VaultRoleName:            roleName,
					VaultAddress:             "my-vault-address",
					VaultNamespace:           "my-vault-namespace",
					VaultKubernetesMountPath: "my-mount-path",
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil},
					},
					VaultTLSConfig: api.TLSConfig{
						CACert:        "my-ca-cert-path",
						CAPath:        "my-ca-directory",
						ClientCert:    "my-tls-client-cert-path",
						ClientKey:     "my-tls-client-key-path",
						TLSServerName: "mytls-server-name",
						Insecure:      true,
					},
					PodInfo: PodInfo{
						"my-pod-name",
						"my-pod-uid",
						"my-pod-namespace",
						"my-pod-sa-name",
					},
				},
			},
		},
	} {
		parametersStr, err := json.Marshal(tc.parameters)
		require.NoError(t, err)
		cfg, err := Parse(string(parametersStr), tc.targetPath, "420")
		require.NoError(t, err, tc.name)
		require.Equal(t, tc.expected, cfg)
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
		_, err = Parse(string(parametersStr), "/some/path", "420")
		require.Error(t, err, tc.name)
	}
}

func TestValidateConfig(t *testing.T) {
	minimumValid := Config{
		TargetPath: "a",
		Parameters: Parameters{
			VaultAddress:  "http://127.0.0.1:8200",
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
				cfg.Parameters.VaultRoleName = ""
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
				cfg.Parameters.Secrets = []Secret{}
				return cfg
			}(),
		},
		{
			name: "Duplicate objectName",
			cfg: func() Config {
				cfg := minimumValid
				cfg.Parameters.Secrets = []Secret{
					{ObjectName: "foo", SecretPath: "path/one"},
					{ObjectName: "foo", SecretPath: "path/two"},
				}
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
