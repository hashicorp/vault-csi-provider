// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	objects      = "-\n  secretPath: \"v1/secret/foo1\"\n  objectName: \"bar1\"\n  filePermission: 0600"
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
		VaultAuthType: AuthTypeKubernetes,
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
	parametersStr, err := os.ReadFile(filepath.Join("testdata", "example-parameters-string.txt"))
	require.NoError(t, err)
	actual, err := parseParameters(string(parametersStr))
	require.NoError(t, err)
	expected := Parameters{
		VaultRoleName: "example-role",
		VaultAddress:  "http://vault:8200",
		VaultAuthType: AuthTypeKubernetes,
		VaultTLSConfig: api.TLSConfig{
			Insecure: true,
		},
		Secrets: []Secret{
			{"bar1", "v1/secret/foo1", "", http.MethodGet, nil, 0, ""},
			{"bar2", "v1/secret/foo2", "", "", nil, 0, ""},
		},
		PodInfo: PodInfo{
			Name:               "nginx-secrets-store-inline",
			UID:                "9aeb260f-d64a-426c-9872-95b6bab37e00",
			Namespace:          "test",
			ServiceAccountName: "default",
		},
		Audience: "testaudience",
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
					expected.VaultAuthType = AuthTypeKubernetes
					expected.VaultTLSConfig.Insecure = true
					expected.Secrets = []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
					}
					return expected
				}(),
			},
		},
		{
			name:       "set all options",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":                                 "example-role",
				"vaultSkipTLSVerify":                       "true",
				"vaultAddress":                             "my-vault-address",
				"vaultNamespace":                           "my-vault-namespace",
				"vaultKubernetesMountPath":                 "my-mount-path",
				"vaultCACertPath":                          "my-ca-cert-path",
				"vaultCADirectory":                         "my-ca-directory",
				"vaultTLSServerName":                       "mytls-server-name",
				"vaultTLSClientCertPath":                   "my-tls-client-cert-path",
				"vaultTLSClientKeyPath":                    "my-tls-client-key-path",
				"csi.storage.k8s.io/pod.name":              "my-pod-name",
				"csi.storage.k8s.io/pod.uid":               "my-pod-uid",
				"csi.storage.k8s.io/pod.namespace":         "my-pod-namespace",
				"csi.storage.k8s.io/serviceAccount.name":   "my-pod-sa-name",
				"csi.storage.k8s.io/serviceAccount.tokens": `{"my-aud": {"token": "my-pod-sa-token", "expirationTimestamp": "bar"}, "other-aud": {"token": "unused-token"}}`,
				"objects":  objects,
				"audience": "my-aud",
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: Parameters{
					VaultRoleName:      roleName,
					VaultAddress:       "my-vault-address",
					VaultNamespace:     "my-vault-namespace",
					VaultAuthMountPath: "my-mount-path",
					VaultAuthType:      AuthTypeKubernetes,
					Secrets: []Secret{
						{"bar1", "v1/secret/foo1", "", "", nil, 0o600, ""},
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
						"my-pod-sa-token",
					},
					Audience: "my-aud",
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

func TestParseParameters_Auth(t *testing.T) {
	for name, tc := range map[string]struct {
		parameters map[string]string
		expected   Parameters
	}{
		"no auth block defaults to kubernetes": {
			parameters: map[string]string{
				"roleName":                 "k8s-role",
				"vaultKubernetesMountPath": "custom-k8s",
			},
			expected: Parameters{
				VaultRoleName:      "k8s-role",
				VaultAuthType:      AuthTypeKubernetes,
				VaultAuthMountPath: "custom-k8s",
			},
		},
		"empty auth block defaults to kubernetes": {
			parameters: map[string]string{
				"roleName": "k8s-role",
				"auth":     "# no settings\n",
			},
			expected: Parameters{
				VaultRoleName: "k8s-role",
				VaultAuthType: AuthTypeKubernetes,
			},
		},
		"single auth document with explicit start and end markers": {
			parameters: map[string]string{
				"roleName": "aws-role",
				"auth":     "---\ntype: aws\n...\n",
			},
			expected: Parameters{
				VaultRoleName: "aws-role",
				VaultAuthType: AuthTypeAWS,
			},
		},
		"kubernetes auth block with mountPath and role": {
			parameters: map[string]string{
				"auth": "type: kubernetes\nmountPath: custom-k8s\nrole: k8s-role",
			},
			expected: Parameters{
				VaultRoleName:      "k8s-role",
				VaultAuthType:      AuthTypeKubernetes,
				VaultAuthMountPath: "custom-k8s",
			},
		},
		"aws inherits roleName": {
			parameters: map[string]string{
				"roleName": "shared-role",
				"auth":     "type: aws",
			},
			expected: Parameters{
				VaultRoleName: "shared-role",
				VaultAuthType: AuthTypeAWS,
			},
		},
		"auth.role overrides roleName": {
			parameters: map[string]string{
				"roleName": "k8s-role",
				"auth":     "type: aws\nrole: aws-role",
			},
			expected: Parameters{
				VaultRoleName: "aws-role",
				VaultAuthType: AuthTypeAWS,
			},
		},
		"aws with all settings": {
			parameters: map[string]string{
				"auth": `type: aws
mountPath: my-aws
role: aws-role
aws:
  region: us-west-2
  iamServerIDHeaderValue: vault.example.com
`,
			},
			expected: Parameters{
				VaultRoleName:      "aws-role",
				VaultAuthType:      AuthTypeAWS,
				VaultAuthMountPath: "my-aws",
				VaultAuthAWS: AWSAuth{
					Region:                 "us-west-2",
					IAMServerIDHeaderValue: "vault.example.com",
				},
			},
		},
		"aws with legacy vaultAuthMountPath": {
			parameters: map[string]string{
				"roleName":           "aws-role",
				"auth":               "type: aws",
				"vaultAuthMountPath": "my-aws",
			},
			expected: Parameters{
				VaultRoleName:      "aws-role",
				VaultAuthType:      AuthTypeAWS,
				VaultAuthMountPath: "my-aws",
			},
		},
		"aws uses sts.amazonaws.com token from mount request by default": {
			parameters: map[string]string{
				"roleName": "aws-role",
				"auth":     "type: aws",
				"csi.storage.k8s.io/serviceAccount.tokens": `{"vault": {"token": "vault-token"}, "sts.amazonaws.com": {"token": "sts-token"}}`,
			},
			expected: Parameters{
				VaultRoleName: "aws-role",
				VaultAuthType: AuthTypeAWS,
				PodInfo:       PodInfo{ServiceAccountToken: "sts-token"},
			},
		},
		"aws uses custom audience token from mount request": {
			parameters: map[string]string{
				"roleName": "aws-role",
				"auth":     "type: aws",
				"audience": "custom",
				"csi.storage.k8s.io/serviceAccount.tokens": `{"custom": {"token": "custom-token"}, "sts.amazonaws.com": {"token": "sts-token"}}`,
			},
			expected: Parameters{
				VaultRoleName: "aws-role",
				VaultAuthType: AuthTypeAWS,
				Audience:      "custom",
				PodInfo:       PodInfo{ServiceAccountToken: "custom-token"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			parametersStr, err := json.Marshal(tc.parameters)
			require.NoError(t, err)
			actual, err := parseParameters(string(parametersStr))
			require.NoError(t, err)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestParseConfig_Errors(t *testing.T) {
	for name, tc := range map[string]struct {
		name        string
		targetPath  string
		parameters  map[string]string
		expectedErr string
	}{
		"no roleName": {
			parameters: map[string]string{
				"vaultSkipTLSVerify": "true",
				"objects":            objects,
			},
		},
		"no secrets configured": {
			parameters: map[string]string{
				"roleName":           "example-role",
				"vaultSkipTLSVerify": "true",
				"objects":            "",
			},
		},
		"both vaultAuthMountPath and vaultKubernetesMountPath specified": {
			parameters: map[string]string{
				"roleName":                 "example-role",
				"vaultSkipTLSVerify":       "true",
				"vaultAuthMountPath":       "foo",
				"vaultKubernetesMountPath": "bar",
				"objects":                  objects,
			},
		},
		"no roleName or auth.role": {
			expectedErr: "missing 'roleName' or 'auth.role'",
			parameters: map[string]string{
				"auth":    "type: aws",
				"objects": objects,
			},
		},
		"auth.mountPath and vaultAuthMountPath specified": {
			expectedErr: "cannot set 'mountPath' in the 'auth' parameter",
			parameters: map[string]string{
				"roleName":           "example-role",
				"auth":               "mountPath: foo",
				"vaultAuthMountPath": "bar",
				"objects":            objects,
			},
		},
		"auth.mountPath and vaultKubernetesMountPath specified": {
			expectedErr: "cannot set 'mountPath' in the 'auth' parameter",
			parameters: map[string]string{
				"roleName":                 "example-role",
				"auth":                     "mountPath: foo",
				"vaultKubernetesMountPath": "bar",
				"objects":                  objects,
			},
		},
		"vaultKubernetesMountPath with aws auth type": {
			expectedErr: "vaultKubernetesMountPath can only be used with the \"kubernetes\" auth type",
			parameters: map[string]string{
				"roleName":                 "example-role",
				"auth":                     "type: aws",
				"vaultKubernetesMountPath": "kubernetes",
				"objects":                  objects,
			},
		},
		"unsupported auth type": {
			expectedErr: "unsupported auth type \"gcp\"",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "type: gcp",
				"objects":  objects,
			},
		},
		"unknown field in auth": {
			expectedErr: "field mouthPath not found",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "type: kubernetes\nmouthPath: foo",
				"objects":  objects,
			},
		},
		"unknown field in auth.aws": {
			expectedErr: "field awsIAMRole not found",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "type: aws\naws:\n  awsIAMRole: foo",
				"objects":  objects,
			},
		},
		"aws settings with kubernetes auth type": {
			expectedErr: "'aws' settings in the 'auth' parameter can only be used with the \"aws\" auth type",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "aws:\n  region: us-west-2",
				"objects":  objects,
			},
		},
		"invalid auth yaml": {
			expectedErr: "failed to parse 'auth' parameter",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "type: [aws",
				"objects":  objects,
			},
		},
		"auth with empty first document and settings in a second": {
			expectedErr: "'auth' parameter must contain a single YAML document",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "---\n---\ntype: aws",
				"objects":  objects,
			},
		},
		"auth with conflicting settings in a second document": {
			expectedErr: "'auth' parameter must contain a single YAML document",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "type: kubernetes\n---\ntype: aws",
				"objects":  objects,
			},
		},
		"auth with an unknown field in a second document": {
			expectedErr: "'auth' parameter must contain a single YAML document",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "type: aws\n---\nmouthPath: aws",
				"objects":  objects,
			},
		},
		"auth with invalid yaml in a second document": {
			expectedErr: "failed to parse 'auth' parameter",
			parameters: map[string]string{
				"roleName": "example-role",
				"auth":     "type: aws\n---\ntype: [aws",
				"objects":  objects,
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			parametersStr, err := json.Marshal(tc.parameters)
			require.NoError(t, err)
			_, err = Parse(string(parametersStr), "/some/path", "420")
			require.Error(t, err, tc.name)
			if tc.expectedErr != "" {
				require.ErrorContains(t, err, tc.expectedErr)
			}
		})
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
