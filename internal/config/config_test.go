package config

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

func TestParseParameters(t *testing.T) {
	parametersStr, err := ioutil.ReadFile("testdata/example-parameters-string.txt")
	require.NoError(t, err)
	actual, err := parseParameters(string(parametersStr))
	require.NoError(t, err)
	expected := Parameters{
		VaultRoleName: "example-role",
		VaultAddress:  "http://vault:8200",
		TLSConfig: TLSConfig{
			VaultSkipTLSVerify: true,
		},
		Secrets: []Secret{
			{"bar1", "v1/secret/foo1", ""},
			{"bar2", "v1/secret/foo2", ""},
		},
		VaultKubernetesMountPath:     defaultVaultKubernetesMountPath,
		KubernetesServiceAccountPath: defaultKubernetesServiceAccountPath,
	}
	assert.DeepEqual(t, expected, actual)
}

func TestParseConfig(t *testing.T) {
	const roleName = "example-role"
	const targetPath = "/some/path"
	defaultParams := Parameters{
		VaultAddress:                 defaultVaultAddress,
		VaultKubernetesMountPath:     defaultVaultKubernetesMountPath,
		KubernetesServiceAccountPath: defaultKubernetesServiceAccountPath,
	}
	for _, tc := range []struct {
		name       string
		targetPath string
		parameters map[string]string
		expected   Config
		warnings   int
	}{
		{
			name:       "defaults",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":           "example-role",
				"vaultSkipTLSVerify": "true",
				"objects":            "array:\n  - |\n    objectPath: \"v1/secret/foo1\"\n    objectName: \"bar1\"\n    objectVersion: \"\"",
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: func() Parameters {
					expected := defaultParams
					expected.VaultRoleName = roleName
					expected.TLSConfig.VaultSkipTLSVerify = true
					expected.Secrets = []Secret{
						{"bar1", "v1/secret/foo1", ""},
					}
					return expected
				}(),
			},
		},
		// {
		// 	name: "minimum for no errors",
		// 	targetPath: "/some/path",
		// 	parametersStr:     "{'roleName': 'example-role', 'vaultSkipTLSVerify': 'true'}",
		// 	cfg: Config{
		// 		TargetPath: targetPath,
		// 		Parameters: Parameters{
		// 			VaultRoleName: roleName,
		// 			TLSConfig: TLSConfig{
		// 				VaultSkipTLSVerify: true,
		// 			},
		// 			Secrets: []Secret{
		// 				{"foo", "bar", "baz"},
		// 			},
		// 		},
		// 	},
		// 	expected: Config{
		// 		TargetPath: "targetPath",
		// 		Parameters: func() Parameters {
		// 			expected := defaultParams
		// 			expected.Secrets = []Secret{
		// 				{"foo", "bar", "baz"},
		// 			}
		// 			expected.TLSConfig.VaultSkipTLSVerify = true
		// 			return expected
		// 		}(),
		// 	},
		// 	warnings: 0,
		// },
		{
			name:       "non-defaults can be set",
			targetPath: targetPath,
			parameters: map[string]string{
				"roleName":                     "example-role",
				"vaultSkipTLSVerify":           "true",
				"vaultAddress":                 "my-vault-address",
				"vaultKubernetesMountPath":     "my-mount-path",
				"KubernetesServiceAccountPath": "my-account-path",
				"objects":                      "array:\n  - |\n    objectPath: \"v1/secret/foo1\"\n    objectName: \"bar1\"\n    objectVersion: \"\"",
			},
			expected: Config{
				TargetPath:     targetPath,
				FilePermission: 420,
				Parameters: func() Parameters {
					expected := defaultParams
					expected.VaultRoleName = roleName
					expected.VaultAddress = "my-vault-address"
					expected.VaultKubernetesMountPath = "my-mount-path"
					expected.KubernetesServiceAccountPath = "my-account-path"
					expected.TLSConfig.VaultSkipTLSVerify = true
					expected.Secrets = []Secret{
						{"bar1", "v1/secret/foo1", ""},
					}
					return expected
				}(),
			},
		},
	} {
		// logBuffer := &bytes.Buffer{}
		// logger := hclog.New(&hclog.LoggerOptions{
		// 	Output:     logBuffer,
		// 	JSONFormat: true,
		// })
		parametersStr, err := json.Marshal(tc.parameters)
		require.NoError(t, err)
		cfg, err := Parse(string(parametersStr), tc.targetPath, "420")
		t.Logf("%+v", cfg)
		require.NoError(t, err, tc.name)
		assert.DeepEqual(t, tc.expected, cfg)
	}
}

// func TestNewProvider_Errors(t *testing.T) {
// 	for _, tc := range []struct {
// 		name string
// 		cfg  Config
// 	}{
// 		{
// 			name: "no roleName set",
// 			cfg: Config{
// 				Parameters: Parameters{},
// 			},
// 		},
// 		{
// 			name: "CA PEM configured and skip TLS set",
// 			cfg: Config{
// 				Parameters: Parameters{
// 					VaultRoleName: "foo",
// 					TLSConfig: TLSConfig{
// 						VaultSkipTLSVerify: true,
// 						VaultCAPEM:         "bar",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "CA cert path configured and skip TLS set",
// 			cfg: Config{
// 				Parameters: Parameters{
// 					VaultRoleName: "foo",
// 					TLSConfig: TLSConfig{
// 						VaultSkipTLSVerify: true,
// 						VaultCACertPath:    "bar",
// 					},
// 				},
// 			},
// 		},
// 		{
// 			name: "CA directory configured and skip TLS set",
// 			cfg: Config{
// 				Parameters: Parameters{
// 					VaultRoleName: "foo",
// 					TLSConfig: TLSConfig{
// 						VaultSkipTLSVerify: true,
// 						VaultCADirectory:   "bar",
// 					},
// 				},
// 			},
// 		},
// 	} {
// 		_, err := NewProvider(hclog.NewNullLogger(), tc.params)
// 		assert.Error(t, err)
// 	}
// }
