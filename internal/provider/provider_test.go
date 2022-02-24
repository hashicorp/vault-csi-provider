package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

func TestEnsureV1Prefix(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected string
	}{
		{"no prefix", "secret/foo", "/v1/secret/foo"},
		{"leading slash", "/secret/foo", "/v1/secret/foo"},
		{"leading v1", "v1/secret/foo", "/v1/secret/foo"},
		{"leading /v1/", "/v1/secret/foo", "/v1/secret/foo"},
		// These will mostly be invalid paths, but testing reasonable behaviour.
		{"empty string", "", "/v1/"},
		{"just /v1/", "/v1/", "/v1/"},
		{"leading 1", "1/secret/foo", "/v1/1/secret/foo"},
		{"2* /v1/", "/v1/v1/", "/v1/v1/"},
		{"v2", "/v2/secret/foo", "/v1/v2/secret/foo"},
	} {
		assert.Equal(t, tc.expected, ensureV1Prefix(tc.input), tc.name)
	}
}

func TestGenerateRequest(t *testing.T) {
	type expected struct {
		method string
		path   string
		params string
		body   string
	}
	client, err := api.NewClient(nil)
	require.NoError(t, err)
	for _, tc := range []struct {
		name     string
		secret   config.Secret
		expected expected
	}{
		{
			name: "base case",
			secret: config.Secret{
				SecretPath: "secret/foo",
			},
			expected: expected{http.MethodGet, "/v1/secret/foo", "", ""},
		},
		{
			name: "zero-length query string",
			secret: config.Secret{
				SecretPath: "secret/foo?",
			},
			expected: expected{http.MethodGet, "/v1/secret/foo", "", ""},
		},
		{
			name: "query string",
			secret: config.Secret{
				SecretPath: "secret/foo?bar=true&baz=maybe&zap=0",
			},
			expected: expected{http.MethodGet, "/v1/secret/foo", "bar=true&baz=maybe&zap=0", ""},
		},
		{
			name: "method specified",
			secret: config.Secret{
				SecretPath: "secret/foo",
				Method:     "PUT",
			},
			expected: expected{"PUT", "/v1/secret/foo", "", ""},
		},
		{
			name: "body specified",
			secret: config.Secret{
				SecretPath: "secret/foo",
				Method:     http.MethodPost,
				SecretArgs: map[string]interface{}{
					"bar": true,
					"baz": 10,
					"zap": "a string",
				},
			},
			expected: expected{http.MethodPost, "/v1/secret/foo", "", `{"bar":true,"baz":10,"zap":"a string"}`},
		},
	} {
		req, err := generateRequest(client, tc.secret)
		require.NoError(t, err, tc.name)
		assert.Equal(t, req.Method, tc.expected.method, tc.name)
		assert.Equal(t, req.URL.Path, tc.expected.path, tc.name)
		assert.Equal(t, req.Params.Encode(), tc.expected.params, tc.name)
		assert.Equal(t, tc.expected.body, string(req.BodyBytes), tc.name)
	}
}

func TestKeyFromData(t *testing.T) {
	data := map[string]interface{}{
		"foo": "bar",
		"baz": "zap",
	}
	dataWithDataString := map[string]interface{}{
		"foo":  "bar",
		"baz":  "zap",
		"data": "hello",
	}
	dataWithDataField := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": "bar",
			"baz": "zap",
		},
	}
	dataWithNonStringValue := map[string]interface{}{
		"foo": 10,
		"baz": "zap",
	}
	dataWithJSON := map[string]interface{}{
		"data": map[string]interface{}{
			"foo": map[string]interface{}{
				"bar": "hop",
				"baz": "zap",
				"cheeses": map[string]interface{}{
					"brie":    9,
					"cheddar": "8",
				},
			},
			"baz": "zap",
		},
	}
	dataWithArray := map[string]interface{}{
		"values": []interface{}{6, "stilton", true},
	}
	for _, tc := range []struct {
		name     string
		key      string
		data     map[string]interface{}
		expected []byte
	}{
		{
			name:     "base case",
			key:      "foo",
			data:     data,
			expected: []byte("bar"),
		},
		{
			name:     "string data",
			key:      "data",
			data:     dataWithDataString,
			expected: []byte("hello"),
		},
		{
			name:     "kv v2 embedded data field",
			key:      "foo",
			data:     dataWithDataField,
			expected: []byte("bar"),
		},
		{
			name:     "kv v2 embedded data field",
			key:      "foo",
			data:     dataWithNonStringValue,
			expected: []byte("10"),
		},
		{
			name:     "json data",
			key:      "foo",
			data:     dataWithJSON,
			expected: []byte(`{"bar":"hop","baz":"zap","cheeses":{"brie":9,"cheddar":"8"}}`),
		},
		{
			name:     "json array",
			key:      "values",
			data:     dataWithArray,
			expected: []byte(`[6,"stilton",true]`),
		},
	} {
		content, err := keyFromData(tc.data, tc.key)
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.expected, content)
	}
}

func TestHandleMountRequest(t *testing.T) {
	// SETUP
	mockVaultServer := httptest.NewServer(http.HandlerFunc(mockVaultHandler()))
	defer mockVaultServer.Close()

	k8sClient := fake.NewSimpleClientset(
		&corev1.ServiceAccount{},
		&authenticationv1.TokenRequest{},
	)

	spcConfig := config.Config{
		TargetPath:     "some/unused/path",
		FilePermission: 0,
		Parameters: config.Parameters{
			VaultRoleName: "my-vault-role",
			Secrets: []config.Secret{
				{
					ObjectName: "object-one",
					SecretPath: "path/one",
					SecretKey:  "the-key",
					Method:     "",
					SecretArgs: nil,
				},
				{
					ObjectName: "object-two",
					SecretPath: "path/two",
					SecretKey:  "",
					Method:     "",
					SecretArgs: nil,
				},
			},
		},
	}
	flagsConfig := config.FlagsConfig{
		VaultAddr: mockVaultServer.URL,
	}

	// TEST
	expectedFiles := []*pb.File{
		{
			Path:     "object-one",
			Mode:     0,
			Contents: []byte("secret v1 from: /v1/path/one"),
		},
		{
			Path:     "object-two",
			Mode:     0,
			Contents: []byte(`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":{"the-key":"secret v1 from: /v1/path/two"},"warnings":null}`),
		},
	}
	expectedVersions := []*pb.ObjectVersion{
		{
			Id:      "object-one",
			Version: "GTA4Q4qmllcXGP5c-2zGpd2nDKA_koge-LpAK3QS6x4=",
		},
		{
			Id:      "object-two",
			Version: "01yGq-JMHV5hkbN-VeaV0sqmhXSigHwkSa1-xiLByLQ=",
		},
	}

	// While we hit the cache, the secret contents and versions should remain the same.
	provider := NewProvider(hclog.Default(), k8sClient)
	for i := 0; i < 3; i++ {
		resp, err := provider.HandleMountRequest(context.Background(), spcConfig, flagsConfig)
		require.NoError(t, err)

		assert.Equal(t, (*v1alpha1.Error)(nil), resp.Error)
		assert.Equal(t, expectedFiles, resp.Files)
		assert.Equal(t, expectedVersions, resp.ObjectVersion)
	}

	// Mounting again with a fresh provider will update the contents of the secrets, which should update the version.
	resp, err := NewProvider(hclog.Default(), k8sClient).HandleMountRequest(context.Background(), spcConfig, flagsConfig)
	require.NoError(t, err)

	assert.Equal(t, (*v1alpha1.Error)(nil), resp.Error)
	expectedFiles[0].Contents = []byte("secret v2 from: /v1/path/one")
	expectedFiles[1].Contents = []byte(`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":{"the-key":"secret v2 from: /v1/path/two"},"warnings":null}`)
	expectedVersions[0].Version = "pEVsjkL1Sa3izLS3yl5jUz3nVdgWbWi4kX5sH-WqYvQ="
	expectedVersions[1].Version = "YhyNECvv1klLks1FxzC690cgBncilNwc5G-UlwIRNDY="
	assert.Equal(t, expectedFiles, resp.Files)
	assert.Equal(t, expectedVersions, resp.ObjectVersion)
}

func mockVaultHandler() func(w http.ResponseWriter, req *http.Request) {
	getsPerPath := map[string]int{}

	return func(w http.ResponseWriter, req *http.Request) {
		switch req.Method {
		case http.MethodPost:
			// Assume all POSTs are login requests and return a token.
			body, err := json.Marshal(&api.Secret{
				Auth: &api.SecretAuth{
					ClientToken: "my-vault-client-token",
				},
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, err = w.Write(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		case http.MethodGet:
			// Assume all GETs are secret reads and return a derivative of the request path.
			path := req.URL.Path
			getsPerPath[path]++
			body, err := json.Marshal(&api.Secret{
				Data: map[string]interface{}{
					"the-key": fmt.Sprintf("secret v%d from: %s", getsPerPath[path], path),
				},
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, err = w.Write(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
}

// To regenerate, configure kubectl for a cluster (e.g. `kind create cluster`), and run:
// kubectl proxy &
// curl --silent http://127.0.0.1:8001/api/v1/namespaces/default/serviceaccounts/default/token \
//   -H "Content-Type: application/json" \
//   -X POST \
//   -d '{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest"}'
// kill %%
const tokenRequestResponse = `{
  "kind": "TokenRequest",
  "apiVersion": "authentication.k8s.io/v1",
  "metadata": {
    "creationTimestamp": null,
    "managedFields": [
      {
        "manager": "curl",
        "operation": "Update",
        "apiVersion": "authentication.k8s.io/v1",
        "time": "2022-02-22T15:28:56Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {"f:spec":{"f:expirationSeconds":{}}}
      }
    ]
  },
  "spec": {
    "audiences": [
      "https://kubernetes.default.svc.cluster.local"
    ],
    "expirationSeconds": 3600,
    "boundObjectRef": null
  },
  "status": {
    "token": "a-kubernetes-jwt",
    "expirationTimestamp": "2022-02-22T16:28:56Z"
  }
}`
