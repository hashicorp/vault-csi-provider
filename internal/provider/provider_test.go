// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/auth"
	"github.com/hashicorp/vault-csi-provider/internal/clientcache"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault-csi-provider/internal/hmac"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/fake"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

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

func TestKeyFromDataMissingKey(t *testing.T) {
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
	for _, tc := range []struct {
		name string
		key  string
		data map[string]interface{}
	}{
		{
			name: "base case",
			key:  "non-existing",
			data: data,
		},
		{
			name: "string data",
			key:  "non-existing",
			data: dataWithDataString,
		},
		{
			name: "kv v2 embedded data field",
			key:  "non-existing",
			data: dataWithDataField,
		},
	} {
		_, err := keyFromData(tc.data, tc.key)
		require.Error(t, err)
	}
}

func TestHandleMountRequest(t *testing.T) {
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
					Encoding:   "",
				},
				{
					ObjectName: "object-two",
					SecretPath: "path/two",
					SecretKey:  "",
					Method:     "",
					SecretArgs: nil,
					Encoding:   "",
				},
				{
					ObjectName: "object-three",
					SecretPath: "path/three",
					SecretKey:  "the-key",
					Method:     "",
					SecretArgs: nil,
					Encoding:   "base64",
				},
			},
		},
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
		{
			Path:     "object-three",
			Mode:     0,
			Contents: []byte("secret v1 from: /v1/path/three"),
		},
	}
	expectedVersionIDs := []string{"object-one", "object-two", "object-three"}
	versionsSeen := map[string]struct{}{}

	// SETUP
	mockVaultServer := httptest.NewServer(http.HandlerFunc(mockVaultHandler(
		map[string]func(numberOfCalls int) (string, interface{}){
			"/v1/path/one": func(numberOfCalls int) (string, interface{}) {
				return "the-key", fmt.Sprintf("secret v%d from: /v1/path/one", numberOfCalls)
			},
			"/v1/path/two": func(numberOfCalls int) (string, interface{}) {
				return "the-key", fmt.Sprintf("secret v%d from: /v1/path/two", numberOfCalls)
			},
			"/v1/path/three": func(numberOfCalls int) (string, interface{}) {
				return "the-key", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("secret v%d from: /v1/path/three", numberOfCalls)))
			},
		},
	)))
	flagsConfig := config.FlagsConfig{
		VaultAddr: mockVaultServer.URL,
	}
	defer mockVaultServer.Close()

	k8sClient := fake.NewSimpleClientset(
		&corev1.ServiceAccount{},
	)
	authMethod := auth.NewKubernetesJWTAuth(hclog.Default(), k8sClient, spcConfig.Parameters, "")
	hmacGenerator := hmac.NewHMACGenerator(k8sClient, &corev1.Secret{})
	clientCache, err := clientcache.NewClientCache(hclog.Default(), 10)
	require.NoError(t, err)
	// While we hit the cache, the secret contents and versions should remain the same.
	provider := NewProvider(hclog.Default(), authMethod, hmacGenerator, clientCache)
	for i := 0; i < 3; i++ {
		resp, err := provider.HandleMountRequest(context.Background(), spcConfig, flagsConfig)
		require.NoError(t, err)

		assert.Equal(t, (*v1alpha1.Error)(nil), resp.Error)
		assert.Equal(t, expectedFiles, resp.Files)
		assert.Equal(t, expectedVersionIDs[i], resp.ObjectVersion[i].Id)
		assert.NotEmpty(t, resp.ObjectVersion[i].Version)
		_, seen := versionsSeen[resp.ObjectVersion[i].Version]
		assert.False(t, seen)
		versionsSeen[resp.ObjectVersion[i].Version] = struct{}{}
	}

	// The mockVaultHandler function below includes a dynamic counter in the content of secrets.
	// That means mounting again with a fresh provider will update the contents of the secrets, which should update the version.
	resp, err := NewProvider(hclog.Default(), authMethod, hmacGenerator, clientCache).HandleMountRequest(context.Background(), spcConfig, flagsConfig)
	require.NoError(t, err)

	assert.Equal(t, (*v1alpha1.Error)(nil), resp.Error)
	expectedFiles[0].Contents = []byte("secret v2 from: /v1/path/one")
	expectedFiles[1].Contents = []byte(`{"request_id":"","lease_id":"","lease_duration":0,"renewable":false,"data":{"the-key":"secret v2 from: /v1/path/two"},"warnings":null}`)
	expectedFiles[2].Contents = []byte("secret v2 from: /v1/path/three")
	assert.Equal(t, expectedFiles, resp.Files)
	for i := 0; i < len(expectedFiles); i++ {
		assert.Equal(t, expectedVersionIDs[i], resp.ObjectVersion[i].Id)
		assert.NotEmpty(t, resp.ObjectVersion[i].Version)
		_, seen := versionsSeen[resp.ObjectVersion[i].Version]
		assert.False(t, seen)
		versionsSeen[resp.ObjectVersion[i].Version] = struct{}{}
	}
}

func mockVaultHandler(pathMapping map[string]func(numberOfCalls int) (string, interface{})) func(w http.ResponseWriter, req *http.Request) {
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
			mappingFunc := pathMapping[path]
			key, value := mappingFunc(getsPerPath[path])
			body, err := json.Marshal(&api.Secret{
				Data: map[string]interface{}{
					key: value,
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
