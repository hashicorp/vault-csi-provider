package provider

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/config"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFilePath(t *testing.T) {
	// Don't use filepath.Join to generate the test cases because it calls filepath.Clean
	// which simplifies some of the test cases into less interesting paths.
	for _, tc := range []string{
		"",
		".",
		"/",
		"bar",
		"bar/foo",
		"bar///foo",
		"./bar",
		"/foo/bar",
		"foo/bar\\baz",
	} {
		err := validateFilePath(tc)
		if err != nil {
			t.Fatalf("Expected no error for %q but got %s", tc, err)
		}
	}
}

func TestValidatePath_Malformed(t *testing.T) {
	for _, tc := range []string{
		"../bar",
		"foo/..",
		"foo/../../bar",
		"foo////..",
	} {
		err := validateFilePath(tc)
		if err == nil {
			t.Fatalf("Expected error for %q but got none", tc)
		}

		tc = strings.ReplaceAll(tc, "/", "\\")
		err = validateFilePath(tc)
		if err == nil {
			t.Fatalf("Expected error for %q but got none", tc)
		}
	}
}

func TestWriteSecret(t *testing.T) {
	l := hclog.NewNullLogger()
	for _, tc := range []struct {
		name       string
		file       string
		permission os.FileMode
		invalid    bool
	}{
		{
			name:       "simple case",
			file:       "foo",
			permission: 0644,
		},
		{
			name:       "validation error",
			file:       filepath.Join("..", "foo"),
			permission: 0644,
			invalid:    true,
		},
		{
			name:       "requires new directory",
			file:       filepath.Join("foo", "bar", "baz"),
			permission: 0644,
		},
		{
			name:       "only owner can read",
			file:       "foo",
			permission: 0600,
		},
	} {
		root, err := ioutil.TempDir(os.TempDir(), "")
		require.NoError(t, err, tc.name)
		defer func() {
			require.NoError(t, os.RemoveAll(root), tc.name)
		}()

		err = writeSecret(l, root, tc.file, "", tc.permission)
		if tc.invalid {
			require.Error(t, err, tc.name)
			assert.Contains(t, err.Error(), "must not contain any .. segments", tc.name)
			continue
		}

		require.NoError(t, err, tc.name)
		rootedPath := filepath.Join(root, tc.file)
		info, err := os.Stat(rootedPath)
		require.NoError(t, err, tc.name)
		assert.Equal(t, tc.permission, info.Mode(), tc.name)
	}
}

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
			expected: expected{"GET", "/v1/secret/foo", "", ""},
		},
		{
			name: "zero-length query string",
			secret: config.Secret{
				SecretPath: "secret/foo?",
			},
			expected: expected{"GET", "/v1/secret/foo", "", ""},
		},
		{
			name: "query string",
			secret: config.Secret{
				SecretPath: "secret/foo?bar=true&baz=maybe&zap=0",
			},
			expected: expected{"GET", "/v1/secret/foo", "bar=true&baz=maybe&zap=0", ""},
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
				Method:     "POST",
				SecretArgs: map[string]interface{}{
					"bar": true,
					"baz": 10,
					"zap": "a string",
				},
			},
			expected: expected{"POST", "/v1/secret/foo", "", `{"bar":true,"baz":10,"zap":"a string"}`},
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
	for _, tc := range []struct {
		name        string
		key         string
		data        map[string]interface{}
		expected    string
		errExpected bool
	}{
		{
			name:     "base case",
			key:      "foo",
			data:     data,
			expected: "bar",
		},
		{
			name:     "string data",
			key:      "data",
			data:     dataWithDataString,
			expected: "hello",
		},
		{
			name:     "kv v2 embedded data field",
			key:      "foo",
			data:     dataWithDataField,
			expected: "bar",
		},
		{
			name:        "kv v2 embedded data field",
			key:         "foo",
			data:        dataWithNonStringValue,
			errExpected: true,
		},
	} {
		content, err := keyFromData(tc.data, tc.key)
		if tc.errExpected {
			require.Error(t, err, tc.name)
		} else {
			require.NoError(t, err, tc.name)
			assert.Equal(t, tc.expected, content)
		}
	}
}
