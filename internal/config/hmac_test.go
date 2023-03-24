package config

import (
	"bytes"
	"os"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	exampleLabels = `app.kubernetes.io/name="vault-csi-provider"
controller-revision-hash="6b9f99c64"
`

	exampleAnnotations = `kubernetes.io/config.seen="2023-03-23T13:55:54.257019345Z"
kubernetes.io/config.source="api"`
)

var (
	expectedLabels = map[string]string{
		"app.kubernetes.io/name":   "vault-csi-provider",
		"controller-revision-hash": "6b9f99c64",
	}

	expectedAnnotations = map[string]string{
		"kubernetes.io/config.seen":   "2023-03-23T13:55:54.257019345Z",
		"kubernetes.io/config.source": "api",
	}
)

func TestParseHMACSecretConfig(t *testing.T) {
	dir := t.TempDir()
	namespacePath := createFile(t, dir, "csi")
	labelsPath := createFile(t, dir, exampleLabels)
	annotationsPath := createFile(t, dir, exampleAnnotations)

	secret, err := ParseHMACSecretConfig(hclog.NewNullLogger(), "foo", namespacePath, labelsPath, annotationsPath)
	require.NoError(t, err)

	assert.Equal(t, "foo", secret.Name)
	assert.Equal(t, "csi", secret.Namespace)
	assert.True(t, *secret.Immutable)
	for _, pair := range []struct {
		expected, actual map[string]string
	}{
		{expectedLabels, secret.Labels},
		{expectedAnnotations, secret.Annotations},
	} {
		require.Equal(t, len(pair.expected), len(pair.actual))
		for k, v := range pair.expected {
			assert.Equal(t, v, pair.actual[k])
		}
	}
}

func TestParseHMACSecretConfig_AllowsMissingMetadataFiles(t *testing.T) {
	dir := t.TempDir()
	namespacePath := createFile(t, dir, "csi")

	logBuf := bytes.NewBuffer(nil)
	require.Zero(t, logBuf.Len())
	logger := hclog.New(&hclog.LoggerOptions{
		Level:  hclog.Warn,
		Output: logBuf,
	})

	secret, err := ParseHMACSecretConfig(logger, "foo", namespacePath, "", "")
	require.NoError(t, err)
	assert.Equal(t, "foo", secret.Name)
	assert.Equal(t, "csi", secret.Namespace)
	assert.True(t, *secret.Immutable)
	assert.Nil(t, secret.Labels)
	assert.Nil(t, secret.Annotations)
	// Should have had some warnings logged.
	assert.NotZero(t, logBuf.Len())
}

func createFile(t *testing.T, dir, contents string) string {
	t.Helper()
	f, err := os.CreateTemp(dir, "")
	require.NoError(t, err)

	_, err = f.WriteString(contents)
	require.NoError(t, err)

	return f.Name()
}
