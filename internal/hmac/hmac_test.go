// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: BUSL-1.1

package hmac

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	secretName      = "test-secret"
	secretNamespace = "test-namespace"
)

var secretSpec = &corev1.Secret{
	ObjectMeta: metav1.ObjectMeta{
		Name:      secretName,
		Namespace: secretNamespace,
	},
	Data: map[string][]byte{
		hmacKeyName: []byte(strings.Repeat("a", 32)),
	},
}

func setup(t *testing.T) (*HMACGenerator, *fake.Clientset) {
	client := fake.NewSimpleClientset()
	return NewHMACGenerator(client, secretSpec), client
}

func TestGenerateSecretIfNoneExists(t *testing.T) {
	gen, client := setup(t)

	// Add counter functions.
	createCount := countAPICalls(client, "create", "secrets")
	getCount := countAPICalls(client, "get", "secrets")

	// Get an HMAC key, which should create the k8s secret.
	key, err := gen.GetOrCreateHMACKey(context.Background())
	require.NoError(t, err)
	assert.Len(t, key, hmacKeyLength)
	assert.Equal(t, 1, *createCount)
	assert.Equal(t, 1, *getCount)
	assert.NotEqual(t, string(secretSpec.Data[hmacKeyName]), string(key))
	assert.NotEmpty(t, string(key))
}

func TestReadSecretIfAlreadyExists(t *testing.T) {
	gen, client := setup(t)

	ctx := context.Background()
	_, err := client.CoreV1().Secrets(secretNamespace).Create(ctx, secretSpec, metav1.CreateOptions{})
	require.NoError(t, err)

	// Add counter functions.
	createCount := countAPICalls(client, "create", "secrets")
	getCount := countAPICalls(client, "get", "secrets")

	// Get an HMAC key, which should read the existing k8s secret.
	key, err := gen.GetOrCreateHMACKey(ctx)
	require.NoError(t, err)
	assert.Len(t, key, hmacKeyLength)
	assert.Equal(t, 0, *createCount)
	assert.Equal(t, 1, *getCount)
	assert.Equal(t, string(secretSpec.Data[hmacKeyName]), string(key))
}

func TestGracefullyHandlesLosingTheRace(t *testing.T) {
	gen, client := setup(t)

	ctx := context.Background()

	client.PrependReactor("create", "secrets", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		// Intercept the create call and create the secret just before.
		err = client.Tracker().Create(schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "secrets",
		}, secretSpec, secretNamespace)
		require.NoError(t, err)
		return false, nil, nil
	})
	createCount := countAPICalls(client, "create", "secrets")
	getCount := countAPICalls(client, "get", "secrets")

	// Get an HMAC key, which should initially find no secret, and then lose the race for creating it.
	key, err := gen.GetOrCreateHMACKey(ctx)
	require.NoError(t, err)
	assert.Len(t, key, hmacKeyLength)
	assert.Equal(t, 1, *createCount)
	assert.Equal(t, 2, *getCount)
	assert.Equal(t, string(secretSpec.Data[hmacKeyName]), string(key))
}

// Counts the number of times an API is called.
func countAPICalls(client *fake.Clientset, verb string, resource string) *int {
	i := 0
	client.PrependReactor(verb, resource, func(_ k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		i++
		return false, nil, nil
	})
	return &i
}
