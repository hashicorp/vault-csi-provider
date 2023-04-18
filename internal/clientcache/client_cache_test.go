package clientcache

import (
	"net/http"
	"sync"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParallelCacheAccess(t *testing.T) {
	cache := NewClientCache(hclog.Default())

	var startWG, endWG sync.WaitGroup
	startWG.Add(1)
	for i := 0; i < 100; i++ {
		endWG.Add(1)
		go func() {
			defer endWG.Done()
			startWG.Wait()
			_, err := cache.GetOrCreateClient(config.Parameters{}, config.FlagsConfig{})
			require.NoError(t, err)
		}()
	}

	// Unblock all the goroutines at once.
	startWG.Done()
	endWG.Wait()
	assert.Len(t, cache.cache, 1)
}

func TestCacheKeyedOnCorrectFields(t *testing.T) {
	cache := NewClientCache(hclog.Default())
	params := config.Parameters{
		VaultRoleName: "example-role",
		VaultAddress:  "http://vault:8200",
		VaultTLSConfig: api.TLSConfig{
			Insecure: true,
		},
		Secrets: []config.Secret{
			{
				ObjectName: "bar1",
				SecretPath: "v1/secret/foo1",
				Method:     http.MethodGet,
			},
			{
				ObjectName: "bar2",
				SecretPath: "v1/secret/foo2",
				Method:     http.MethodGet,
			},
		},
		PodInfo: config.PodInfo{
			Name:                "nginx-secrets-store-inline",
			UID:                 "9aeb260f-d64a-426c-9872-95b6bab37e00",
			Namespace:           "test",
			ServiceAccountName:  "default",
			ServiceAccountToken: "footoken",
		},
		Audience: "testaudience",
	}

	_, err := cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Len(t, cache.cache, 1)

	// Shouldn't have modified the original params struct
	assert.Equal(t, "footoken", params.PodInfo.ServiceAccountToken)
	assert.Len(t, params.Secrets, 2)

	params.Secrets = append(params.Secrets, config.Secret{})
	params.PodInfo.ServiceAccountToken = "bartoken"

	_, err = cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Len(t, cache.cache, 1)

	// Still shouldn't have modified the updated params struct
	assert.Equal(t, "bartoken", params.PodInfo.ServiceAccountToken)
	assert.Len(t, params.Secrets, 3)

	params.PodInfo.UID = "new-uid"

	_, err = cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Len(t, cache.cache, 2)
}
