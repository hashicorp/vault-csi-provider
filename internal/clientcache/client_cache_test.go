package clientcache

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParallelCacheAccess(t *testing.T) {
	cache := NewClientCache(hclog.Default())

	var createdCount int32
	var startWG, endWG sync.WaitGroup
	startWG.Add(1)
	for i := 0; i < 100; i++ {
		endWG.Add(1)
		go func() {
			defer endWG.Done()
			startWG.Wait()
			_, created, err := cache.GetOrCreateClient(config.Parameters{}, config.FlagsConfig{})
			require.NoError(t, err)
			if created {
				atomic.AddInt32(&createdCount, 1)
			}
		}()
	}

	// Unblock all the goroutines at once.
	startWG.Done()
	endWG.Wait()
	assert.Equal(t, int32(1), createdCount)
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
			{"bar1", "v1/secret/foo1", "", http.MethodGet, nil, 0, ""},
			{"bar2", "v1/secret/foo2", "", "", nil, 0, ""},
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

	_, created, err := cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, true, created)
	assert.Len(t, cache.cache, 1)

	// Shouldn't have modified the original params struct
	assert.Equal(t, "footoken", params.PodInfo.ServiceAccountToken)
	assert.Len(t, params.Secrets, 2)

	params.Secrets = append(params.Secrets, config.Secret{})
	params.PodInfo.ServiceAccountToken = "bartoken"

	_, created, err = cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, false, created)
	assert.Len(t, cache.cache, 1)

	// Still shouldn't have modified the updated params struct
	assert.Equal(t, "bartoken", params.PodInfo.ServiceAccountToken)
	assert.Len(t, params.Secrets, 3)

	params.PodInfo.UID = "new-uid"

	_, created, err = cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, true, created)
	assert.Len(t, cache.cache, 2)
}
