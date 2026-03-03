// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	cache, err := NewClientCache(hclog.Default(), 1000)
	require.NoError(t, err)

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
	assert.Equal(t, 1, cache.cache.Len())
}

func TestCacheKeyedOnCorrectFields(t *testing.T) {
	cache, err := NewClientCache(hclog.Default(), 10)
	require.NoError(t, err)
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

	_, err = cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, 1, cache.cache.Len())

	// Shouldn't have modified the original params struct
	assert.Equal(t, "footoken", params.PodInfo.ServiceAccountToken)
	assert.Len(t, params.Secrets, 2)

	params.Secrets = append(params.Secrets, config.Secret{})
	params.PodInfo.ServiceAccountToken = "bartoken"

	_, err = cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, 1, cache.cache.Len())

	// Still shouldn't have modified the updated params struct
	assert.Equal(t, "bartoken", params.PodInfo.ServiceAccountToken)
	assert.Len(t, params.Secrets, 3)

	params.PodInfo.UID = "new-uid"

	_, err = cache.GetOrCreateClient(params, config.FlagsConfig{})
	require.NoError(t, err)
	assert.Equal(t, 2, cache.cache.Len())
}

func TestCache_CanBeDisabled(t *testing.T) {
	for name, tc := range map[string]struct {
		size            int
		expectedCaching bool
	}{
		"-10": {-10, false},
		"-1":  {-1, false},
		"0":   {0, false},
		"1":   {1, true},
	} {
		t.Run(name, func(t *testing.T) {
			cache, err := NewClientCache(hclog.Default(), tc.size)
			require.NoError(t, err)
			params := config.Parameters{}
			flags := config.FlagsConfig{}

			c1, err := cache.GetOrCreateClient(params, flags)
			require.NoError(t, err)
			c2, err := cache.GetOrCreateClient(params, flags)
			require.NoError(t, err)
			if tc.expectedCaching {
				assert.Equal(t, 1, cache.cache.Len())
				assert.Equal(t, c1, c2)
			} else {
				assert.Nil(t, cache.cache)
				assert.NotEqual(t, c1, c2)
			}
		})
	}
}
