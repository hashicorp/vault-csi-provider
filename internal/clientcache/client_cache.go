// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package clientcache

import (
	"sync"

	"github.com/hashicorp/go-hclog"
	lru "github.com/hashicorp/golang-lru/v2"
	vaultclient "github.com/hashicorp/vault-csi-provider/internal/client"
	"github.com/hashicorp/vault-csi-provider/internal/config"
)

type ClientCache struct {
	logger hclog.Logger

	mtx   sync.Mutex
	cache *lru.Cache[cacheKey, *vaultclient.Client]
}

// NewClientCache intializes a new client cache. The cache's lifetime
// should be tied to the provider process (i.e. longer than a single
// mount request) so that Vault tokens stored in the clients are cached
// and reused across different mount requests for the same pod.
func NewClientCache(logger hclog.Logger, size int) (*ClientCache, error) {
	var cache *lru.Cache[cacheKey, *vaultclient.Client]
	var err error
	if size > 0 {
		logger.Info("Creating Vault client cache", "size", size)
		cache, err = lru.New[cacheKey, *vaultclient.Client](size)
		if err != nil {
			return nil, err
		}
	} else {
		logger.Info("Disabling Vault client cache", "size", size)
	}

	return &ClientCache{
		logger: logger,
		cache:  cache,
	}, nil
}

func (c *ClientCache) GetOrCreateClient(params config.Parameters, flagsConfig config.FlagsConfig) (*vaultclient.Client, error) {
	if c.cache == nil {
		return vaultclient.New(c.logger, params, flagsConfig)
	}

	key, err := makeCacheKey(params)
	if err != nil {
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if cachedClient, ok := c.cache.Get(key); ok {
		return cachedClient, nil
	}

	client, err := vaultclient.New(c.logger, params, flagsConfig)
	if err != nil {
		return nil, err
	}

	c.cache.Add(key, client)
	return client, nil
}
