package clientcache

import (
	"sync"

	"github.com/hashicorp/go-hclog"
	vaultclient "github.com/hashicorp/vault-csi-provider/internal/client"
	"github.com/hashicorp/vault-csi-provider/internal/config"
)

// ClientCache is an in-memory cache of tokens created by the Provider, tied to
// the lifetime of each Provider process. Repeated calls to Token for the same
// _pod_ should produce the same token for as long as its TTL has >10% remaining.
type ClientCache struct {
	logger hclog.Logger

	mtx   sync.RWMutex
	cache map[cacheKey]*vaultclient.Client
}

// NewClientCache intializes a new token cache.
func NewClientCache(logger hclog.Logger) *ClientCache {
	return &ClientCache{
		logger: logger,
		cache:  make(map[cacheKey]*vaultclient.Client),
	}
}

func (c *ClientCache) GetOrCreateClient(params config.Parameters, flagsConfig config.FlagsConfig) (client *vaultclient.Client, created bool, err error) {
	key, err := makeCacheKey(params)
	if err != nil {
		return nil, false, err
	}

	c.mtx.RLock()
	cachedClient, ok := c.cache[key]
	c.mtx.RUnlock()
	if ok {
		return cachedClient, false, nil
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Check cache once more with the write lock held.
	if cachedClient, ok := c.cache[key]; ok {
		return cachedClient, false, nil
	}

	client, err = vaultclient.New(c.logger, params, flagsConfig)
	if err != nil {
		return nil, false, err
	}

	c.cache[key] = client
	return client, true, nil
}
