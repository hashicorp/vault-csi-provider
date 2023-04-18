package clientcache

import (
	"sync"

	"github.com/hashicorp/go-hclog"
	vaultclient "github.com/hashicorp/vault-csi-provider/internal/client"
	"github.com/hashicorp/vault-csi-provider/internal/config"
)

type ClientCache struct {
	logger hclog.Logger

	mtx   sync.Mutex
	cache map[cacheKey]*vaultclient.Client
}

// NewClientCache intializes a new client cache. The cache's lifetime
// should be tied to the provider process (i.e. longer than a single
// mount request) so that Vault tokens stored in the clients are cached
// and reused across different mount requests for the same pod.
func NewClientCache(logger hclog.Logger) *ClientCache {
	return &ClientCache{
		logger: logger,
		cache:  make(map[cacheKey]*vaultclient.Client),
	}
}

func (c *ClientCache) GetOrCreateClient(params config.Parameters, flagsConfig config.FlagsConfig) (*vaultclient.Client, error) {
	key, err := makeCacheKey(params)
	if err != nil {
		return nil, err
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	if cachedClient, ok := c.cache[key]; ok {
		return cachedClient, nil
	}

	client, err := vaultclient.New(c.logger, params, flagsConfig)
	if err != nil {
		return nil, err
	}

	c.cache[key] = client
	return client, nil
}
