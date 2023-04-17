package clientcache

import (
	"encoding/json"

	"github.com/hashicorp/vault-csi-provider/internal/config"
)

type cacheKey string

func makeCacheKey(params config.Parameters) (cacheKey, error) {
	// Zero out the configurables that should not cause a cache miss when they change.
	params.PodInfo.ServiceAccountToken = ""
	params.Secrets = nil

	paramsBytes, err := json.Marshal(&params)
	if err != nil {
		return "", err
	}

	return cacheKey(paramsBytes), nil
}
