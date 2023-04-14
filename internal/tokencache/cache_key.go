package tokencache

import (
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"k8s.io/apimachinery/pkg/types"
)

type cacheKey struct {
	namespace          string
	serviceAccountName string
	podUID             types.UID
	audience           string
}

func makeCacheKey(podInfo config.PodInfo, audience string) cacheKey {
	return cacheKey{
		namespace:          podInfo.Namespace,
		serviceAccountName: podInfo.ServiceAccountName,
		podUID:             podInfo.UID,
		audience:           audience,
	}
}

func logFields(key cacheKey) []string {
	return []string{"namespace", key.namespace,
		"serviceAccountName", key.serviceAccountName,
		"podUID", string(key.podUID),
		"audience", key.audience}
}
