package tokencache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// TokenCache is an in-memory cache of tokens created by the Provider, tied to
// the lifetime of each Provider process. Repeated calls to Token for the same
// _pod_ should produce the same token for as long as its TTL has >10% remaining.
type TokenCache struct {
	logger    hclog.Logger
	k8sClient kubernetes.Interface

	mtx   sync.RWMutex
	cache map[cacheKey]authenticationv1.TokenRequestStatus
}

// NewTokenCache intializes a new token cache.
func NewTokenCache(logger hclog.Logger, k8sClient kubernetes.Interface) *TokenCache {
	return &TokenCache{
		logger:    logger,
		k8sClient: k8sClient,
		cache:     make(map[cacheKey]authenticationv1.TokenRequestStatus),
	}
}

// GetOrCreateKubernetesToken checks the cache for a token still within its TTL,
// and if none is found requests a new one from the Kubernetes API.
func (c *TokenCache) GetOrCreateKubernetesToken(ctx context.Context, podInfo config.PodInfo, audience string) (string, error) {
	key := makeCacheKey(podInfo, audience)

	c.mtx.RLock()
	cachedToken := c.validCachedToken(key)
	c.mtx.RUnlock()
	if cachedToken != "" {
		return cachedToken, nil
	}

	c.mtx.Lock()
	defer c.mtx.Unlock()

	// Check cache once more with the write lock held.
	if cachedToken := c.validCachedToken(key); cachedToken != "" {
		return cachedToken, nil
	}

	c.logger.Debug("creating service account token bound to pod",
		"namespace", key.namespace,
		"serviceAccountName", key.serviceAccountName,
		"podUID", string(key.podUID),
		"audience", key.audience)

	ttl := int64(15 * time.Minute.Seconds())
	audiences := []string{}
	if audience != "" {
		audiences = []string{audience}
	}
	resp, err := c.k8sClient.CoreV1().ServiceAccounts(podInfo.Namespace).CreateToken(ctx, podInfo.ServiceAccountName, &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &ttl,
			Audiences:         audiences,
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       "Pod",
				APIVersion: "v1",
				Name:       podInfo.Name,
				UID:        podInfo.UID,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to create a service account token for requesting pod %v: %w", podInfo, err)
	}

	c.logger.Debug("service account token creation successful")
	c.cache[key] = resp.Status
	return resp.Status.Token, nil
}

func (c *TokenCache) validCachedToken(key cacheKey) string {
	status, ok := c.cache[key]
	if !ok {
		return ""
	}
	if expired(status) {
		c.logger.Debug("token in cache expired or expiring shortly",
			"namespace", key.namespace,
			"serviceAccountName", key.serviceAccountName,
			"podUID", string(key.podUID),
			"audience", key.audience)
		delete(c.cache, key)
		return ""
	}

	c.logger.Debug("token cache hit",
		"namespace", key.namespace,
		"serviceAccountName", key.serviceAccountName,
		"podUID", string(key.podUID),
		"audience", key.audience)

	return status.Token
}

func expired(status authenticationv1.TokenRequestStatus) bool {
	return time.Now().Add(time.Minute).After(status.ExpirationTimestamp.Time)
}
