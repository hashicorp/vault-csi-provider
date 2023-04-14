package tokencache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestParallelCacheAccess(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{},
	)
	tokenCreations := countTokenCreations(client, 10*time.Minute)
	cache := NewTokenCache(hclog.Default(), client)

	tokens := map[string]struct{}{}
	mtx := sync.Mutex{}
	var startWG, endWG sync.WaitGroup
	startWG.Add(1)
	for i := 0; i < 100; i++ {
		endWG.Add(1)
		go func() {
			defer endWG.Done()
			startWG.Wait()
			token, err := cache.GetOrCreateKubernetesToken(context.Background(), config.PodInfo{}, "vault")
			require.NoError(t, err)
			mtx.Lock()
			tokens[token] = struct{}{}
			mtx.Unlock()
		}()
	}

	// Unblock all the goroutines at once.
	startWG.Done()
	endWG.Wait()
	assert.Len(t, tokens, 1)
	assert.Equal(t, 1, *tokenCreations)
}

func TestTokenExpiry(t *testing.T) {
	for name, tc := range map[string]struct {
		ttl           time.Duration
		expectedCalls int
	}{
		"not expired":   {10 * time.Minute, 1},
		"expiring soon": {30 * time.Second, 2},
		"expired":       {-30 * time.Second, 2},
	} {
		t.Run(name, func(t *testing.T) {
			client := fake.NewSimpleClientset(
				&corev1.ServiceAccount{},
			)
			tokenCreations := countTokenCreations(client, tc.ttl)
			cache := NewTokenCache(hclog.Default(), client)

			token1, err := cache.GetOrCreateKubernetesToken(context.Background(), config.PodInfo{}, "vault")
			require.NoError(t, err)
			token2, err := cache.GetOrCreateKubernetesToken(context.Background(), config.PodInfo{}, "vault")
			require.NoError(t, err)
			assert.Equal(t, tc.expectedCalls == 1, token1 == token2)
			assert.Equal(t, tc.expectedCalls, *tokenCreations)
		})
	}
}

// Counts the number of times a token is created.
func countTokenCreations(client *fake.Clientset, returnedTTL time.Duration) *int {
	i := 0
	client.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		if action.GetSubresource() == "token" {
			i++
		}
		return true, &authenticationv1.TokenRequest{
			Status: authenticationv1.TokenRequestStatus{
				Token:               fmt.Sprintf("%d", i),
				ExpirationTimestamp: metav1.Time{Time: time.Now().Add(returnedTTL)},
			},
		}, nil
	})
	return &i
}
