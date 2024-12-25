package auth

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/stretchr/testify/assert"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"testing"
)

func TestAuthRequestWithExistingToken(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Debug,
	})

	// Mock Kubernetes client
	k8sClient := fake.NewClientset()

	params := config.Parameters{
		PodInfo: config.PodInfo{
			ServiceAccountToken: "existing-token",
		},
		VaultAuth: config.Auth{
			MouthPath: "kubernetes",
		},
		VaultRoleName: "test-role",
	}

	auth, err := NewKubernetesJWTAuth(logger, k8sClient, params, "kubernetes")
	assert.NoError(t, err)

	path, body, _, err := auth.AuthRequest(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, "/v1/auth/kubernetes/login", path)
	assert.Equal(t, "existing-token", body["jwt"])
	assert.Equal(t, "test-role", body["role"])
}

func TestAuthRequestWithGeneratedToken(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Debug,
	})

	// Mock Kubernetes client with service account token response
	token := "generated-token"
	k8sClient := fake.NewClientset()
	k8sClient.Fake.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &authenticationv1.TokenRequest{
			Status: authenticationv1.TokenRequestStatus{
				Token: token,
			},
		}, nil
	})

	params := config.Parameters{
		PodInfo: config.PodInfo{
			Namespace:          "default",
			ServiceAccountName: "default",
			UID:                "1234",
		},
		VaultAuth: config.Auth{
			MouthPath: "kubernetes",
		},
		Audience:      "vault",
		VaultRoleName: "test-role",
	}

	auth, err := NewKubernetesJWTAuth(logger, k8sClient, params, "kubernetes")
	assert.NoError(t, err)

	path, body, _, err := auth.AuthRequest(context.TODO())
	assert.NoError(t, err)
	assert.Equal(t, "/v1/auth/kubernetes/login", path)
	assert.Equal(t, token, body["jwt"])
	assert.Equal(t, "test-role", body["role"])
}

func TestCreateJWTToken(t *testing.T) {
	logger := hclog.New(&hclog.LoggerOptions{
		Name:  "test-logger",
		Level: hclog.Debug,
	})

	// Mock Kubernetes client with token generation
	token := "generated-token"
	k8sClient := fake.NewClientset()
	k8sClient.Fake.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (handled bool, ret runtime.Object, err error) {
		return true, &authenticationv1.TokenRequest{
			Status: authenticationv1.TokenRequestStatus{
				Token: token,
			},
		}, nil
	})

	auth := &KubernetesJWTAuth{
		logger:           logger,
		k8sClient:        k8sClient,
		defaultMountPath: "kubernetes",
	}

	jwt, err := auth.createJWTToken(context.TODO(), config.PodInfo{
		Namespace:          "default",
		ServiceAccountName: "default",
		UID:                "1234",
		Name:               "test-pod",
	}, "vault")
	assert.NoError(t, err)
	assert.Equal(t, token, jwt)
}
