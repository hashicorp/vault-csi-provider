// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/hashicorp/vault-csi-provider/internal/config"
)

func TestKubernetesJWTAuth_AuthRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		params                config.Parameters
		expectedPath          string
		expectedJWT           string
		expectedTokenRequests int
	}{
		"default mount path and self-generated token": {
			params: config.Parameters{
				VaultRoleName: "vault-role",
				Audience:      "vault",
				PodInfo:       testPodInfo(),
			},
			expectedPath:          "/v1/auth/default-mount/login",
			expectedJWT:           "self-generated-token",
			expectedTokenRequests: 1,
		},
		"custom mount path and token from mount request": {
			params: config.Parameters{
				VaultRoleName:      "vault-role",
				VaultAuthMountPath: "custom-mount",
				PodInfo: func() config.PodInfo {
					p := testPodInfo()
					p.ServiceAccountToken = "mount-request-token"
					return p
				}(),
			},
			expectedPath: "/v1/auth/custom-mount/login",
			expectedJWT:  "mount-request-token",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var tokenRequests []*authenticationv1.TokenRequest
			k8sClient := fake.NewClientset()
			k8sClient.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
				tokenRequests = append(tokenRequests, action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenRequest))
				return true, &authenticationv1.TokenRequest{
					Status: authenticationv1.TokenRequestStatus{Token: "self-generated-token"},
				}, nil
			})

			k := NewKubernetesJWTAuth(hclog.NewNullLogger(), k8sClient, tc.params, "default-mount")
			path, body, err := k.AuthRequest(context.Background())
			require.NoError(t, err)
			require.Equal(t, tc.expectedPath, path)
			require.Equal(t, map[string]string{"jwt": tc.expectedJWT, "role": "vault-role"}, body)
			require.Len(t, tokenRequests, tc.expectedTokenRequests)
			if tc.expectedTokenRequests > 0 {
				require.Equal(t, []string{tc.params.Audience}, tokenRequests[0].Spec.Audiences)
			}
		})
	}
}
