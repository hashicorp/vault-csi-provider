// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// KubernetesJWTAuth implements both Kubernetes and JWT auth, as both have
// exactly the same login endpoint. If their login endpoints ever diverge, this
// struct may need splitting.
type KubernetesJWTAuth struct {
	logger           hclog.Logger
	k8sClient        kubernetes.Interface
	params           config.Parameters
	defaultMountPath string
}

func NewKubernetesJWTAuth(logger hclog.Logger, k8sClient kubernetes.Interface, params config.Parameters, defaultMountPath string) *KubernetesJWTAuth {
	return &KubernetesJWTAuth{
		logger:           logger,
		k8sClient:        k8sClient,
		params:           params,
		defaultMountPath: defaultMountPath,
	}
}

// AuthRequest returns the request path and body required to authenticate
// using the configured auth role in Vault. If no appropriate JWT is provided
// in the CSI mount request, it will create a new one.
func (k *KubernetesJWTAuth) AuthRequest(ctx context.Context) (path string, body map[string]string, err error) {
	jwt := k.params.PodInfo.ServiceAccountToken
	if jwt == "" {
		k.logger.Debug("no suitable token found in mount request, using self-generated service account JWT")
		var err error
		jwt, err = k.createJWTToken(ctx, k.params.PodInfo, k.params.Audience)
		if err != nil {
			return "", nil, err
		}
	} else {
		k.logger.Debug("using token from mount request for login")
	}

	mountPath := k.params.VaultAuthMountPath
	if mountPath == "" {
		mountPath = k.defaultMountPath
	}

	return fmt.Sprintf("/v1/auth/%s/login", mountPath), map[string]string{
		"jwt":  jwt,
		"role": k.params.VaultRoleName,
	}, nil
}

func (k *KubernetesJWTAuth) createJWTToken(ctx context.Context, podInfo config.PodInfo, audience string) (string, error) {
	k.logger.Debug("creating service account token bound to pod",
		"namespace", podInfo.Namespace,
		"serviceAccountName", podInfo.ServiceAccountName,
		"podUID", podInfo.UID,
		"audience", audience)

	ttl := int64((15 * time.Minute).Seconds())
	audiences := []string{}
	if audience != "" {
		audiences = []string{audience}
	}
	resp, err := k.k8sClient.CoreV1().ServiceAccounts(podInfo.Namespace).CreateToken(ctx, podInfo.ServiceAccountName, &authenticationv1.TokenRequest{
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

	k.logger.Debug("service account token creation successful")
	return resp.Status.Token, nil
}
