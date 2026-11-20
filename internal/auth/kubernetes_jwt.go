// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"k8s.io/client-go/kubernetes"

	"github.com/hashicorp/vault-csi-provider/internal/config"
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
		jwt, err = createServiceAccountToken(ctx, k.logger, k.k8sClient, k.params.PodInfo, k.params.Audience)
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
