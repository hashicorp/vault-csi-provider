// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/go-hclog"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/hashicorp/vault-csi-provider/internal/config"
)

// Method is a Vault auth method that authenticates using the identity of the
// pod requesting the mount.
type Method interface {
	// AuthRequest returns the Vault login request path and JSON body.
	AuthRequest(ctx context.Context) (path string, body map[string]string, err error)
}

var (
	_ Method = (*KubernetesJWTAuth)(nil)
	_ Method = (*AWSIAMAuth)(nil)
)

// NewAuthMethod returns the auth method selected by the SecretProviderClass.
// defaultKubernetesMountPath is used by the Kubernetes auth method when no
// mount path is configured in the SecretProviderClass.
func NewAuthMethod(logger hclog.Logger, k8sClient kubernetes.Interface, params config.Parameters, defaultKubernetesMountPath string) (Method, error) {
	switch params.VaultAuthType {
	case "", config.AuthTypeKubernetes:
		return NewKubernetesJWTAuth(logger, k8sClient, params, defaultKubernetesMountPath), nil
	case config.AuthTypeAWS:
		return NewAWSIAMAuth(logger, k8sClient, params), nil
	default:
		return nil, fmt.Errorf("unsupported auth type %q", params.VaultAuthType)
	}
}

// createServiceAccountToken creates a short-lived token for the requesting
// pod's service account, bound to the pod's lifetime.
func createServiceAccountToken(ctx context.Context, logger hclog.Logger, k8sClient kubernetes.Interface, podInfo config.PodInfo, audience string) (string, error) {
	logger.Debug("creating service account token bound to pod",
		"namespace", podInfo.Namespace,
		"serviceAccountName", podInfo.ServiceAccountName,
		"podUID", podInfo.UID,
		"audience", audience)

	ttl := int64((15 * time.Minute).Seconds())
	audiences := []string{}
	if audience != "" {
		audiences = []string{audience}
	}
	resp, err := k8sClient.CoreV1().ServiceAccounts(podInfo.Namespace).CreateToken(ctx, podInfo.ServiceAccountName, &authenticationv1.TokenRequest{
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

	logger.Debug("service account token creation successful")
	return resp.Status.Token, nil
}
