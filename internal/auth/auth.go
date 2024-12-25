package auth

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"k8s.io/client-go/kubernetes"
)

type Auth interface {
	AuthRequest(context.Context) (string, map[string]any, map[string]string, error)
}

func NewAuth(logger hclog.Logger, k8sClient kubernetes.Interface, params config.Parameters, defaultMountPath string) (Auth, error) {
	if params.VaultAuth.Type == "kubernetes" || params.VaultAuth.Type == "jwt" {
		return NewKubernetesJWTAuth(logger, k8sClient, params, defaultMountPath)
	}
	if params.VaultAuth.Type == "aws" {
		return NewAWSIAMAuth(logger, k8sClient, params, defaultMountPath)
	}
	// Default to Kubernetes
	return NewKubernetesJWTAuth(logger, k8sClient, params, defaultMountPath)
}
