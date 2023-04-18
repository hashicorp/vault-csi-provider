// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/auth"
	"github.com/hashicorp/vault-csi-provider/internal/clientcache"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault-csi-provider/internal/hmac"
	"github.com/hashicorp/vault-csi-provider/internal/provider"
	"github.com/hashicorp/vault-csi-provider/internal/version"
	"k8s.io/client-go/kubernetes"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var _ pb.CSIDriverProviderServer = (*Server)(nil)

// Server implements the secrets-store-csi-driver provider gRPC service interface.
type Server struct {
	logger        hclog.Logger
	flagsConfig   config.FlagsConfig
	k8sClient     kubernetes.Interface
	hmacGenerator *hmac.HMACGenerator
	clientCache   *clientcache.ClientCache
}

func NewServer(logger hclog.Logger, flagsConfig config.FlagsConfig, k8sClient kubernetes.Interface, hmacGenerator *hmac.HMACGenerator) *Server {
	return &Server{
		logger:        logger,
		flagsConfig:   flagsConfig,
		k8sClient:     k8sClient,
		hmacGenerator: hmacGenerator,
		clientCache:   clientcache.NewClientCache(logger.Named("vaultclient")),
	}
}

func (s *Server) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "vault-csi-provider",
		RuntimeVersion: version.BuildVersion,
	}, nil
}

func (s *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	cfg, err := config.Parse(req.Attributes, req.TargetPath, req.Permission)
	if err != nil {
		return nil, err
	}

	authMethod := auth.NewKubernetesAuth(s.logger.Named("auth"), s.k8sClient, cfg.Parameters, s.flagsConfig.VaultMount)
	provider := provider.NewProvider(s.logger.Named("provider"), authMethod, s.hmacGenerator, s.clientCache)
	resp, err := provider.HandleMountRequest(ctx, cfg, s.flagsConfig)
	if err != nil {
		return nil, fmt.Errorf("error making mount request: %w", err)
	}

	return resp, nil
}
