package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/config"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/provider"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/version"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var (
	_ pb.CSIDriverProviderServer = (*Server)(nil)
)

// Server implements the secrets-store-csi-driver provider gRPC service interface.
type Server struct {
	Logger hclog.Logger
}

func (p *Server) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	p.Logger.Info("Processing version method call")
	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "secrets-store-csi-driver-provider-vault",
		RuntimeVersion: version.BuildVersion,
	}, nil
}

func (p *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	p.Logger.Info("Processing mount method call", "request", req)

	versions, err := p.handleMountRequest(ctx, req.Attributes, req.TargetPath, req.Permission)
	if err != nil {
		return nil, err
	}

	var ov []*pb.ObjectVersion
	for k, v := range versions {
		ov = append(ov, &pb.ObjectVersion{Id: k, Version: v})
	}

	return &pb.MountResponse{ObjectVersion: ov}, nil
}

func (p *Server) handleMountRequest(ctx context.Context, parametersStr, targetPath, permissionStr string) (map[string]string, error) {
	p.Logger.Debug("Handling mount request", "parametersStr", parametersStr)
	cfg, err := config.Parse(p.Logger.Named("config"), parametersStr, targetPath, permissionStr)
	if err != nil {
		return nil, err
	}

	p.Logger.Debug("Running provider server", "vault address", cfg.Parameters.VaultAddress, "roleName", cfg.Parameters.VaultRoleName)

	provider := provider.NewProvider(p.Logger.Named("provider"))
	versions, err := provider.MountSecretsStoreObjectContent(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error making mount request: %w", err)
	}

	p.Logger.Info("Successfully handled mount request")

	return versions, nil
}
