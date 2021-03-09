package server

import (
	"context"
	"fmt"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/hashicorp/vault-csi-provider/internal/provider"
	"github.com/hashicorp/vault-csi-provider/internal/version"
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
	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "vault-csi-provider",
		RuntimeVersion: version.BuildVersion,
	}, nil
}

func (p *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
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
	cfg, err := config.Parse(p.Logger.Named("config"), parametersStr, targetPath, permissionStr)
	if err != nil {
		return nil, err
	}

	provider := provider.NewProvider(p.Logger.Named("provider"))
	versions, err := provider.MountSecretsStoreObjectContent(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error making mount request: %w", err)
	}

	return versions, nil
}
