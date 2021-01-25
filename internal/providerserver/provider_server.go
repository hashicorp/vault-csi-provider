package providerserver

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
	_ pb.CSIDriverProviderServer = (*ProviderServer)(nil)
)

// ProviderServer implements the secrets-store-csi-driver provider gRPC service interface.
type ProviderServer struct {
	Logger hclog.Logger
}

func (p *ProviderServer) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	p.Logger.Info("Processing version method call")
	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "secrets-store-csi-driver-provider-vault",
		RuntimeVersion: version.BuildVersion,
	}, nil
}

func (p *ProviderServer) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	p.Logger.Info(fmt.Sprintf("Processing mount method call: %+v", req))

	versions, err := p.handleMountRequest(ctx, req.Attributes, req.TargetPath, req.Permission)
	if err != nil {
		return nil, err
	}

	var ov []*pb.ObjectVersion
	for k, v := range versions {
		ov = append(ov, &pb.ObjectVersion{Id: k, Version: fmt.Sprintf("%d", v)})
	}

	return &pb.MountResponse{ObjectVersion: ov}, nil
}

func (p *ProviderServer) handleMountRequest(ctx context.Context, parametersStr, targetPath, permissionStr string) (map[string]int, error) {
	p.Logger.Debug("parametersStr", parametersStr)
	cfg, err := config.Parse(parametersStr, targetPath, permissionStr)
	if err != nil {
		return nil, err
	}

	p.Logger.Debug("vault: vault address", cfg.Parameters.VaultAddress)
	p.Logger.Debug("vault: roleName", cfg.Parameters.VaultRoleName)

	provider := provider.NewProvider(p.Logger)
	versions, err := provider.MountSecretsStoreObjectContent(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error making mount request: %w", err)
	}

	p.Logger.Info("Successfully handled mount request")

	return versions, nil
}
