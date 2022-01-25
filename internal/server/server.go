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
	Logger     hclog.Logger
	VaultAddr  string
	VaultMount string
}

func (p *Server) Version(context.Context, *pb.VersionRequest) (*pb.VersionResponse, error) {
	return &pb.VersionResponse{
		Version:        "v1alpha1",
		RuntimeName:    "vault-csi-provider",
		RuntimeVersion: version.BuildVersion,
	}, nil
}

func (p *Server) Mount(ctx context.Context, req *pb.MountRequest) (*pb.MountResponse, error) {
	cfg, err := config.Parse(req.Attributes, req.TargetPath, req.Permission, p.VaultAddr, p.VaultMount)
	if err != nil {
		return nil, err
	}

	provider := provider.NewProvider(p.Logger.Named("provider"))
	resp, err := provider.HandleMountRequest(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error making mount request: %w", err)
	}

	return resp, nil
}
