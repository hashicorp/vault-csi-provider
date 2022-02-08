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
	logger      hclog.Logger
	flagsConfig config.FlagsConfig
}

func NewServer(logger hclog.Logger, flagsConfig config.FlagsConfig) *Server {
	return &Server{
		logger:      logger,
		flagsConfig: flagsConfig,
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

	provider := provider.NewProvider(s.logger.Named("provider"))
	resp, err := provider.HandleMountRequest(ctx, cfg, s.flagsConfig)
	if err != nil {
		return nil, fmt.Errorf("error making mount request: %w", err)
	}

	return resp, nil
}
