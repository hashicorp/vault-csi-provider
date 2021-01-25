package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/providerserver"
	"github.com/hashicorp/secrets-store-csi-driver-provider-vault/internal/version"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var (
	endpoint    = pflag.String("endpoint", "/tmp/vault.sock", "path to socket on which to listen for driver gRPC calls")
	debug       = pflag.Bool("debug", false, "sets log to debug level")
	selfVersion = pflag.Bool("version", false, "prints the version information")
)

func main() {
	logger := hclog.Default()
	err := realMain(logger)
	if err != nil {
		logger.Error("Error running provider", err)
		os.Exit(1)
	}
}

func realMain(logger hclog.Logger) error {
	pflag.Parse()

	// set log level
	logger.SetLevel(hclog.Info)
	if *debug {
		logger.SetLevel(hclog.Debug)
	}

	if *selfVersion {
		v, err := version.GetVersion()
		if err != nil {
			return fmt.Errorf("failed to print version, err: %w", err)
		}
		// print the version and exit
		logger.Info(v)
		return nil
	}

	server := grpc.NewServer()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-c
		logger.Info(fmt.Sprintf("Caught signal %s, shutting down", sig))
		server.GracefulStop()
	}()

	listener, err := net.Listen("unix", *endpoint)
	if err != nil {
		return fmt.Errorf("failed to listen on unix socket at %s: %v", *endpoint, err)
	}
	defer listener.Close()
	logger.Info(fmt.Sprintf("Listening on %s", *endpoint))

	s := &providerserver.ProviderServer{
		Logger: logger,
	}
	pb.RegisterCSIDriverProviderServer(server, s)

	err = server.Serve(listener)
	if err != nil {
		return fmt.Errorf("error running gRPC server: %w", err)
	}

	return nil
}
