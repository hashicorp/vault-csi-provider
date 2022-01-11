package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hashicorp/go-hclog"
	providerserver "github.com/hashicorp/vault-csi-provider/internal/server"
	"github.com/hashicorp/vault-csi-provider/internal/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

func main() {
	logger := hclog.Default()
	err := realMain(logger)
	if err != nil {
		logger.Error("Error running provider", "err", err)
		os.Exit(1)
	}
}

func realMain(logger hclog.Logger) error {
	var (
		endpoint     = flag.String("endpoint", "/tmp/vault.sock", "path to socket on which to listen for driver gRPC calls")
		debug        = flag.Bool("debug", false, "sets log to debug level")
		selfVersion  = flag.Bool("version", false, "prints the version information")
		vaultAddr    = flag.String("vault-addr", "https://127.0.0.1:8200", "default address for connecting to Vault")
		vaultMount   = flag.String("vault-mount", "kubernetes", "default Vault mount path for Kubernetes authentication")
		writeSecrets = flag.Bool("write-secrets", false, "deprecated, write secrets directly to filesystem (true), or send secrets to CSI driver in gRPC response (false)")
		healthAddr   = new(string)
	)
	flag.StringVar(healthAddr, "health_addr", "", "deprecated, please use -health-addr")
	flag.StringVar(healthAddr, "health-addr", ":8080", "configure http listener for reporting health")
	flag.Parse()

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
		_, err = fmt.Println(v)
		return err
	}

	logger.Info("Creating new gRPC server")
	serverLogger := logger.Named("server")
	server := grpc.NewServer(
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			startTime := time.Now()
			serverLogger.Info("Processing unary gRPC call", "grpc.method", info.FullMethod)
			serverLogger.Debug("Request contents", "req", req)
			resp, err := handler(ctx, req)
			serverLogger.Info("Finished unary gRPC call", "grpc.method", info.FullMethod, "grpc.time", time.Since(startTime), "grpc.code", status.Code(err), "err", err)
			return resp, err
		}),
	)

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-c
		logger.Info(fmt.Sprintf("Caught signal %s, shutting down", sig))
		server.GracefulStop()
	}()

	listener, err := listen(logger, *endpoint)
	if err != nil {
		return err
	}
	defer listener.Close()

	s := &providerserver.Server{
		Logger:       serverLogger,
		VaultAddr:    *vaultAddr,
		VaultMount:   *vaultMount,
		WriteSecrets: *writeSecrets,
	}
	pb.RegisterCSIDriverProviderServer(server, s)

	// Create health handler
	mux := http.NewServeMux()
	ms := http.Server{
		Addr:    *healthAddr,
		Handler: mux,
	}
	defer func() {
		err := ms.Shutdown(context.Background())
		if err != nil {
			logger.Error("Error shutting down health handler", "err", err)
		}
	}()

	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Start health handler
	go func() {
		logger.Info("Starting health handler", "addr", *healthAddr)
		if err := ms.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Error with health handler", "error", err)
		}
	}()

	logger.Info("Starting gRPC server")
	err = server.Serve(listener)
	if err != nil {
		return fmt.Errorf("error running gRPC server: %w", err)
	}

	return nil
}

func listen(logger hclog.Logger, endpoint string) (net.Listener, error) {
	// Because the unix socket is created in a host volume (i.e. persistent
	// storage), it can persist from previous runs if the pod was not terminated
	// cleanly. Check if we need to clean up before creating a listener.
	_, err := os.Stat(endpoint)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to check for existence of unix socket: %w", err)
	} else if err == nil {
		logger.Info("Cleaning up pre-existing file at unix socket location", "endpoint", endpoint)
		err = os.Remove(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to clean up pre-existing file at unix socket location: %w", err)
		}
	}

	logger.Info("Opening unix socket", "endpoint", endpoint)
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on unix socket at %s: %v", endpoint, err)
	}

	return listener, nil
}
