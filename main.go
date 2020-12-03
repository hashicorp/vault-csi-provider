package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	pb "sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

var (
	endpoint = pflag.String("endpoint", "/tmp/vault.sock", "path to socket on which to listen for driver gRPC calls")
	debug    = pflag.Bool("debug", false, "sets log to debug level")
	version  = pflag.Bool("version", false, "prints the version information")
)

const minDriverVersion = "v0.0.8"

// LogHook is used to setup custom hooks
type LogHook struct {
	Writer    io.Writer
	Loglevels []log.Level
}

func main() {
	pflag.Parse()

	setupLogger()

	if *version {
		v, err := getVersion()
		if err != nil {
			log.Fatalf("failed to print version, err: %+v", err)
		}
		// print the version and exit
		fmt.Printf("%s\n", v)
		os.Exit(0)
	}

	server := grpc.NewServer()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-c
		log.Infof("Caught signal %s, shutting down", sig)
		server.GracefulStop()
	}()

	listener, err := net.Listen("unix", *endpoint)
	if err != nil {
		log.Fatalf("Failed to listen on unix socket at %s: %v", *endpoint, err)
	}
	defer listener.Close()
	log.Infof("Listening on %s", *endpoint)

	s := &ProviderServer{}
	pb.RegisterCSIDriverProviderServer(server, s)

	err = server.Serve(listener)
	if err != nil {
		log.Fatal(err)
	}
}

func HandleRequest(ctx context.Context, attributes, secrets, permission, targetPath string) (map[string]int, error) {
	var attrib, secret map[string]string
	var filePermission os.FileMode

	err := json.Unmarshal([]byte(attributes), &attrib)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal attributes, err: %v", err)
	}
	err = json.Unmarshal([]byte(secrets), &secret)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal secrets, err: %v", err)
	}
	err = json.Unmarshal([]byte(permission), &filePermission)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal file permission, err: %v", err)
	}

	provider, err := NewProvider()
	if err != nil {
		return nil, fmt.Errorf("[error] : %v", err)
	}

	versions, err := provider.MountSecretsStoreObjectContent(ctx, attrib, secret, targetPath, filePermission)
	if err != nil {
		return nil, fmt.Errorf("[error] : %v", err)
	}

	log.Info("Successfully handled mount request")

	return versions, nil
}

// setupLogger sets up hooks to redirect stdout and stderr
func setupLogger() {
	log.SetOutput(ioutil.Discard)

	// set log level
	log.SetLevel(log.InfoLevel)
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	// add hook to send info, debug, warn level logs to stdout
	log.AddHook(&LogHook{
		Writer: os.Stdout,
		Loglevels: []log.Level{
			log.InfoLevel,
			log.DebugLevel,
			log.WarnLevel,
		},
	})

	// add hook to send panic, fatal, error logs to stderr
	log.AddHook(&LogHook{
		Writer: os.Stderr,
		Loglevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
		},
	})
}

// Fire is called when logging function with current hook is called
// write to appropriate writer based on log level
func (hook *LogHook) Fire(entry *log.Entry) error {
	line, err := entry.String()
	if err != nil {
		return err
	}
	_, err = hook.Writer.Write([]byte(line))
	return err
}

// Levels defines log levels at which hook is triggered
func (hook *LogHook) Levels() []log.Level {
	return hook.Loglevels
}
