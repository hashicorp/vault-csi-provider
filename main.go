package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/golang/glog"
	"github.com/spf13/pflag"
)

var (
	attributes = pflag.String("attributes", "", "volume attributes")
	secrets    = pflag.String("secrets", "", "node publish ref secret")
	targetPath = pflag.String("targetPath", "", "Target path to write data.")
	permission = pflag.String("permission", "", "File permission")
)

func main() {
	pflag.Parse()

	ctx := context.Background()

	var attrib map[string]string
	var secret map[string]string
	var filePermission os.FileMode

	err := json.Unmarshal([]byte(*attributes), &attrib)
	if err != nil {
		glog.Fatalf("failed to unmarshal attributes, err: %v", err)
	}
	err = json.Unmarshal([]byte(*secrets), &secret)
	if err != nil {
		glog.Fatalf("failed to unmarshal secrets, err: %v", err)
	}
	err = json.Unmarshal([]byte(*permission), &filePermission)
	if err != nil {
		glog.Fatalf("failed to unmarshal file permission, err: %v", err)
	}

	provider, err := NewProvider()
	if err != nil {
		glog.Fatalf("[error] : %s", err)
	}
	err = provider.MountSecretsStoreObjectContent(ctx, attrib, secret, *targetPath, filePermission)
	if err != nil {
		glog.Fatalf("[error] : %s", err)
	}

	glog.Flush()
	os.Exit(0)
}
