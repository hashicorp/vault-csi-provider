// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/go-hclog"

	"github.com/hashicorp/vault-csi-provider/internal/config"
	"github.com/stretchr/testify/require"
)

func TestListen(t *testing.T) {
	logger := hclog.NewNullLogger()
	dir, err := ioutil.TempDir("/tmp", "TestListen")
	require.NoError(t, err)
	endpoint := path.Join(dir, "vault.sock")
	defer func() {
		require.NoError(t, os.Remove(endpoint))
	}()

	// Works when no file in the way.
	l, err := listen(logger, endpoint)
	require.NoError(t, err)

	// Will replace existing file.
	require.NoError(t, l.Close())
	_, err = os.Create(endpoint)
	require.NoError(t, err)
}

func TestSetupLogger(t *testing.T) {
	tests := []struct {
		flags    config.FlagsConfig
		expected hclog.Level
	}{
		{config.FlagsConfig{Debug: true}, hclog.Debug}, // deprecated flag test
		{config.FlagsConfig{LogLevel: "trace"}, hclog.Trace},
		{config.FlagsConfig{LogLevel: "debug"}, hclog.Debug},
		{config.FlagsConfig{LogLevel: "info"}, hclog.Info},
		{config.FlagsConfig{LogLevel: "warn"}, hclog.Warn},
		{config.FlagsConfig{LogLevel: "error"}, hclog.Error},
		{config.FlagsConfig{LogLevel: "off"}, hclog.Off},
		{config.FlagsConfig{LogLevel: "no-level"}, hclog.Info},
		{config.FlagsConfig{Debug: true, LogLevel: "warn"}, hclog.Warn}, // if both set, LogLevel should take precedence
	}

	for _, tt := range tests {
		t.Run(string(tt.expected), func(t *testing.T) {
			logger := setupLogger(tt.flags)

			if logger.GetLevel() != tt.expected {
				t.Errorf("expected log level %v, got %v", tt.expected, logger.GetLevel())
			}
		})
	}
}
