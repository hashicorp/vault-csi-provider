// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"io/ioutil"
	"os"
	"path"
	"testing"

	"github.com/hashicorp/go-hclog"

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
