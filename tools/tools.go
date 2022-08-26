//go:build tools

// This file ensures tool dependencies are kept in sync.  This is the
// recommended way of doing this according to
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
// To install the following tools at the version used by this repo run:
// $ make bootstrap
// or
// $ go generate -tags tools tools/tools.go

package tools

//go:generate go install github.com/golangci/golangci-lint/cmd/golangci-lint
//go:generate golangci-lint version
//go:generate go install mvdan.cc/gofumpt
//go:generate gofumpt --version
import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "mvdan.cc/gofumpt"
)
