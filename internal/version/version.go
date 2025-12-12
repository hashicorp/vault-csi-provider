// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package version

import (
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// the following variables are meant to be set at build time from 'ldflags'
var (
	// Major version
	Major = ""
	// Minor version
	Minor = ""
	// Patch version
	Patch = ""
	// GitVersion is the git version relative or equal to the latest tag
	GitVersion = ""
	// GitCommit is the git commit hash at which the binary was built
	GitCommit = ""
	// GitTreeState is the state of the git tree at which the binary was built (clean or dirty)
	GitTreeState = ""
	// BuildDate is the date at which the binary was built
	BuildDate = ""
	// GoVersion is the version of Go used to build the binary
	GoVersion = ""
	// Compiler is the name of the compiler used to build the binary
	Compiler = ""
	// Platform is the platform for which the binary was built
	Platform = ""
	// MinDriverVersion is the minimum supported version of the driver
	MinDriverVersion = ""
)

// Info holds the build's version information.
type Info struct {
	Major            string `json:"major" yaml:"major"`
	Minor            string `json:"minor" yaml:"minor"`
	Patch            string `json:"patch" yaml:"patch"`
	GitVersion       string `json:"gitVersion" yaml:"gitVersion"`
	GitCommit        string `json:"gitCommit" yaml:"gitCommit"`
	GitTreeState     string `json:"gitTreeState" yaml:"gitTreeState"`
	BuildDate        string `json:"buildDate" yaml:"buildDate"`
	GoVersion        string `json:"goVersion" yaml:"goVersion"`
	Compiler         string `json:"compiler" yaml:"compiler"`
	Platform         string `json:"platform" yaml:"platform"`
	MinDriverVersion string `json:"minDriverVersion" yaml:"minDriverVersion"` // Minimum driver version the provider works with.
}

// String returns info as a human-friendly version string.
func (i *Info) String() string {
	return i.GitVersion
}

// Version returns the current version information.
func Version() *Info {
	return &Info{
		Major:            Major,
		Minor:            Minor,
		Patch:            Patch,
		GitVersion:       GitVersion,
		GitCommit:        GitCommit,
		GitTreeState:     GitTreeState,
		BuildDate:        BuildDate,
		GoVersion:        GoVersion,
		Compiler:         Compiler,
		Platform:         Platform,
		MinDriverVersion: MinDriverVersion,
	}
}

// MarshalJSON returns the JSON encoding of Info. Useful for pretty printing.
func (i *Info) MarshalJSON(pretty bool) ([]byte, error) {
	var b []byte
	var err error
	if pretty {
		b, err = json.MarshalIndent(*i, "", "  ")
	} else {
		b, err = json.Marshal(*i)
	}

	if err != nil {
		return nil, err
	}
	return b, nil

}

// MarshalYAML returns the YAML encoding of Info. Useful for pretty printing.
func (i *Info) MarshalYAML() ([]byte, error) {
	b, err := yaml.Marshal(*i)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Print prints the version information in the specified format to the given writer.
func (i *Info) Print(format string, w io.WriteCloser) error {
	var output []byte
	var err error
	switch format {
	case "yaml":
		output, err = i.MarshalYAML()
	case "json":
		output, err = i.MarshalJSON(false)
	case "json-pretty":
		output, err = i.MarshalJSON(true)
	default:
		output = []byte(fmt.Sprintf("%#v\n", i))
	}

	if err != nil {
		return err
	}
	_, _ = w.Write(append(output, []byte("\n")...))
	return nil
}
