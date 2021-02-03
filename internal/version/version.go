package version

import (
	"encoding/json"
)

const minDriverVersion = "v0.0.17"

var (
	// BuildDate is date when binary was built
	BuildDate string
	// BuildVersion is the version of binary
	BuildVersion string
)

// providerVersion holds current provider version
type providerVersion struct {
	Version   string `json:"version"`
	BuildDate string `json:"buildDate"`
	// MinDriverVersion is minimum driver version the provider works with
	MinDriverVersion string `json:"minDriverVersion"`
}

func GetVersion() (string, error) {
	pv := providerVersion{
		Version:          BuildVersion,
		BuildDate:        BuildDate,
		MinDriverVersion: minDriverVersion,
	}

	res, err := json.Marshal(pv)
	if err != nil {
		return "", err
	}

	return string(res), nil
}
