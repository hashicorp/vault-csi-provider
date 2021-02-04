package version

import (
	"fmt"
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	BuildDate = "Now"
	BuildVersion = "version"
	GoVersion = "go version x.y.z"

	v, err := GetVersion()

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	expected := fmt.Sprintf(`{"version":"version","buildDate":"Now","goVersion":"go version x.y.z","minDriverVersion":"%s"}`, minDriverVersion)
	if !strings.EqualFold(v, expected) {
		t.Fatalf("string doesn't match, expected %s, got %s", expected, v)
	}
}
