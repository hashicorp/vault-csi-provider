package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	BuildDate = "Now"
	BuildVersion = "version"

	v, err := getVersion()

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	expected := fmt.Sprintf(`{"version":"version","buildDate":"Now","minDriverVersion":"%s"}`, minDriverVersion)
	if !strings.EqualFold(v, expected) {
		t.Fatalf("string doesn't match, expected %s, got %s", expected, v)
	}
}
