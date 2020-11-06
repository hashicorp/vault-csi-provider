package main

import (
	"strings"
	"testing"
)

func TestValidateFilePath(t *testing.T) {
	// Don't use filepath.Join to generate the test cases because it calls filepath.Clean
	// which simplifies some of the test cases into less interesting paths.
	for _, tc := range []string{
		"",
		".",
		"/",
		"bar",
		"bar/foo",
		"bar///foo",
		"./bar",
		"/foo/bar",
		"foo/bar\\baz",
	} {
		err := validateFilePath(tc)
		if err != nil {
			t.Fatalf("Expected no error for %q but got %s", tc, err)
		}
	}
}

func TestValidatePath_Malformed(t *testing.T) {
	for _, tc := range []string{
		"../bar",
		"foo/..",
		"foo/../../bar",
		"foo////..",
	} {
		err := validateFilePath(tc)
		if err == nil {
			t.Fatalf("Expected error for %q but got none", tc)
		}

		tc = strings.ReplaceAll(tc, "/", "\\")
		err = validateFilePath(tc)
		if err == nil {
			t.Fatalf("Expected error for %q but got none", tc)
		}
	}
}
