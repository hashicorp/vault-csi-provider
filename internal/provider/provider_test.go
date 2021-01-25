package provider

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestWriteSecret(t *testing.T) {
	l := hclog.NewNullLogger()
	for _, tc := range []struct {
		name       string
		file       string
		permission os.FileMode
		invalid    bool
	}{
		{
			name:       "simple case",
			file:       "foo",
			permission: 0644,
		},
		{
			name:       "validation error",
			file:       filepath.Join("..", "foo"),
			permission: 0644,
			invalid:    true,
		},
		{
			name:       "requires new directory",
			file:       filepath.Join("foo", "bar", "baz"),
			permission: 0644,
		},
		{
			name:       "only owner can read",
			file:       "foo",
			permission: 0600,
		},
	} {
		root, err := ioutil.TempDir(os.TempDir(), "")
		require.NoError(t, err)
		defer func() {
			err := os.RemoveAll(root)
			if err != nil {
				t.Log("Error cleaning up", err)
			}
		}()

		err = writeSecret(l, root, tc.file, "", tc.permission)
		if tc.invalid {
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must not contain any .. segments")
			continue
		}

		require.NoError(t, err)
		rootedPath := filepath.Join(root, tc.file)
		info, err := os.Stat(rootedPath)
		require.NoError(t, err)
		assert.Equal(t, tc.permission, info.Mode())
	}
}
