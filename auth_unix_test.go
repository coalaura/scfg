//go:build !windows

package scfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthMethodRejectsUnsafePermissions(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "unsafe")

	writePrivateKey(t, path, nil)

	err := os.Chmod(path, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	server := Server{IdentityFile: path}

	_, err = server.AuthMethod(home, nil)
	if err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("error = %v, want unsafe permissions", err)
	}
}

func TestAuthMethodSkipsUnsafeIdentityWhenAnotherIsUsable(t *testing.T) {
	home := t.TempDir()
	unsafePath := filepath.Join(home, ".ssh", "unsafe")
	safePath := filepath.Join(home, ".ssh", "safe")

	writePrivateKey(t, unsafePath, nil)
	writePrivateKey(t, safePath, nil)

	err := os.Chmod(unsafePath, 0o644)
	if err != nil {
		t.Fatal(err)
	}

	server := Server{IdentityFiles: []string{unsafePath, safePath}}

	methods, err := server.AuthMethod(home, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(methods) != 1 {
		t.Fatalf("auth methods = %d, want 1", len(methods))
	}
}
