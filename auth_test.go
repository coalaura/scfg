package scfg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestAuthMethodLoadsMultipleIdentities(t *testing.T) {
	home := t.TempDir()
	first := filepath.Join(home, ".ssh", "first")
	second := filepath.Join(home, ".ssh", "second")

	writePrivateKey(t, first, nil)
	writePrivateKey(t, second, nil)

	server := Server{IdentityFiles: []string{"~/.ssh/missing", "~/.ssh/first", "~/.ssh/second"}}

	methods, err := server.AuthMethod(home, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(methods) != 1 {
		t.Fatalf("auth methods = %d, want 1", len(methods))
	}
}

func TestAuthMethodEncryptedIdentity(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "encrypted")

	passphrase := []byte("secret passphrase")

	writePrivateKey(t, path, passphrase)

	server := Server{IdentityFile: path}

	_, err := server.AuthMethod(home, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	_, err = server.AuthMethod(home, []byte("incorrect"))
	if err == nil {
		t.Fatal("encrypted key accepted an incorrect passphrase")
	}
}

func TestParseUnencryptedIdentityWithPassphrase(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".ssh", "plain")

	writePrivateKey(t, path, nil)

	key, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = parsePrivateKey(key, []byte("unused passphrase"))
	if err != nil {
		t.Fatalf("parse unencrypted key with supplied passphrase: %v", err)
	}
}

func TestAuthMethodNoDefaultIdentity(t *testing.T) {
	server := Server{}

	_, err := server.AuthMethod(t.TempDir(), nil)
	if err == nil {
		t.Fatal("expected no usable identity error")
	}
}

func TestAuthMethodIdentityFileNoneDisablesExistingDefault(t *testing.T) {
	home := t.TempDir()

	writePrivateKey(t, filepath.Join(home, ".ssh", "id_ed25519"), nil)
	writeTestFile(t, filepath.Join(home, ".ssh", "config"), "Host no-key\nIdentityFile none")

	resolver, err := ParseResolver(home)
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolver.Resolve("no-key").AuthMethod(home, nil)
	if err == nil {
		t.Fatal("IdentityFile none loaded a default identity")
	}
}

func writePrivateKey(t *testing.T, path string, passphrase []byte) {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var block *pem.Block

	if len(passphrase) == 0 {
		block, err = ssh.MarshalPrivateKey(privateKey, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "test", passphrase)
	}

	if err != nil {
		t.Fatal(err)
	}

	err = os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}
