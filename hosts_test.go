package scfg

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestKnownHostsCommonForms(t *testing.T) {
	home := t.TempDir()

	key := newTestPublicKey(t)
	secondKey := newTestPublicKey(t)

	hashed := knownhosts.HashHostname("hashed.example")

	keyText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	lines := strings.Join([]string{
		knownhosts.Line([]string{"one.example", "two.example"}, key),
		knownhosts.Line([]string{"one.example"}, secondKey),
		knownhosts.Line([]string{"[port.example]:2222"}, key),
		hashed + " " + keyText,
		"*.wild.example " + keyText,
	}, "\n")

	writeTestFile(t, filepath.Join(home, ".ssh", "known_hosts"), lines)

	hosts, err := ParseKnownHosts(home)
	if err != nil {
		t.Fatal(err)
	}

	if len(hosts.Entries()) != 5 {
		t.Fatalf("entries = %d, want 5", len(hosts.Entries()))
	}

	callback := hosts.HostKeyCallback()

	assertHostKeyAccepted(t, callback, "two.example:22", 22, key)
	assertHostKeyAccepted(t, callback, "one.example:22", 22, secondKey)
	assertHostKeyAccepted(t, callback, "port.example:2222", 2222, key)
	assertHostKeyAccepted(t, callback, "hashed.example:22", 22, key)
	assertHostKeyAccepted(t, callback, "node.wild.example:22", 22, key)

	verifier, err := ParseHostKeyVerifier(home)
	if err != nil {
		t.Fatal(err)
	}

	assertHostKeyAccepted(t, verifier.HostKeyCallback(), "hashed.example:22", 22, key)
}

func TestKnownHostsUnknownAndMissingFailClosed(t *testing.T) {
	key := newTestPublicKey(t)
	home := t.TempDir()

	hosts, err := ParseKnownHosts(home)
	if err != nil {
		t.Fatal(err)
	}

	err = hosts.HostKeyCallback()("unknown.example:22", testRemoteAddress(22), key)
	if err == nil {
		t.Fatal("missing known_hosts accepted an unknown key")
	}

	writeTestFile(t, filepath.Join(home, ".ssh", "known_hosts"), "")

	hosts, err = ParseKnownHosts(home)
	if err != nil {
		t.Fatal(err)
	}

	err = hosts.HostKeyCallback()("unknown.example:22", testRemoteAddress(22), key)
	if err == nil {
		t.Fatal("empty known_hosts accepted an unknown key")
	}

	verifier, err := ParseHostKeyVerifier(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	err = verifier.HostKeyCallback()("unknown.example:22", testRemoteAddress(22), key)
	if err == nil {
		t.Fatal("missing verifier database accepted an unknown key")
	}
}

func TestKnownHostsRejectsRevokedKey(t *testing.T) {
	home := t.TempDir()

	key := newTestPublicKey(t)

	keyText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))

	writeTestFile(t, filepath.Join(home, ".ssh", "known_hosts"), "@revoked * "+keyText)

	hosts, err := ParseKnownHosts(home)
	if err != nil {
		t.Fatal(err)
	}

	err = hosts.HostKeyCallback()("revoked.example:22", testRemoteAddress(22), key)

	var revoked *knownhosts.RevokedError

	if !errors.As(err, &revoked) {
		t.Fatalf("error = %v, want RevokedError", err)
	}
}

func TestKnownHostsCertificateAuthority(t *testing.T) {
	home := t.TempDir()

	authority := newTestSigner(t)
	hostSigner := newTestSigner(t)

	certificate := &ssh.Certificate{
		Key:             hostSigner.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "test-host",
		ValidPrincipals: []string{"cert.example"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Minute).Unix()),
	}

	err := certificate.SignCert(rand.Reader, authority)
	if err != nil {
		t.Fatal(err)
	}

	authorityText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(authority.PublicKey())))

	writeTestFile(t, filepath.Join(home, ".ssh", "known_hosts"), "@cert-authority cert.example "+authorityText)

	hosts, err := ParseKnownHosts(home)
	if err != nil {
		t.Fatal(err)
	}

	assertHostKeyAccepted(t, hosts.HostKeyCallback(), "cert.example:22", 22, certificate)
}

func BenchmarkKnownHosts(b *testing.B) {
	home := b.TempDir()

	key := newBenchmarkPublicKey(b)

	line := knownhosts.Line([]string{"benchmark.example"}, key)

	writeBenchmarkFile(b, filepath.Join(home, ".ssh", "known_hosts"), line)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		hosts, err := ParseKnownHosts(home)
		if err != nil {
			b.Fatal(err)
		}

		_ = hosts
	}
}

func assertHostKeyAccepted(t *testing.T, callback ssh.HostKeyCallback, hostname string, port int, key ssh.PublicKey) {
	t.Helper()

	err := callback(hostname, testRemoteAddress(port), key)
	if err != nil {
		t.Fatalf("host %q was rejected: %v", hostname, err)
	}
}

func testRemoteAddress(port int) net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: port}
}

func newTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	signer := newTestSigner(t)

	return signer.PublicKey()
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	return signer
}

func newBenchmarkPublicKey(b *testing.B) ssh.PublicKey {
	b.Helper()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		b.Fatal(err)
	}

	return signer.PublicKey()
}

func writeBenchmarkFile(b *testing.B, path, content string) {
	b.Helper()

	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		b.Fatal(err)
	}

	err = os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		b.Fatal(err)
	}
}
