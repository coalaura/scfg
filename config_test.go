package scfg

import (
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type malformedConfigTest struct {
	name   string
	config string
}

func TestResolvePrecedencePatternsAndDefaults(t *testing.T) {
	home := t.TempDir()

	config := strings.Join([]string{
		"ForwardAgent no",
		"Host *.example.com !blocked.example.com",
		"  User wildcard",
		"  Port=2200",
		"  IdentityFile \"~/.ssh/key one\" # comment",
		"Host app.example.com",
		"  User late",
		"  IdentityFile=~/.ssh/key_two",
		"  IdentitiesOnly = yes",
		"  ProxyJump jump.example.com",
		"  ConnectTimeout 7",
		"Host node?",
		"  HostName question.example.com",
		"Host *",
		"  User fallback",
	}, "\n")

	writeTestFile(t, filepath.Join(home, ".ssh", "config"), config)

	resolver, err := ParseResolver(home)
	if err != nil {
		t.Fatal(err)
	}

	server := resolver.Resolve("app.example.com")
	if server.HostName != "app.example.com" || server.User != "wildcard" || server.Port != "2200" {
		t.Fatalf("unexpected resolved address: %#v", server)
	}

	wantIdentities := []string{"~/.ssh/key one", "~/.ssh/key_two"}
	if !reflect.DeepEqual(server.IdentityFiles, wantIdentities) {
		t.Fatalf("identities = %q, want %q", server.IdentityFiles, wantIdentities)
	}

	if server.IdentityFile != wantIdentities[0] || server.IdentitiesOnly != "yes" {
		t.Fatalf("unexpected identity compatibility fields: %#v", server)
	}

	if server.ProxyJump != "jump.example.com" || server.ForwardAgent != "no" {
		t.Fatalf("unexpected common options: %#v", server)
	}

	if server.Timeout(time.Minute) != 7*time.Second {
		t.Fatalf("timeout = %s", server.Timeout(time.Minute))
	}

	blocked := resolver.Resolve("blocked.example.com")
	if blocked.User != "fallback" || blocked.Port != "22" {
		t.Fatalf("negated host resolved incorrectly: %#v", blocked)
	}

	question := resolver.Resolve("node1")
	if question.HostName != "question.example.com" {
		t.Fatalf("question-mark pattern did not match: %#v", question)
	}
}

func TestResolveCurrentUserAndDefaultIdentities(t *testing.T) {
	home := t.TempDir()

	resolver, err := ParseResolver(home)
	if err != nil {
		t.Fatal(err)
	}

	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	server := resolver.Resolve("plain-host")
	if server.User != current.Username || server.DefaultUser() != current.Username {
		t.Fatalf("user = %q, want local user %q", server.User, current.Username)
	}

	if server.HostName != "plain-host" || server.Port != "22" || server.Addr() != "plain-host:22" {
		t.Fatalf("unexpected defaults: %#v", server)
	}

	want := defaultIdentityFiles()
	if !reflect.DeepEqual(server.IdentityFiles, want) {
		t.Fatalf("identities = %q, want %q", server.IdentityFiles, want)
	}
}

func TestIdentityFileNoneDisablesDefaults(t *testing.T) {
	home := t.TempDir()

	writeTestFile(t, filepath.Join(home, ".ssh", "config"), "Host no-key\nIdentityFile none")

	resolver, err := ParseResolver(home)
	if err != nil {
		t.Fatal(err)
	}

	server := resolver.Resolve("no-key")
	if len(server.IdentityFiles) != 0 || server.IdentityFile != "" {
		t.Fatalf("identities = %q, want none", server.IdentityFiles)
	}
}

func TestIncludesAreExpandedInPlace(t *testing.T) {
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")

	writeTestFile(t, filepath.Join(sshDirectory, "config"), "Include config.d/*.conf\nInclude ~/extra.conf\nHost *\n User fallback")
	writeTestFile(t, filepath.Join(sshDirectory, "config.d", "10-host.conf"), "Host included\n HostName \"target host\"\n User first")
	writeTestFile(t, filepath.Join(sshDirectory, "config.d", "20-host.conf"), "Host included\n User second\n Port 2222")
	writeTestFile(t, filepath.Join(home, "extra.conf"), "Host extra\nUser extra-user")

	resolver, err := ParseResolver(home)
	if err != nil {
		t.Fatal(err)
	}

	included := resolver.Resolve("included")
	if included.HostName != "target host" || included.User != "first" || included.Port != "2222" {
		t.Fatalf("included host = %#v", included)
	}

	extra := resolver.Resolve("extra")
	if extra.User != "extra-user" {
		t.Fatalf("tilde include was not applied: %#v", extra)
	}
}

func TestNestedRelativeIncludeUsesSSHDirectory(t *testing.T) {
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")

	writeTestFile(t, filepath.Join(sshDirectory, "config"), "Include config.d/outer.conf")
	writeTestFile(t, filepath.Join(sshDirectory, "config.d", "outer.conf"), "Include nested.conf")
	writeTestFile(t, filepath.Join(sshDirectory, "nested.conf"), "Host nested\nUser root-relative")

	resolver, err := ParseResolver(home)
	if err != nil {
		t.Fatal(err)
	}

	nested := resolver.Resolve("nested")
	if nested.User != "root-relative" {
		t.Fatalf("nested include resolved to wrong directory: %#v", nested)
	}
}

func TestIncludeCycleFails(t *testing.T) {
	home := t.TempDir()
	sshDirectory := filepath.Join(home, ".ssh")

	writeTestFile(t, filepath.Join(sshDirectory, "config"), "Include other.conf")
	writeTestFile(t, filepath.Join(sshDirectory, "other.conf"), "Include config")

	_, err := ParseResolver(home)
	if err == nil || !strings.Contains(err.Error(), "include cycle") {
		t.Fatalf("error = %v, want include cycle", err)
	}
}

func TestConfigFinalLineWithoutNewlineAndCompatibilityView(t *testing.T) {
	home := t.TempDir()

	writeTestFile(t, filepath.Join(home, ".ssh", "config"), "Host alias\nHostName=destination")

	config, err := ParseConfig(home)
	if err != nil {
		t.Fatal(err)
	}

	server := config["alias"]
	if server == nil || server.HostName != "destination" {
		t.Fatalf("alias = %#v", server)
	}
}

func TestMalformedConfigFails(t *testing.T) {
	tests := []malformedConfigTest{
		{name: "quote", config: "Host example\nUser \"unfinished"},
		{name: "escape", config: "Host example\nUser unfinished\\"},
		{name: "host", config: "Host"},
		{name: "port", config: "Host example\nPort 70000"},
		{name: "boolean", config: "Host example\nIdentitiesOnly maybe"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()

			writeTestFile(t, filepath.Join(home, ".ssh", "config"), test.config)

			_, err := ParseResolver(home)
			if err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestUnsupportedMatchBodyIsIgnored(t *testing.T) {
	home := t.TempDir()
	config := "Match host privileged-*\nUser root\nIdentityFile ~/.ssh/privileged\nHost *\nUser deploy"

	writeTestFile(t, filepath.Join(home, ".ssh", "config"), config)

	resolver, err := ParseResolver(home)
	if err != nil {
		t.Fatal(err)
	}

	server := resolver.Resolve("ordinary")
	if server.User != "deploy" {
		t.Fatalf("unsupported Match body leaked into host: %#v", server)
	}

	if len(server.IdentityFiles) != len(defaultIdentityFiles()) {
		t.Fatalf("unsupported Match identity leaked into host: %q", server.IdentityFiles)
	}
}

func BenchmarkConfig(b *testing.B) {
	home := b.TempDir()
	path := filepath.Join(home, ".ssh", "config")

	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		b.Fatal(err)
	}

	err = os.WriteFile(path, []byte("Host *.example.com\n User deploy\n Port 2222\nHost *\n ForwardAgent no\n"), 0o600)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		resolver, parseErr := ParseResolver(home)
		if parseErr != nil {
			b.Fatal(parseErr)
		}

		_ = resolver.Resolve("app.example.com")
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}
}
