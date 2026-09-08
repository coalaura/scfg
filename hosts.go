package scfg

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type KnownHost struct {
	Marker      string
	Hosts       []string
	Type        string
	Fingerprint string
	key         ssh.PublicKey
}

type KnownHosts map[string][]KnownHost

type HostKeyVerifier struct {
	callback ssh.HostKeyCallback
}

func (h KnownHosts) Entries() []KnownHost {
	count := 0

	for _, entries := range h {
		count += len(entries)
	}

	result := make([]KnownHost, 0, count)

	for _, entries := range h {
		result = append(result, entries...)
	}

	return result
}

func (h KnownHosts) HostKeyCallback() ssh.HostKeyCallback {
	plainKeyCallback := func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		if h.keyRevoked(key) {
			return &knownhosts.RevokedError{Revoked: knownhosts.KnownKey{Key: key}}
		}

		if h.keyAccepted(hostname, key, "") {
			return nil
		}

		return unknownHostKeyError(hostname, key)
	}

	checker := ssh.CertChecker{
		HostKeyFallback: plainKeyCallback,
		IsHostAuthority: func(authority ssh.PublicKey, address string) bool {
			return !h.keyRevoked(authority) && h.keyAccepted(address, authority, "@cert-authority")
		},
		IsRevoked: func(certificate *ssh.Certificate) bool {
			return h.keyRevoked(certificate)
		},
	}

	return checker.CheckHostKey
}

func (v *HostKeyVerifier) HostKeyCallback() ssh.HostKeyCallback {
	if v != nil && v.callback != nil {
		return v.callback
	}

	return rejectUnknownHostKey
}

func ParseKnownHosts(home string) (KnownHosts, error) {
	path := filepath.Join(home, ".ssh", "known_hosts")
	hosts := make(KnownHosts)

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return hosts, nil
		}

		return nil, err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}

		entry, parseErr := parseKnownHostLine(line)
		if parseErr != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber, parseErr)
		}

		pattern := strings.Join(entry.Hosts, ",")
		hosts[pattern] = append(hosts[pattern], entry)
	}

	err = scanner.Err()
	if err != nil {
		return nil, fmt.Errorf("read known_hosts: %w", err)
	}

	return hosts, nil
}

func ParseHostKeyVerifier(home string) (*HostKeyVerifier, error) {
	path := filepath.Join(home, ".ssh", "known_hosts")

	callback, err := knownhosts.New(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &HostKeyVerifier{callback: rejectUnknownHostKey}, nil
		}

		return nil, fmt.Errorf("parse known_hosts: %w", err)
	}

	return &HostKeyVerifier{callback: callback}, nil
}

func (h KnownHosts) keyAccepted(hostname string, key ssh.PublicKey, marker string) bool {
	normalized := knownhosts.Normalize(hostname)
	wantKey := key.Marshal()

	for patterns, entries := range h {
		if !matchKnownHostPatterns(patterns, normalized) {
			continue
		}

		for entryIndex := range entries {
			entry := &entries[entryIndex]
			if entry.Marker != marker {
				continue
			}

			entryKey := entry.publicKey()
			if entryKey == nil || entryKey.Type() != key.Type() {
				continue
			}

			if subtle.ConstantTimeCompare(entryKey.Marshal(), wantKey) == 1 {
				return true
			}
		}
	}

	return false
}

func (h KnownHosts) keyRevoked(key ssh.PublicKey) bool {
	wantKey := key.Marshal()

	for _, entries := range h {
		for entryIndex := range entries {
			entry := &entries[entryIndex]
			if entry.Marker != "@revoked" {
				continue
			}

			entryKey := entry.publicKey()
			if entryKey != nil && subtle.ConstantTimeCompare(entryKey.Marshal(), wantKey) == 1 {
				return true
			}
		}
	}

	return false
}

func (h KnownHost) publicKey() ssh.PublicKey {
	if h.key != nil {
		return h.key
	}

	text := h.Type + " " + h.Fingerprint

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return nil
	}

	return key
}

func parseKnownHostLine(line string) (KnownHost, error) {
	fields := strings.Fields(line)
	entry := KnownHost{}

	if len(fields) > 0 && strings.HasPrefix(fields[0], "@") {
		entry.Marker = fields[0]
		fields = fields[1:]
	}

	if entry.Marker != "" && entry.Marker != "@revoked" && entry.Marker != "@cert-authority" {
		return entry, fmt.Errorf("unsupported marker %q", entry.Marker)
	}

	if len(fields) < 3 {
		return entry, fmt.Errorf("malformed known_hosts entry")
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fields[1] + " " + fields[2]))
	if err != nil {
		return entry, fmt.Errorf("invalid host key: %w", err)
	}

	entry.Hosts = strings.Split(fields[0], ",")
	entry.Type = fields[1]
	entry.Fingerprint = fields[2]
	entry.key = key

	return entry, nil
}

func matchKnownHostPatterns(patterns, hostname string) bool {
	matched := false

	for pattern := range strings.SplitSeq(patterns, ",") {
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = pattern[1:]
		}

		if !matchKnownHostPattern(pattern, hostname) {
			continue
		}

		if negated {
			return false
		}

		matched = true
	}

	return matched
}

func matchKnownHostPattern(pattern, hostname string) bool {
	if strings.HasPrefix(pattern, "|1|") {
		return matchHashedHost(pattern, hostname)
	}

	return matchHostPattern(pattern, hostname)
}

func matchHashedHost(pattern, hostname string) bool {
	parts := strings.Split(pattern, "|")
	if len(parts) != 4 || parts[1] != "1" {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	hash := hmac.New(sha1.New, salt)
	_, _ = hash.Write([]byte(hostname))
	actual := hash.Sum(nil)

	return subtle.ConstantTimeCompare(actual, want) == 1
}

func unknownHostKeyError(hostname string, key ssh.PublicKey) error {
	return fmt.Errorf("unknown host key for %s: %s %s", hostname, key.Type(), ssh.FingerprintSHA256(key))
}

func rejectUnknownHostKey(hostname string, _ net.Addr, key ssh.PublicKey) error {
	return unknownHostKeyError(hostname, key)
}
