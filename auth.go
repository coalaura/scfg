package scfg

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func (s *Server) AuthMethod(home string, passphrase []byte) ([]ssh.AuthMethod, error) {
	identities := s.IdentityFiles
	usingDefaults := identities == nil && s.IdentityFile == ""

	if len(identities) == 0 && s.IdentityFile != "" {
		identities = []string{s.IdentityFile}
	}

	if usingDefaults {
		identities = defaultIdentityFiles()
	}

	signers := make([]ssh.Signer, 0, len(identities))

	var parseErrors []error

	for _, identity := range identities {
		keyPath := expandPath(home, identity)

		err := checkPrivateKeyPermissions(keyPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if !usingDefaults {
					parseErrors = append(parseErrors, fmt.Errorf("inspect identity %q: %w", keyPath, err))
				}

				continue
			}

			parseErrors = append(parseErrors, fmt.Errorf("inspect identity %q: %w", keyPath, err))

			continue
		}

		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			if usingDefaults && errors.Is(err, os.ErrNotExist) {
				continue
			}

			parseErrors = append(parseErrors, fmt.Errorf("read identity %q: %w", keyPath, err))

			continue
		}

		signer, err := parsePrivateKey(keyBytes, passphrase)
		if err != nil {
			parseErrors = append(parseErrors, fmt.Errorf("parse identity %q: %w", keyPath, err))

			continue
		}

		signers = append(signers, signer)
	}

	if len(signers) == 0 {
		if len(parseErrors) > 0 {
			return nil, errors.Join(parseErrors...)
		}

		return nil, errors.New("no usable identity file")
	}

	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

func parsePrivateKey(key, passphrase []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(key)
	if err == nil || len(passphrase) == 0 {
		return signer, err
	}

	return ssh.ParsePrivateKeyWithPassphrase(key, passphrase)
}

func defaultIdentityFiles() []string {
	return []string{
		"~/.ssh/id_rsa",
		"~/.ssh/id_ecdsa",
		"~/.ssh/id_ecdsa_sk",
		"~/.ssh/id_ed25519",
		"~/.ssh/id_ed25519_sk",
	}
}

func expandPath(home, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}

	if path == "~" {
		return home
	}

	if path[0] == '~' && len(path) > 1 && (path[1] == '/' || path[1] == '\\') {
		return filepath.Join(home, path[2:])
	}

	return path
}
