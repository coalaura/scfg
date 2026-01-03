package scfg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func (s *Server) AuthMethod(home string, passphrase []byte) ([]ssh.AuthMethod, error) {
	if s.IdentityFile == "" {
		return nil, errors.New("no identity file")
	}

	keyPath := expandPath(home, s.IdentityFile)

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	var signer ssh.Signer

	if len(passphrase) > 0 {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, passphrase)
		if err != nil {
			return nil, err
		}
	} else {
		signer, err = ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, err
		}
	}

	return []ssh.AuthMethod{
		ssh.PublicKeys(signer),
	}, nil
}

func expandPath(home, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}

	if path == "~" {
		return home
	} else if path[0] == '~' && (path[1] == '/' || path[1] == '\\') {
		return filepath.Join(home, path[2:])
	}

	return path
}
