package scfg

import (
	"encoding/base64"
	"fmt"
	"iter"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

func (h KnownHosts) HostKeyCallback() ssh.HostKeyCallback {
	if len(h) == 0 {
		return ssh.InsecureIgnoreHostKey()
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		raw := remote.String()

		keyType := key.Type()
		keyPrint := base64.StdEncoding.EncodeToString(key.Marshal())

		for entry := range findKnownHosts(h, hostname, raw) {
			if entry.Type != keyType {
				continue
			}

			if entry.Fingerprint == keyPrint {
				return nil
			}
		}

		return fmt.Errorf("unknown host key for %s: %s %s", raw, keyType, keyPrint)
	}
}

func findKnownHosts(hosts KnownHosts, hostname, remote string) iter.Seq[KnownHost] {
	return func(yield func(KnownHost) bool) {
		for _, entry := range hosts[hostname] {
			if !yield(entry) {
				return
			}
		}

		host, port := splitHostPort(remote)
		if host == "" {
			return
		}

		if host != hostname {
			for _, entry := range hosts[host] {
				if !yield(entry) {
					return
				}
			}
		}

		if port == "" {
			return
		}

		for _, entry := range hosts[bracketHostPort(hostname, port)] {
			if !yield(entry) {
				return
			}
		}

		if host == hostname {
			return
		}

		for _, entry := range hosts[bracketHostPort(host, port)] {
			if !yield(entry) {
				return
			}
		}
	}
}

func splitHostPort(remote string) (string, string) {
	if remote == "" {
		return "", ""
	}

	if remote[0] == '[' {
		close := strings.IndexByte(remote, ']')
		if close <= 1 {
			return remote, ""
		}

		host := remote[1:close]

		if close+1 < len(remote) && remote[close+1] == ':' {
			return host, remote[close+2:]
		}

		return host, ""
	}

	colon := strings.LastIndexByte(remote, ':')
	if colon <= 0 || colon+1 >= len(remote) {
		return remote, ""
	}

	return remote[:colon], remote[colon+1:]
}

func bracketHostPort(host, port string) string {
	var result strings.Builder

	result.WriteByte('[')
	result.WriteString(host)
	result.WriteString("]:")
	result.WriteString(port)

	return result.String()
}
