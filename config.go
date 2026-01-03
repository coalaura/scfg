package scfg

import (
	"bytes"
	"iter"
	"os"
	"path/filepath"
)

type Server struct {
	HostName       string
	User           string
	Port           string
	ProxyJump      string
	IdentityFile   string
	ForwardAgent   string
	ConnectTimeout string
}

type Config map[string]*Server

func ParseConfig(home string) (Config, error) {
	config := make(Config)

	path := filepath.Join(home, ".ssh", "config")

	lines, err := ReadLines(path)
	if err != nil {
		if os.IsNotExist(err) {
			return config, nil
		}

		return nil, err
	}

	var (
		name  []byte
		entry *Server
	)

	push := func() {
		if entry == nil || len(entry.HostName) == 0 {
			name = nil
			entry = nil

			return
		}

		for key := range fields(name) {
			config[key] = entry
		}

		name = nil
		entry = nil
	}

	for line := range lines {
		if bytes.HasPrefix(line, []byte("Host ")) {
			push()

			name = TrimStart(line[5:])
			entry = &Server{}
		} else if entry != nil {
			start, end := NextSpace(line)
			if start == -1 {
				// weird line
				continue
			}

			key := line[:start]
			ln := len(key)

			if ln < 4 || ln > 14 {
				// not our concern
				continue
			}

			switch key[0] | 0x20 {
			case 'h':
				if ln == 8 && bytes.EqualFold(key, []byte("hostname")) {
					entry.HostName = string(TrimEnd(line[end+1:]))
				}
			case 'u':
				if ln == 4 && bytes.EqualFold(key, []byte("user")) {
					entry.User = string(TrimEnd(line[end+1:]))
				}
			case 'p':
				if ln == 4 && bytes.EqualFold(key, []byte("port")) {
					entry.Port = string(TrimEnd(line[end+1:]))
				} else if ln == 9 && bytes.EqualFold(key, []byte("proxyjump")) {
					entry.ProxyJump = string(TrimEnd(line[end+1:]))
				}
			case 'i':
				if ln == 12 && bytes.EqualFold(key, []byte("identityfile")) {
					entry.IdentityFile = string(TrimEnd(line[end+1:]))
				}
			case 'f':
				if ln == 12 && bytes.EqualFold(key, []byte("forwardagent")) {
					entry.ForwardAgent = string(TrimEnd(line[end+1:]))
				}
			case 'c':
				if ln == 14 && bytes.EqualFold(key, []byte("connecttimeout")) {
					entry.ConnectTimeout = string(TrimEnd(line[end+1:]))
				}
			}
		}
	}

	push()

	return config, nil
}

func fields(b []byte) iter.Seq[string] {
	return func(yield func(string) bool) {
		for len(b) > 0 {
			start, end := NextSpace(b)
			if start == -1 {
				break
			}

			field := b[:start]
			b = b[end+1:]

			if len(field) == 0 {
				continue
			}

			if !yield(string(field)) {
				return
			}
		}

		if len(b) > 0 {
			yield(string(b))
		}
	}
}
