package scfg

import (
	"bytes"
	"iter"
	"os"
	"path/filepath"
)

type Server struct {
	HostName     string
	User         string
	Port         string
	IdentityFile string
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

			if len(key) < 4 || len(key) > 12 {
				// not our concern
				continue
			}

			value := TrimEnd(line[end+1:])

			if bytes.EqualFold(key, []byte("hostname")) {
				entry.HostName = string(value)
			} else if bytes.EqualFold(key, []byte("user")) {
				entry.User = string(value)
			} else if bytes.EqualFold(key, []byte("port")) {
				entry.Port = string(value)
			} else if bytes.EqualFold(key, []byte("identityfile")) {
				entry.IdentityFile = string(value)
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
