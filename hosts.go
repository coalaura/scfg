package scfg

import (
	"os"
	"path/filepath"
)

type KnownHost struct {
	Type        string
	Fingerprint string
}

type KnownHosts map[string][]KnownHost

func ParseKnownHosts(home string) (KnownHosts, error) {
	hosts := make(KnownHosts)

	path := filepath.Join(home, ".ssh", "known_hosts")

	lines, err := readLines(path)
	if err != nil {
		if os.IsNotExist(err) {
			return hosts, nil
		}

		return nil, err
	}

	for line := range lines {
		start, end := nextSpace(line)
		if start == -1 {
			continue
		}

		host := line[:start]
		line = line[end+1:]

		start, end = nextSpace(line)
		if start == -1 {
			continue
		}

		typ := line[:start]
		line = trimEnd(line[end+1:])

		if len(line) == 0 {
			continue
		}

		key := string(host)

		hosts[key] = append(hosts[key], KnownHost{
			Type:        string(typ),
			Fingerprint: string(line),
		})
	}

	return hosts, nil
}
