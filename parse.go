package scfg

import (
	"bytes"
	"iter"
	"os"
)

func readLines(path string) (iter.Seq[[]byte], error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return func(yield func([]byte) bool) {
		var index int

		for len(data) > 0 {
			index = bytes.Index(data, []byte("\n"))
			if index == -1 {
				break
			}

			line := bytes.TrimSpace(data[:index])
			data = data[index+1:]

			if len(line) == 0 || line[0] == '#' {
				continue
			}

			hash := bytes.Index(line, []byte("#"))
			if hash != -1 {
				line = trimEnd(line[:hash])

				if len(line) == 0 {
					continue
				}
			}

			if !yield(line) {
				return
			}
		}
	}, nil
}

func nextSpace(b []byte) (int, int) {
	var (
		started bool
		start   int
		end     int
	)

	for index, char := range b {
		if char == ' ' || char == '\t' {
			if !started {
				started = true
				start = index
			}

			end = index
		} else if started {
			break
		}
	}

	if !started {
		return -1, -1
	}

	return start, end
}

func trimEnd(b []byte) []byte {
	return bytes.TrimRight(b, " \t\r")
}

func trimStart(b []byte) []byte {
	return bytes.TrimLeft(b, " \t")
}
