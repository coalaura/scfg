package scfg

import (
	"fmt"
	"strings"
)

func parseWords(line string) ([]string, error) {
	words := make([]string, 0, 4)

	var (
		word    strings.Builder
		quote   byte
		escaped bool
		started bool
	)

	flush := func() {
		if !started {
			return
		}

		words = append(words, word.String())

		word.Reset()

		started = false
	}

	for index := 0; index < len(line); index++ {
		character := line[index]

		if escaped {
			if !isEscapable(character) {
				word.WriteByte('\\')
			}

			word.WriteByte(character)

			escaped = false
			started = true

			continue
		}

		if character == '\\' {
			escaped = true
			started = true

			continue
		}

		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				word.WriteByte(character)
			}

			started = true

			continue
		}

		switch character {
		case '\'', '"':
			quote = character
			started = true
		case '#':
			flush()

			return words, nil
		case ' ', '\t', '\r':
			flush()
		case '=':
			if len(words) == 0 && started {
				flush()
			} else if len(words) == 1 && !started {
				continue
			} else {
				word.WriteByte(character)

				started = true
			}
		default:
			word.WriteByte(character)
			started = true
		}
	}

	if escaped {
		return nil, fmt.Errorf("unfinished escape")
	}

	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}

	flush()

	return words, nil
}

func isEscapable(character byte) bool {
	switch character {
	case '\\', '\'', '"', '#', '=', ' ', '\t', '\r':
		return true
	default:
		return false
	}
}
