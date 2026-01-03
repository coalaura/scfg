package scfg

import (
	"os"
	"testing"
)

func BenchmarkConfig(b *testing.B) {
	home, err := os.UserHomeDir()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for b.Loop() {
		_, err = ParseConfig(home)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKnownHosts(b *testing.B) {
	home, err := os.UserHomeDir()
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()

	for b.Loop() {
		_, err = ParseKnownHosts(home)
		if err != nil {
			b.Fatal(err)
		}
	}
}
