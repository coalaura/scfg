# scfg

Fast OpenSSH config resolver and known_hosts verifier.

### Usage

```go
package main

import (
	"fmt"
	"os"

	"github.com/coalaura/scfg"
	"golang.org/x/crypto/ssh"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	config, err := scfg.ParseResolver(home)
	if err != nil {
		panic(err)
	}

	server := config.Resolve("example")
	fmt.Printf("dial %s as %s\n", server.Addr(), server.DefaultUser())

	hosts, err := scfg.ParseHostKeyVerifier(home)
	if err != nil {
		panic(err)
	}

	clientConfig := ssh.ClientConfig{
		User:            server.DefaultUser(),
		HostKeyCallback: hosts.HostKeyCallback(),
	}
	_ = clientConfig
}
```

`ParseConfig` remains available as a compatibility view of literal `Host` aliases. Use `ParseResolver` when wildcard, negated pattern, include, or default semantics matter. `ParseHostKeyVerifier` uses `x/crypto/ssh/knownhosts` and fails closed for missing, empty, unknown, mismatched, and revoked host keys.

### Benchmarks

```
$ go test -v -bench BenchmarkConfig
goos: linux
goarch: amd64
pkg: github.com/coalaura/scfg
cpu: AMD Ryzen 7 7840U w/ Radeon(TM) 780M Graphics
BenchmarkConfig
BenchmarkConfig-16    	   55056	     26263 ns/op
PASS
ok  	github.com/coalaura/scfg	1.451s

$ go test -v -bench BenchmarkKnownHosts
goos: linux
goarch: amd64
pkg: github.com/coalaura/scfg
cpu: AMD Ryzen 7 7840U w/ Radeon(TM) 780M Graphics
BenchmarkKnownHosts
BenchmarkKnownHosts-16    	  107126	     11252 ns/op
PASS
ok  	github.com/coalaura/scfg	1.208s
```
