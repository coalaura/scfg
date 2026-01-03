# scfg

Fast ssh config and known_hosts parser.

### Usage

```go
package main

import (
	"fmt"
	"os"

	"github.com/coalaura/scfg"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	config, err := scfg.ParseConfig(home)
	if err != nil {
		panic(err)
	}

	for name, server := range config {
		fmt.Printf("%s: %v\n", name, server)
	}

	hosts, err := scfg.ParseKnownHosts(home)
	if err != nil {
		panic(err)
	}

	for host, known := range hosts {
		fmt.Printf("%s:\n", host)

		for _, entry := range known {
			fmt.Println(entry)
		}
	}
}
```

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