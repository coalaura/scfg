# scfg

Fast ssh config and known_hosts parser.

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