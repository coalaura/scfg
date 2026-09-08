//go:build windows

package scfg

import (
	"fmt"
	"os"
)

func checkPrivateKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("identity %q is not a regular file", path)
	}

	return nil
}
