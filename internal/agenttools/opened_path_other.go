//go:build !darwin && !linux

package agenttools

import (
	"fmt"
	"os"
)

func openedFilePath(_ *os.File) (string, error) {
	return "", fmt.Errorf("opened descriptor path validation is unsupported on this platform")
}
