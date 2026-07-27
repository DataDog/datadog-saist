//go:build linux

package agenttools

import (
	"fmt"
	"os"
)

func openedFilePath(file *os.File) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
}
