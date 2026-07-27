//go:build darwin

package agenttools

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func openedFilePath(file *os.File) (string, error) {
	buffer := make([]byte, darwinPathMax)
	_, _, errno := syscall.Syscall(
		syscall.SYS_FCNTL,
		file.Fd(),
		uintptr(syscall.F_GETPATH),
		uintptr(unsafe.Pointer(&buffer[0])),
	)
	if errno != 0 {
		return "", fmt.Errorf("fcntl F_GETPATH: %w", errno)
	}
	if end := bytes.IndexByte(buffer, 0); end >= 0 {
		buffer = buffer[:end]
	}
	if len(buffer) == 0 {
		return "", fmt.Errorf("fcntl F_GETPATH returned an empty path")
	}
	return string(buffer), nil
}
