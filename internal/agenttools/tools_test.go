package agenttools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadFileRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	sandbox, err := NewSandbox(root)
	assert.NoError(t, err)
	output := Execute(sandbox, "read_file", `{"path":"../secret.go"}`)
	assert.Contains(t, output, "escapes repository root")
}

func TestSearchAndReadFile(t *testing.T) {
	root := t.TempDir()
	err := os.WriteFile(filepath.Join(root, "handler.go"), []byte("func dangerous(input string) {}\n"), 0600)
	assert.NoError(t, err)
	sandbox, err := NewSandbox(root)
	assert.NoError(t, err)
	search := Execute(sandbox, "search_code", `{"query":"dangerous"}`)
	assert.Contains(t, search, "handler.go")
	read := Execute(sandbox, "read_file", `{"path":"handler.go"}`)
	assert.True(t, strings.Contains(read, "1: func dangerous"))
}
