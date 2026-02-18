package utils

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestLoadDatadogDriverConfigSuccess(t *testing.T) {
	tmpDir := t.TempDir()

	configData := `{
		"files": {
			"file1.go": ["rule1", "rule2"],
			"file2.go": ["rule3"],
			"internal/utils/file3.go": ["rule4", "rule5", "rule6"]
		}
	}`

	configPath := filepath.Join(tmpDir, model.DatadogDriverConfigFilename)
	err := os.WriteFile(configPath, []byte(configData), 0644)
	assert.NoError(t, err)

	config, err := LoadDatadogDriverConfig(tmpDir)

	assert.NoError(t, err)
	assert.Len(t, config.Files, 3)
	assert.Contains(t, config.Files, "file1.go")
	assert.Contains(t, config.Files, "file2.go")
	assert.Contains(t, config.Files, "internal/utils/file3.go")
	assert.Equal(t, []string{"rule1", "rule2"}, config.Files["file1.go"])
	assert.Equal(t, []string{"rule3"}, config.Files["file2.go"])
	assert.Equal(t, []string{"rule4", "rule5", "rule6"}, config.Files["internal/utils/file3.go"])
}

func TestLoadDatadogDriverConfigFileNotPresent(t *testing.T) {
	tmpDir := t.TempDir()

	config, err := LoadDatadogDriverConfig(tmpDir)

	assert.Error(t, err)
	assert.Nil(t, config.Files)
	assert.True(t, errors.Is(err, os.ErrNotExist), "error should be os.ErrNotExist")
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoadDatadogDriverConfigUnmarshalError(t *testing.T) {
	tmpDir := t.TempDir()

	invalidJSON := `{
		"files": {"file1.go": ["rule1", "rule2",
	}`

	configPath := filepath.Join(tmpDir, model.DatadogDriverConfigFilename)
	err := os.WriteFile(configPath, []byte(invalidJSON), 0644)
	assert.NoError(t, err)

	config, err := LoadDatadogDriverConfig(tmpDir)

	assert.Error(t, err)
	assert.Nil(t, config.Files)

	var syntaxErr *json.SyntaxError
	assert.True(t, errors.As(err, &syntaxErr), "error should be json.SyntaxError")
	assert.Contains(t, err.Error(), "failed to unmarshal config file")
}
