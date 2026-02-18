package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/datadog-saist/internal/model"
)

// LoadDatadogDriverConfig loads the Datadog driver configuration from a JSON file in the repository
func LoadDatadogDriverConfig(path string) (model.DatadogDriverConfig, error) {
	var config model.DatadogDriverConfig

	configPath := filepath.Join(path, model.DatadogDriverConfigFilename)

	data, err := os.ReadFile(configPath) // nolint: gosec
	if err != nil {
		return config, fmt.Errorf("failed to read config file %s: %w", configPath, err)
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config file %s: %w", configPath, err)
	}

	return config, nil
}
