// Package codesecurity parses the Code Security YAML sast subset used by SAIST so local
// datadog-saist runs can honor the same repo config files as code-workload-runner (dd-source).
package codesecurity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Local config filenames (same order as code-workload-runner/saist readLocalConfigFile).
var localConfigFilenames = []string{
	"code-security.datadog.yaml",
	"code-security.datadog.yml",
	"static-analysis.datadog.yaml",
	"static-analysis.datadog.yml",
}

// File represents the parts of a v1 Code Security file we need for SAIST scoping.
type File struct {
	SchemaVersion string `yaml:"schema-version"`
	Sast          *Sast  `yaml:"sast,omitempty"`
}

// Sast mirrors saconfig.YamlSastConfigV1_0 path-related fields.
type Sast struct {
	UseDefaultRulesets *bool                         `yaml:"use-default-rulesets,omitempty"`
	UseRulesets        *[]string                     `yaml:"use-rulesets,omitempty"`
	IgnoreRulesets     *[]string                     `yaml:"ignore-rulesets,omitempty"`
	RulesetConfigs     *map[string]YamlRulesetConfig `yaml:"ruleset-configs,omitempty"`
	GlobalConfig       *YamlGlobalConfig             `yaml:"global-config,omitempty"`
}

// YamlGlobalConfig mirrors saconfig.YamlGlobalConfigV1_0 (path fields only).
type YamlGlobalConfig struct {
	OnlyPaths   *[]string `yaml:"only-paths,omitempty"`
	IgnorePaths *[]string `yaml:"ignore-paths,omitempty"`
}

// YamlRulesetConfig mirrors saconfig.YamlRulesetConfigV1_0 (path fields only).
type YamlRulesetConfig struct {
	OnlyPaths   *[]string                  `yaml:"only-paths,omitempty"`
	IgnorePaths *[]string                  `yaml:"ignore-paths,omitempty"`
	RuleConfigs *map[string]YamlRuleConfig `yaml:"rule-configs,omitempty"`
}

// YamlRuleConfig mirrors saconfig.YamlRuleConfigV1_0 (path fields only).
type YamlRuleConfig struct {
	OnlyPaths   *[]string `yaml:"only-paths,omitempty"`
	IgnorePaths *[]string `yaml:"ignore-paths,omitempty"`
}

// ReadLocalConfigBytes reads the first existing local config file in directory, or nil if none.
func ReadLocalConfigBytes(directory string) ([]byte, error) {
	for _, name := range localConfigFilenames {
		p := filepath.Join(directory, name)
		b, err := os.ReadFile(p) //nolint:gosec // intentional repo config read
		if err == nil {
			return b, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
	}
	return nil, nil
}

// ParseConfigFile decodes YAML into File. Unknown top-level keys are ignored (KnownFields=false).
func ParseConfigFile(content string) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(content))
	dec.KnownFields(false)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse Code Security YAML: %w", err)
	}
	return &f, nil
}

// LoadLocalFile reads and parses the local Code Security file when present.
// Returns (nil, nil) when no config file exists.
func LoadLocalFile(directory string) (*File, error) {
	b, err := ReadLocalConfigBytes(directory)
	if err != nil || len(b) == 0 {
		return nil, err
	}
	return ParseConfigFile(string(b))
}
