// Package codesecurity parses the Code Security YAML sast subset used by SAIST so local
// datadog-saist runs can honor the same repo config files as code-workload-runner (dd-source).
package codesecurity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrUnsupportedSchemaVersion is returned when schema-version is set but not a supported v1.x value.
var ErrUnsupportedSchemaVersion = errors.New(
	"unsupported schema-version: SAIST YAML narrowing supports v1.x (major 1) only; " +
		"parity with dd-source saconfig parseV1",
)

// Local config filenames (same order as code-workload-runner/saist readLocalConfigFile).
// static-analysis.datadog.* is legacy naming only; content is still decoded as the v1 subset below.
// Legacy-only schema (pre-Code Security v1) is not converted here; use v1-shaped YAML with sast: for narrowing.
var localConfigFilenames = []string{
	"code-security.datadog.yaml",
	"code-security.datadog.yml",
	"static-analysis.datadog.yaml",
	"static-analysis.datadog.yml",
}

// IsLegacyConfigBasename reports whether basename is a legacy config filename
// (static-analysis.datadog.*). An empty basename (no file found) is also treated as legacy
// so that repositories without any config file still receive AI SAST coverage.
func IsLegacyConfigBasename(basename string) bool {
	return basename == "" || basename == "static-analysis.datadog.yaml" || basename == "static-analysis.datadog.yml"
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

// readFirstLocalConfigFile returns the contents and basename of the first existing candidate file.
// If no file exists, returns nil, "", nil. Read errors other than not-exist are returned with basename set.
func readFirstLocalConfigFile(directory string) (content []byte, basename string, err error) {
	for _, name := range localConfigFilenames {
		p := filepath.Join(directory, name)
		b, rerr := os.ReadFile(p) //nolint:gosec // intentional repo config read
		if rerr == nil {
			return b, name, nil
		}
		if !os.IsNotExist(rerr) {
			return nil, name, fmt.Errorf("read %s: %w", name, rerr)
		}
	}
	return nil, "", nil
}

// ReadLocalConfigBytes reads the first existing local config file in directory, or nil if none.
func ReadLocalConfigBytes(directory string) ([]byte, error) {
	b, _, err := readFirstLocalConfigFile(directory)
	return b, err
}

// validateSchemaVersion checks schema-version when present, aligned with saconfig parseV1 major==1 rule.
// Empty schema-version is allowed so minimal repo files can still declare sast without tripping validation.
func validateSchemaVersion(s string) error {
	if s == "" {
		return nil
	}
	if s[0] != 'v' {
		return fmt.Errorf("%w: got %q", ErrUnsupportedSchemaVersion, s)
	}
	majorStr, minorStr, ok := strings.Cut(s[1:], ".")
	if !ok {
		return fmt.Errorf("%w: got %q (expected v1.0 form)", ErrUnsupportedSchemaVersion, s)
	}
	major, err := strconv.ParseUint(majorStr, 10, 8)
	if err != nil || major != 1 {
		return fmt.Errorf("%w: got %q", ErrUnsupportedSchemaVersion, s)
	}
	if _, err := strconv.ParseUint(minorStr, 10, 8); err != nil {
		return fmt.Errorf("%w: got %q", ErrUnsupportedSchemaVersion, s)
	}
	return nil
}

// ParseConfigFile decodes YAML into File. KnownFields(false) ignores extra top-level keys (sca, secrets, …)
// so real v1 repo files decode; unknown keys do not change behavior of modeled fields.
func ParseConfigFile(content string) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(content))
	dec.KnownFields(false)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse Code Security YAML: %w", err)
	}
	if err := validateSchemaVersion(f.SchemaVersion); err != nil {
		return nil, err
	}
	return &f, nil
}

// LoadLocalFile reads and parses the first existing local Code Security file in directory.
// Returns the parsed config, the basename of the file used (e.g. code-security.datadog.yaml), and an error.
// If no candidate file exists, or the file is empty, returns nil, "", nil.
// If parsing fails, returns nil, basename, err.
func LoadLocalFile(directory string) (*File, string, error) {
	b, name, err := readFirstLocalConfigFile(directory)
	if err != nil {
		return nil, name, err
	}
	if len(b) == 0 {
		return nil, "", nil
	}
	f, perr := ParseConfigFile(string(b))
	if perr != nil {
		return nil, name, perr
	}
	return f, name, nil
}
