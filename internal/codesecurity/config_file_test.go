package codesecurity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigFile_UnsupportedSchemaVersion(t *testing.T) {
	_, err := ParseConfigFile(`schema-version: v2.0
sast:
  use-default-rulesets: true
`)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedSchemaVersion)
}

func TestParseConfigFile_SchemaVersionV1WithoutMinorRejected(t *testing.T) {
	_, err := ParseConfigFile(`schema-version: v1
sast: {}
`)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedSchemaVersion)
}

func TestParseConfigFile_SchemaVersionV1Minor(t *testing.T) {
	y := `schema-version: v1.99
sast:
  use-default-rulesets: true
`
	f, err := ParseConfigFile(y)
	require.NoError(t, err)
	require.NotNil(t, f.Sast)
}

func TestParseConfigFile_MinimalSast(t *testing.T) {
	y := `
schema-version: v1.0
sast:
  use-default-rulesets: true
`
	f, err := ParseConfigFile(y)
	require.NoError(t, err)
	require.NotNil(t, f.Sast)
	require.NotNil(t, f.Sast.UseDefaultRulesets)
	assert.True(t, *f.Sast.UseDefaultRulesets)
}

func TestReadLocalConfigBytes_PrefersCodeSecurityYaml(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "static-analysis.datadog.yaml"), []byte("x"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte("preferred"), 0o600)
	require.NoError(t, err)
	b, err := ReadLocalConfigBytes(dir)
	require.NoError(t, err)
	assert.Equal(t, []byte("preferred"), b)
}

func TestReadLocalConfigBytes_NoFile(t *testing.T) {
	b, err := ReadLocalConfigBytes(t.TempDir())
	assert.NoError(t, err)
	assert.Nil(t, b)
}

func TestLoadLocalFile_ReturnsBasename(t *testing.T) {
	dir := t.TempDir()
	y := "schema-version: v1.0\nsast:\n  use-default-rulesets: true\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "code-security.datadog.yaml"), []byte(y), 0o600))

	f, base, err := LoadLocalFile(dir)
	require.NoError(t, err)
	assert.Equal(t, "code-security.datadog.yaml", base)
	require.NotNil(t, f)
	require.NotNil(t, f.Sast)
}

func TestIsLegacyConfigBasename(t *testing.T) {
	// Legacy filenames → true
	assert.True(t, IsLegacyConfigBasename("static-analysis.datadog.yaml"))
	assert.True(t, IsLegacyConfigBasename("static-analysis.datadog.yml"))
	// Empty basename (no file found) → treated as legacy so repositories without any
	// config file still receive AI SAST coverage via the fallback path.
	assert.True(t, IsLegacyConfigBasename(""))
	// SAIST-aware filenames → false
	assert.False(t, IsLegacyConfigBasename("code-security.datadog.yaml"))
	assert.False(t, IsLegacyConfigBasename("code-security.datadog.yml"))
}

func TestLoadLocalFile_LegacyFormatLoadsWithoutError(t *testing.T) {
	// Legacy static-analysis files (root rulesets: block, no schema-version or schema-version: v1)
	// are not parsed by datadog-saist for narrowing — the settings API converts them before SAIST
	// sees the merged config. LoadLocalFile should still read and return the file without error;
	// the resulting File has a nil Sast section so no YAML narrowing is applied.
	dir := t.TempDir()
	y := "rulesets:\n  - python-design\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "static-analysis.datadog.yml"), []byte(y), 0o600))

	f, base, err := LoadLocalFile(dir)
	require.NoError(t, err)
	assert.Equal(t, "static-analysis.datadog.yml", base)
	require.NotNil(t, f)
	assert.Nil(t, f.Sast) // no sast block — YAML narrowing is skipped
}
