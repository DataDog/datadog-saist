package codesecurity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
