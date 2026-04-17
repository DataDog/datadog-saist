package codesecurity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchFilesToRules_GlobOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(p, []byte("package main"), 0o600))

	rules := []api.AiPrompt{{
		ID:    "datadog/go-sqli",
		Globs: []string{"**/*.go"},
	}}
	files := []SourceFile{{
		RelPath: "main.go",
		AbsPath: p,
		Lang:    model.Go,
	}}
	m := MatchFilesToRules(files, rules)
	assert.Equal(t, []string{"datadog/go-sqli"}, m["main.go"])
}

func TestMatchFilesToRules_KeywordFilters(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "handler.go")
	require.NoError(t, os.WriteFile(p, []byte(`package x
func main() { db.Query("SELECT " + x) }`), 0o600))

	rules := []api.AiPrompt{{
		ID:                 "datadog/go-sqli",
		Globs:              []string{"**/*.go"},
		FileSearchKeywords: []string{"query"},
	}}
	files := []SourceFile{{RelPath: "handler.go", AbsPath: p, Lang: model.Go}}
	m := MatchFilesToRules(files, rules)
	assert.Contains(t, m["handler.go"], "datadog/go-sqli")

	require.NoError(t, os.WriteFile(p, []byte("package x\nfunc main() {}\n"), 0o600))
	m2 := MatchFilesToRules(files, rules)
	assert.Empty(t, m2["handler.go"])
}
