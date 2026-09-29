package main

import (
	"bytes"
	"context"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type rejectNetwork struct{ calls int }

func (r *rejectNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls++
	return nil, context.Canceled
}

func TestOfflineCommandNeedsNoModelCredentialsOrNetwork(t *testing.T) {
	t.Setenv("DATADOG_DRIVER_ENABLED", "")
	t.Setenv("OPENAI_BEARER_TOKEN", "")
	t.Setenv("OPENAI_API_KEY", "")
	dir := t.TempDir()
	rules := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc f() {}"), 0600))
	assert.NoError(t, os.WriteFile(filepath.Join(rules, "datadog-go-sqli.md"), []byte("SQL injection"), 0600))
	network := &rejectNetwork{}
	original := http.DefaultTransport
	http.DefaultTransport = network
	t.Cleanup(func() { http.DefaultTransport = original })
	var output, stderr bytes.Buffer
	err := run(context.Background(), []string{"--directory", dir, "--rules-directory", rules}, &output, &stderr)
	assert.NoError(t, err)
	assert.Equal(t, 0, network.calls)
	assert.Contains(t, output.String(), `"type":"summary"`)
	assert.Contains(t, stderr.String(), "1 candidate pairs")
}

func TestOutputDoesNotOverwriteExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.jsonl")
	assert.NoError(t, os.WriteFile(path, []byte("existing"), 0600))
	var stdout bytes.Buffer
	err := writeOutput(path, &stdout, func(w io.Writer) error { return nil })
	assert.Error(t, err)
	content, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.Equal(t, "existing", string(content))
}

func TestCommandRequiresExplicitRuleSource(t *testing.T) {
	var output, stderr bytes.Buffer
	err := run(context.Background(), []string{"--directory", t.TempDir()}, &output, &stderr)
	assert.ErrorContains(t, err, "provide exactly one")
	assert.Empty(t, output.String())
}

func TestCommandRecordsRuleSnapshotProvenance(t *testing.T) {
	t.Setenv("DATADOG_DRIVER_ENABLED", "")
	directory := t.TempDir()
	rulesFile := filepath.Join(t.TempDir(), "rules.json")
	assert.NoError(t, os.WriteFile(filepath.Join(directory, "main.go"), []byte("package main\nfunc f() {}"), 0600))
	assert.NoError(t, os.WriteFile(rulesFile, []byte(`[{"id":"datadog/go-sqli","globs":["**/*.go"],"file_search_keywords":["select"],"content":"actual prompt"}]`), 0600))
	var output, stderr bytes.Buffer
	err := run(context.Background(), []string{"--directory", directory, "--rules-json", rulesFile}, &output, &stderr)
	assert.NoError(t, err)
	assert.Contains(t, output.String(), `"rule_source":{"source":"unversioned-array"`)
	assert.Contains(t, output.String(), `"rules_sha256":`)
	assert.Contains(t, output.String(), `"candidate_pairs":1`)
}
