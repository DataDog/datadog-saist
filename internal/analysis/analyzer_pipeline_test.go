package analysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

// TestRelatedFilesAppearsInPromptAfterIndexing verifies that the pipeline ordering
// fix works end-to-end: tree-sitter indexing must populate aiContext before
// BuildScanDataForResult assembles the prompt, so that cross-file references
// appear inside the rendered <relatedFilesInformation> section.
//
// Prior to the fix, BuildScanDataForResult was called before indexFilesForContext,
// so aiContext was always empty at prompt-assembly time and the related-files
// section was never populated.
func TestRelatedFilesAppearsInPromptAfterIndexing(t *testing.T) {
	tmpDir := t.TempDir()

	// helper.go defines unsafeQuery — the vulnerable function.
	helperContent := `package main

import "database/sql"

func unsafeQuery(db *sql.DB, userInput string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = '" + userInput + "'")
}
`
	// main.go calls unsafeQuery from an HTTP handler, passing user-controlled input.
	// This is the cross-file taint that the LLM needs to see.
	mainContent := `package main

import (
	"database/sql"
	"net/http"
)

func handler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	_, _ = unsafeQuery(db, r.URL.Query().Get("name"))
}

func main() {}
`

	err := os.WriteFile(filepath.Join(tmpDir, "helper.go"), []byte(helperContent), 0600)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainContent), 0600)
	assert.NoError(t, err)

	rule := api.AiPrompt{
		ID: "test/go-sqli",
		Content: "Analyze the following Go file for SQL injection.\n\n" +
			"Path: <path>\n\n```\n<code>\n```\n\n<relatedFilesInformation>\n\n" +
			"Report any vulnerabilities.",
		Globs:    []string{"**/*.go"},
		Severity: api.SeverityError,
		Category: api.CategorySecurity,
	}

	opts := &model.AnalysisOptions{
		Directory:       tmpDir,
		Rules:           []api.AiPrompt{rule},
		FileConcurrency: 4,
		SkipIndexing:    false,
	}

	aiContext := model.NewAiContextProject()
	ctx := ContextWithShimmedLogger(context.Background(), log.NewDefaultLogger())

	// Phase 1: determine applicable rules (Scans still nil at this point).
	files := []fileMeta{
		{RelPath: "helper.go", AbsPath: filepath.Join(tmpDir, "helper.go"), Language: model.Go},
		{RelPath: "main.go", AbsPath: filepath.Join(tmpDir, "main.go"), Language: model.Go},
	}

	ruleProcessor, err := NewRuleProcessor(nil, opts, &aiContext)
	assert.NoError(t, err)

	results := determineApplicableRules(ctx, files, ruleProcessor)

	// Confirm both files matched the rule before indexing.
	filesWithRules := 0
	for _, r := range results {
		if len(r.applicableRules) > 0 {
			filesWithRules++
		}
	}
	assert.Equal(t, 2, filesWithRules, "both files should have applicable rules")

	// Phase 2: index BEFORE building scan data (the fix).
	indexFilesForContext(ctx, tmpDir, files, &aiContext, false)

	// Phase 3: build scan data with populated aiContext.
	// (analyzeFiles now builds scan data inline per file in the scan loop; this
	// mirrors that by calling BuildScanDataForResult for each result.)
	for i := range results {
		if len(results[i].applicableRules) == 0 {
			continue
		}
		err = ruleProcessor.BuildScanDataForResult(ctx, &results[i])
		assert.NoError(t, err)
	}

	// Find the ScanData for helper.go and assert the prompt contains main.go's content.
	var helperPrompt string
	for _, res := range results {
		if res.RelPath == "helper.go" {
			for _, scan := range res.Scans {
				helperPrompt = scan.UserPrompt
			}
		}
	}

	assert.NotEmpty(t, helperPrompt, "helper.go should have a rendered prompt")
	assert.Contains(t, helperPrompt, "## Related Files",
		"prompt must contain the Related Files section")
	assert.Contains(t, helperPrompt, "### main.go",
		"prompt must reference main.go as a related file")
	assert.Contains(t, helperPrompt, `r.URL.Query().Get("name")`,
		"prompt must contain the cross-file taint source from main.go")
	assert.Equal(t, 1, strings.Count(helperPrompt, "## Related Files"),
		"Related Files header must appear exactly once")
}

func TestDriverWritesSkipOnlyArtifact(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	dir := t.TempDir()
	conditional := api.AiPrompt{
		ID:                 "test/conditional",
		Globs:              []string{"**/*.go"},
		FileSearchKeywords: []string{"package"},
		AnalysisFilter: &api.AnalysisFilter{
			Version:    api.AnalysisFilterVersion,
			Expression: api.FilterExpression{ContainsAny: []string{"missing"}},
		},
	}
	keyword := api.AiPrompt{
		ID:                 "test/keyword",
		Globs:              []string{"**/*.go"},
		FileSearchKeywords: []string{"missing"},
	}
	unrequested := keyword
	unrequested.ID = "test/unrequested"
	opts := &model.AnalysisOptions{
		Directory:         dir,
		Output:            filepath.Join(dir, "report.sarif"),
		DetectionModel:    model.OpenAIGPT5Mini,
		ValidationModel:   model.OpenAIGPT5Mini,
		OpenAIBaseURL:     "http://127.0.0.1:0",
		RequestTimeoutSec: 1,
		FileConcurrency:   1,
		SkipIndexing:      true,
		Rules:             []api.AiPrompt{conditional, keyword, unrequested},
		DatadogDriver: &model.DatadogDriverConfig{Files: map[string][]string{
			"filtered.go": {"test/conditional", "test/keyword"},
			"removed.go":  {"test/conditional"},
			"unknown.go":  {"test/unknown"},
			"missing.go":  {"test/conditional"},
		}},
	}
	for _, name := range []string{"filtered.go", "removed.go", "unknown.go", "unrequested.go"} {
		if !assert.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("package example\n"), 0600)) {
			return
		}
	}

	ctx := ContextWithShimmedLogger(context.Background(), log.NewDefaultLogger())
	files, aiContext, err := processDirectory(ctx, opts)
	if !assert.NoError(t, err) || !assert.Len(t, files, 4) {
		return
	}
	if !assert.NoError(t, os.Remove(filepath.Join(dir, "removed.go"))) {
		return
	}
	results, err := analyzeFiles(ctx, files, opts, aiContext)
	if !assert.NoError(t, err) || !assert.NoError(t, writeCheckpoint(opts, results)) {
		return
	}

	report, err := sarif.Open(opts.Output)
	if !assert.NoError(t, err) || !assert.Len(t, report.Runs, 1) {
		return
	}
	run := report.Runs[0]
	assert.Empty(t, run.Results)
	if assert.Len(t, run.Artifacts, 1) {
		assert.Equal(t, "filtered.go", *run.Artifacts[0].Location.URI)
		assert.Equal(t, []any{"RULE_SKIPPED:test/conditional,test/keyword"}, run.Artifacts[0].Properties["tags"])
	}
}
