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
	"github.com/stretchr/testify/assert"
)

// TestRelatedFilesAppearsInPromptAfterIndexing verifies that the pipeline ordering
// fix works end-to-end: tree-sitter indexing must populate aiContext before
// buildScanDataForResults assembles the prompt, so that cross-file references
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

	results, err := determineApplicableRules(ctx, files, ruleProcessor)
	assert.NoError(t, err)

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
	err = buildScanDataForResults(ctx, results, ruleProcessor)
	assert.NoError(t, err)

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
