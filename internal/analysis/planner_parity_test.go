package analysis

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/codesecurity"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/planning"
	"github.com/DataDog/datadog-saist/internal/prefilter"
	"github.com/stretchr/testify/assert"
)

func TestPlannerMatchesLegacyScanDataAndYAMLKeywordIntersection(t *testing.T) {
	directory := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(directory, "main.go"),
		[]byte("package main\nfunc f() { db.Query(\"SELECT * FROM users\" + input) }"), 0600))
	assert.NoError(t, os.WriteFile(filepath.Join(directory, "code-security.datadog.yml"),
		[]byte("schema-version: v1.0\nsast:\n  use-rulesets:\n    - go-ai_sast\n"), 0600))
	rules := []api.AiPrompt{
		{ID: "datadog/go-sqli", Globs: []string{"**/*.go"}, FileSearchKeywords: []string{"absent_keyword"}, Content: "<code>"},
		{ID: "datadog/go-xss", Globs: []string{"**/*.go"}, Content: "<code>"},
	}
	ctx := context.Background()
	files, err := NewFileDiscoverer(directory, false).DiscoverFiles(ctx)
	if !assert.NoError(t, err) {
		return
	}
	aiContext := model.NewAiContextProject()
	rp, err := NewRuleProcessor(nil, &model.AnalysisOptions{Directory: directory, Rules: rules}, &aiContext)
	if !assert.NoError(t, err) {
		return
	}
	results, err := rp.ProcessFileRulesBatched(files)
	assert.NoError(t, err)
	if !assert.Len(t, results, 1) {
		return
	}
	assert.NoError(t, rp.BuildScanDataForResult(ctx, &results[0]))
	assert.Len(t, results[0].Scans, 1)
	oldMapping := codesecurity.MatchFilesToRules([]codesecurity.SourceFile{
		{RelPath: "main.go", AbsPath: filepath.Join(directory, "main.go"), Lang: model.Go},
	}, rules)
	scans := filterScanDataForDatadogDriver(oldMapping, results[0].Scans)
	assert.Empty(t, scans)
	var output bytes.Buffer
	summary, err := planning.Plan(ctx, planning.Options{Directory: directory, Rules: rules, Selector: prefilter.Legacy{}}, &output)
	assert.NoError(t, err)
	assert.Equal(t, len(scans), summary.SelectedPairs)
	assert.Equal(t, 2, summary.CandidatePairs)
}
