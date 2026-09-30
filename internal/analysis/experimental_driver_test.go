package analysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestExperimentalDriverBypassesLegacyOnlyWhenEnabled(t *testing.T) {
	directory := t.TempDir()
	assert.NoError(t, os.WriteFile(filepath.Join(directory, "main.go"), []byte("package main\nfunc f() {}"), 0600))
	ctx := context.Background()
	files, err := NewFileDiscoverer(directory, false).DiscoverFiles(ctx)
	if !assert.NoError(t, err) {
		return
	}
	aiContext := model.NewAiContextProject()
	opts := &model.AnalysisOptions{Directory: directory, Rules: []api.AiPrompt{
		{ID: "datadog/go-sqli", Globs: []string{"**/*.go"}, Content: "<code>"},
	}, DatadogDriver: &model.DatadogDriverConfig{Files: map[string][]string{"main.go": {"datadog/go-sqli"}}}}
	rp, err := NewRuleProcessor(nil, opts, &aiContext)
	if !assert.NoError(t, err) {
		return
	}
	results, err := rp.ProcessFileRulesBatched(files)
	assert.NoError(t, err)
	if !assert.Len(t, results, 1) {
		return
	}
	assert.NoError(t, rp.BuildScanDataForResult(ctx, &results[0]))
	assert.Empty(t, results[0].Scans)
	opts.ExperimentalDriverOnly = true
	rp, err = NewRuleProcessor(nil, opts, &aiContext)
	if !assert.NoError(t, err) {
		return
	}
	assert.NoError(t, rp.BuildScanDataForResult(ctx, &results[0]))
	assert.Len(t, results[0].Scans, 1)
	assert.Len(t, filterScanDataForDatadogDriver(opts.DatadogDriver.Files, results[0].Scans), 1)
	assert.Empty(t, filterScanDataForDatadogDriver(map[string][]string{}, results[0].Scans))
}

func TestExperimentalDriverIsRequired(t *testing.T) {
	_, err := RunConfiguredAnalysis(context.Background(), &model.AnalysisOptions{ExperimentalDriverOnly: true})
	assert.EqualError(t, err, "experimental driver-only scanning requires a driver")
}

func TestSingleStageRequiresExperimentalMode(t *testing.T) {
	_, err := RunConfiguredAnalysis(context.Background(), &model.AnalysisOptions{ExperimentalSingleStage: true})
	assert.EqualError(t, err, "single-stage scanning requires experimental driver-only mode")
}
