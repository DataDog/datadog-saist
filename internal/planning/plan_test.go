package planning

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/prefilter"
	"github.com/stretchr/testify/assert"
)

func fixture(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	if !assert.NoError(t, os.WriteFile(filepath.Join(dir, "a.go"), []byte("package main\nfunc f() { db.Query(\"SELECT * FROM users\" + input) }"), 0600)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(filepath.Join(dir, "b.go"), []byte("package main\nfunc f() {}"), 0600)) {
		t.FailNow()
	}
	return Options{Directory: dir, Selector: prefilter.Legacy{}, Rules: []api.AiPrompt{
		{ID: "datadog/go-sqli", Globs: []string{"**/*.go"}, FileSearchKeywords: []string{"absent_keyword"}},
		{ID: "datadog/go-xss", Globs: []string{"**/*.go"}},
	}}
}

func TestPlanExportsRejectedPairsAndStableOrdering(t *testing.T) {
	opts := fixture(t)
	var a, b bytes.Buffer
	summary, err := Plan(context.Background(), opts, &a)
	assert.NoError(t, err)
	assert.Equal(t, 4, summary.CandidatePairs)
	assert.Equal(t, 1, summary.SelectedPairs)
	assert.Equal(t, 0, summary.ErrorPairs)
	_, err = Plan(context.Background(), opts, &b)
	assert.NoError(t, err)
	first, err := ReadDecisions(&a)
	assert.NoError(t, err)
	second, err := ReadDecisions(&b)
	assert.NoError(t, err)
	assert.Equal(t, first, second)
	assert.True(t, first["a.go\x00datadog/go-sqli"].Selected)
	assert.False(t, first["b.go\x00datadog/go-sqli"].Selected)
}

func TestConfigKeywordsRemainDecisionsAndPathsRemainScope(t *testing.T) {
	opts := fixture(t)
	config := "schema-version: v1.0\nsast:\n  use-rulesets:\n    - go-ai_sast\n  global-config:\n    ignore-paths:\n      - b.go\n"
	assert.NoError(t, os.WriteFile(filepath.Join(opts.Directory, "code-security.datadog.yml"), []byte(config), 0600))
	var baseline, unfiltered bytes.Buffer
	before, err := Plan(context.Background(), opts, &baseline)
	assert.NoError(t, err)
	assert.Equal(t, 2, before.CandidatePairs)
	assert.Equal(t, 0, before.SelectedPairs)
	opts.Selector = prefilter.None{}
	after, err := Plan(context.Background(), opts, &unfiltered)
	assert.NoError(t, err)
	assert.Equal(t, 2, after.CandidatePairs)
	assert.Equal(t, 2, after.SelectedPairs)
	diff, err := Compare(&baseline, &unfiltered)
	assert.NoError(t, err)
	assert.Equal(t, 2, diff.Counts.Added)
	assert.Equal(t, 0, diff.Counts.Removed)
}

func TestExplicitDriverPreservesScopeAndOverridesYAML(t *testing.T) {
	opts := fixture(t)
	assert.NoError(t, os.WriteFile(filepath.Join(opts.Directory, "code-security.datadog.yml"), []byte("malformed: ["), 0600))
	opts.Driver = &model.DatadogDriverConfig{Files: map[string][]string{"a.go": {"datadog/go-sqli"}}}
	var output bytes.Buffer
	summary, err := Plan(context.Background(), opts, &output)
	assert.NoError(t, err)
	assert.Equal(t, 1, summary.CandidatePairs)
	assert.Equal(t, 1, summary.SelectedPairs)
}

type failingSelector struct{ calls int }

func (*failingSelector) Name() string { return "failed" }
func (s *failingSelector) Select(context.Context, prefilter.File, []api.AiPrompt) (prefilter.Result, error) {
	s.calls++
	return prefilter.Result{}, errors.New("unavailable")
}

func TestSelectorErrorFailsOpenAndIsCounted(t *testing.T) {
	opts := fixture(t)
	selector := &failingSelector{}
	opts.Selector = selector
	var output bytes.Buffer
	summary, err := Plan(context.Background(), opts, &output)
	assert.NoError(t, err)
	assert.Equal(t, 2, selector.calls)
	assert.Equal(t, 4, summary.SelectedPairs)
	assert.Equal(t, 4, summary.ErrorPairs)
	decisions, err := ReadDecisions(&output)
	assert.NoError(t, err)
	assert.Equal(t, "fail_open", decisions["a.go\x00datadog/go-sqli"].Reason)
}

func TestCancelledPlanNeverCallsSelector(t *testing.T) {
	opts := fixture(t)
	selector := &failingSelector{}
	opts.Selector = selector
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	_, err := Plan(ctx, opts, &output)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 0, selector.calls)
	assert.Empty(t, output.String())
}

func TestCompareRejectsChangedSourceAndIncompletePlans(t *testing.T) {
	opts := fixture(t)
	var before, after bytes.Buffer
	_, err := Plan(context.Background(), opts, &before)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(filepath.Join(opts.Directory, "a.go"), []byte("package main\nfunc changed() {}"), 0600))
	_, err = Plan(context.Background(), opts, &after)
	assert.NoError(t, err)
	_, err = Compare(bytes.NewReader(before.Bytes()), bytes.NewReader(after.Bytes()))
	assert.ErrorContains(t, err, "content mismatch")
	lines := bytes.Split(bytes.TrimSpace(before.Bytes()), []byte("\n"))
	_, err = ReadDecisions(bytes.NewReader(bytes.Join(lines[:len(lines)-1], []byte("\n"))))
	assert.ErrorContains(t, err, "incomplete")
}

func TestCompareRejectsChangedRules(t *testing.T) {
	opts := fixture(t)
	var before, after bytes.Buffer
	_, err := Plan(context.Background(), opts, &before)
	assert.NoError(t, err)
	opts.Rules[0].FileSearchKeywords = []string{"new_keyword"}
	_, err = Plan(context.Background(), opts, &after)
	assert.NoError(t, err)
	_, err = Compare(&before, &after)
	assert.ErrorContains(t, err, "content mismatch")
}
