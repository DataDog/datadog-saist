package codesecurity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyRuleConfigFilters_OnlyPaths(t *testing.T) {
	in := map[string][]string{
		"internal/a.go": {"datadog/go-sqli"},
		"cmd/b.go":      {"datadog/go-sqli"},
	}
	cfg := map[string]YamlRuleConfig{
		"datadog/go-sqli": {OnlyPaths: &[]string{"internal/**"}},
	}
	out := ApplyRuleConfigFilters(in, cfg)
	assert.Contains(t, out, "internal/a.go")
	assert.NotContains(t, out, "cmd/b.go")
}

func TestApplyGlobalPathFiltersToFileRuleMapping(t *testing.T) {
	in := map[string][]string{
		"src/a.go":    {"datadog/go-sqli"},
		"vendor/b.go": {"datadog/go-sqli"},
	}
	g := &YamlGlobalConfig{OnlyPaths: &[]string{"src/**"}}
	out := ApplyGlobalPathFiltersToFileRuleMapping(in, g)
	assert.Contains(t, out, "src/a.go")
	assert.NotContains(t, out, "vendor/b.go")
}

func TestFilterRuleConfigsToParentRuleset(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast":     {"datadog/go-sqli", "datadog/go-xss"},
		"python-ai_sast": {"datadog/python-sqli"},
	}
	cfg := map[string]YamlRuleConfig{
		"datadog/go-sqli":     {},
		"datadog/python-sqli": {},
	}
	f, skipped := FilterRuleConfigsToParentRuleset("go-ai_sast", cfg, rulesetToRules)
	assert.Equal(t, []string{"datadog/python-sqli"}, skipped)
	require.Len(t, f, 1)
	assert.Contains(t, f, "datadog/go-sqli")
}

func TestForEachRulesetConfigPathFilter_SkipsUnknownRuleset(t *testing.T) {
	rulesetToRules := map[string][]string{"go-ai_sast": {"datadog/go-sqli"}}
	enabled := map[string]bool{"go-ai_sast": true, "bogus-ai_sast": true}
	rc := map[string]YamlRulesetConfig{
		"bogus-ai_sast": {OnlyPaths: &[]string{"**"}},
	}
	var applied int
	ForEachRulesetConfigPathFilter(context.Background(), &rc, enabled, rulesetToRules, func(map[string]YamlRuleConfig) {
		applied++
	})
	assert.Equal(t, 0, applied)
}
