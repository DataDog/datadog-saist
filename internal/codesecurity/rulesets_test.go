package codesecurity

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractLanguageFromRuleID(t *testing.T) {
	assert.Equal(t, "go", ExtractLanguageFromRuleID("datadog/go-sqli"))
	assert.Equal(t, "csharp", ExtractLanguageFromRuleID("datadog/csharp-sqli"))
	assert.Equal(t, "", ExtractLanguageFromRuleID("other/go-sqli"))
}

func TestBuildRulesetToRuleIDs(t *testing.T) {
	rules := []api.AiPrompt{
		{ID: "datadog/go-sqli"},
		{ID: "datadog/python-sqli"},
		{ID: "datadog/go-xss"},
	}
	m := BuildRulesetToRuleIDs(rules)
	assert.ElementsMatch(t, []string{"datadog/go-sqli", "datadog/go-xss"}, m["go-ai_sast"])
	assert.ElementsMatch(t, []string{"datadog/python-sqli"}, m["python-ai_sast"])
}

func TestEnabledSaistRulesetNames_IgnoreRulesets(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast":     {"datadog/go-sqli"},
		"python-ai_sast": {"datadog/python-sqli"},
	}
	f := false
	s := &Sast{
		UseDefaultRulesets: &f,
		UseRulesets:        &[]string{"go-ai_sast", "python-ai_sast"},
		IgnoreRulesets:     &[]string{"python-ai_sast"},
	}
	en := EnabledSaistRulesetNames(s, rulesetToRules)
	assert.True(t, en["go-ai_sast"])
	assert.False(t, en["python-ai_sast"])
}

func TestEnabledSaistRulesetNames_IgnoresUnknownUseRulesets(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast": {"datadog/go-sqli"},
	}
	f := false
	s := &Sast{
		UseDefaultRulesets: &f,
		UseRulesets:        &[]string{"python-design", "go-ai_sast"},
	}

	en := EnabledSaistRulesetNames(s, rulesetToRules)

	assert.Equal(t, map[string]bool{"go-ai_sast": true}, en)
}

func TestFilterRulesByEnabledRulesets(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast": {"datadog/go-sqli", "datadog/go-xss"},
	}
	rules := []api.AiPrompt{{ID: "datadog/go-sqli"}, {ID: "datadog/python-sqli"}}
	enabled := map[string]bool{"go-ai_sast": true}
	out := FilterRulesByEnabledRulesets(rules, enabled, rulesetToRules)
	require.Len(t, out, 1)
	assert.Equal(t, "datadog/go-sqli", out[0].ID)
}

func TestFilterRulesBySastConfig_LegacyConvertedConfigKeepsDefaultRules(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast":     {"datadog/go-sqli"},
		"python-ai_sast": {"datadog/python-sqli"},
	}
	rules := []api.AiPrompt{{ID: "datadog/go-sqli"}, {ID: "datadog/python-sqli"}}
	f := false
	s := &Sast{
		UseDefaultRulesets: &f,
		UseRulesets:        &[]string{"python-design"},
	}

	enabled, out := FilterRulesBySastConfig(rules, s, true, rulesetToRules)

	assert.Empty(t, enabled)
	assert.Equal(t, rules, out)
}

func TestFilterRulesBySastConfig_NativeConfigCanDisableSaist(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast": {"datadog/go-sqli"},
	}
	rules := []api.AiPrompt{{ID: "datadog/go-sqli"}}
	f := false
	s := &Sast{
		UseDefaultRulesets: &f,
	}

	enabled, out := FilterRulesBySastConfig(rules, s, false, rulesetToRules)

	assert.Empty(t, enabled)
	assert.Empty(t, out)
}

func TestFilterRulesBySastConfig_LegacyWithValidSaistRulesetHonorsSelection(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast":     {"datadog/go-sqli"},
		"python-ai_sast": {"datadog/python-sqli"},
	}
	rules := []api.AiPrompt{{ID: "datadog/go-sqli"}, {ID: "datadog/python-sqli"}}
	f := false
	s := &Sast{
		UseDefaultRulesets: &f,
		UseRulesets:        &[]string{"python-design", "go-ai_sast"},
	}

	enabled, out := FilterRulesBySastConfig(rules, s, true, rulesetToRules)

	assert.Equal(t, map[string]bool{"go-ai_sast": true}, enabled)
	require.Len(t, out, 1)
	assert.Equal(t, "datadog/go-sqli", out[0].ID)
}
