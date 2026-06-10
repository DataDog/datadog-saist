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
	// Legacy (static-analysis.datadog.yaml) with only classic SA rulesets.
	// use-rulesets is non-empty so IsExplicitAISastDisablement returns false → falls back to all rules.
	// enabled is empty because "python-design" is not in rulesetToRules (not an AI SAST ruleset).
	s := &Sast{
		UseDefaultRulesets: &f,
		UseRulesets:        &[]string{"python-design"},
	}

	enabled, out, fallback := FilterRulesBySastConfig(rules, s, rulesetToRules, true)

	assert.True(t, fallback)
	assert.Empty(t, enabled)
	assert.Equal(t, rules, out)
}

func TestFilterRulesBySastConfig_NonLegacyClassicOnlyConfigNoFallback(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast":     {"datadog/go-sqli"},
		"python-ai_sast": {"datadog/python-sqli"},
	}
	rules := []api.AiPrompt{{ID: "datadog/go-sqli"}, {ID: "datadog/python-sqli"}}
	f := false
	// code-security.datadog.yaml (isLegacy=false) with only classic SA rulesets.
	// Zero filtered rules but non-legacy config → intentional, no fallback.
	s := &Sast{
		UseDefaultRulesets: &f,
		UseRulesets:        &[]string{"python-design"},
	}

	enabled, out, fallback := FilterRulesBySastConfig(rules, s, rulesetToRules, false)

	assert.False(t, fallback)
	assert.Empty(t, enabled)
	assert.Empty(t, out)
}

func TestFilterRulesBySastConfig_ExplicitOptOutRespectedRegardlessOfLegacy(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast": {"datadog/go-sqli"},
	}
	rules := []api.AiPrompt{{ID: "datadog/go-sqli"}}
	f := false
	// Explicit disablement: use-default-rulesets: false with no use-rulesets.
	// Must produce zero rules and no fallback for both legacy and non-legacy files.
	s := &Sast{UseDefaultRulesets: &f}

	for _, isLegacy := range []bool{true, false} {
		enabled, out, fallback := FilterRulesBySastConfig(rules, s, rulesetToRules, isLegacy)
		assert.False(t, fallback, "isLegacy=%v", isLegacy)
		assert.Empty(t, enabled, "isLegacy=%v", isLegacy)
		assert.Empty(t, out, "isLegacy=%v", isLegacy)
	}
}

func TestFilterRulesBySastConfig_LegacyWithValidSaistRulesetHonorsSelection(t *testing.T) {
	rulesetToRules := map[string][]string{
		"go-ai_sast":     {"datadog/go-sqli"},
		"python-ai_sast": {"datadog/python-sqli"},
	}
	rules := []api.AiPrompt{{ID: "datadog/go-sqli"}, {ID: "datadog/python-sqli"}}
	f := false
	// Mixed: one classic SA ruleset (ignored) and one valid AI SAST ruleset → non-empty filtered result.
	s := &Sast{
		UseDefaultRulesets: &f,
		UseRulesets:        &[]string{"python-design", "go-ai_sast"},
	}

	enabled, out, fallback := FilterRulesBySastConfig(rules, s, rulesetToRules, true)

	assert.False(t, fallback)
	assert.Equal(t, map[string]bool{"go-ai_sast": true}, enabled)
	require.Len(t, out, 1)
	assert.Equal(t, "datadog/go-sqli", out[0].ID)
}

func TestIsExplicitAISastDisablement(t *testing.T) {
	f := false
	tr := true

	t.Run("nil sast returns false", func(t *testing.T) {
		assert.False(t, IsExplicitAISastDisablement(nil))
	})
	t.Run("use-default-rulesets true returns false", func(t *testing.T) {
		assert.False(t, IsExplicitAISastDisablement(&Sast{UseDefaultRulesets: &tr}))
	})
	t.Run("use-default-rulesets nil returns false", func(t *testing.T) {
		assert.False(t, IsExplicitAISastDisablement(&Sast{}))
	})
	t.Run("use-default-rulesets false with no use-rulesets is explicit disablement", func(t *testing.T) {
		assert.True(t, IsExplicitAISastDisablement(&Sast{UseDefaultRulesets: &f}))
	})
	t.Run("use-default-rulesets false with empty use-rulesets is explicit disablement", func(t *testing.T) {
		assert.True(t, IsExplicitAISastDisablement(&Sast{UseDefaultRulesets: &f, UseRulesets: &[]string{}}))
	})
	t.Run("use-default-rulesets false with classic SA rulesets is not explicit disablement", func(t *testing.T) {
		assert.False(t, IsExplicitAISastDisablement(&Sast{UseDefaultRulesets: &f, UseRulesets: &[]string{"python-design"}}))
	})
	t.Run("use-default-rulesets false with AI SAST rulesets is not explicit disablement", func(t *testing.T) {
		assert.False(t, IsExplicitAISastDisablement(&Sast{UseDefaultRulesets: &f, UseRulesets: &[]string{"go-ai_sast"}}))
	})
}
