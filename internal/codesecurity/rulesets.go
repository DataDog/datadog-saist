package codesecurity

import (
	"fmt"
	"slices"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

// ExtractLanguageFromRuleID returns the language segment from a rule id (e.g. datadog/go-sqli -> go).
func ExtractLanguageFromRuleID(ruleID string) string {
	const prefix = "datadog/"
	if len(ruleID) <= len(prefix) || ruleID[:len(prefix)] != prefix {
		return ""
	}
	suffix := ruleID[len(prefix):]
	for i, c := range suffix {
		if c == '-' {
			return suffix[:i]
		}
	}
	return ""
}

// RulesetNameForLanguage returns the SAIST ruleset name for a language key (e.g. go -> go-ai_sast).
func RulesetNameForLanguage(langKey string) string {
	if langKey == "" {
		return ""
	}
	return fmt.Sprintf("%s-ai_sast", langKey)
}

// BuildRulesetToRuleIDs groups API rule IDs by derived ruleset name (language-ai_sast).
func BuildRulesetToRuleIDs(rules []api.AiPrompt) map[string][]string {
	m := make(map[string][]string)
	for i := range rules {
		lang := ExtractLanguageFromRuleID(rules[i].ID)
		if lang == "" {
			continue
		}
		name := RulesetNameForLanguage(lang)
		m[name] = append(m[name], rules[i].ID)
	}
	for k := range m {
		slices.Sort(m[k])
	}
	return m
}

// IsValidRuleset reports whether name is a known ruleset for the current rule set.
func IsValidRuleset(rulesetToRules map[string][]string, name string) bool {
	_, ok := rulesetToRules[name]
	return ok
}

// GetRulesForRuleset returns rule IDs for a ruleset, or nil if unknown.
func GetRulesForRuleset(rulesetToRules map[string][]string, name string) []string {
	return rulesetToRules[name]
}

// EnabledSaistRulesetNames mirrors code-workload-runner enabledSaistRulesetNames for the sast block.
func EnabledSaistRulesetNames(s *Sast, rulesetToRules map[string][]string) map[string]bool {
	if s == nil {
		return nil
	}
	enabled := make(map[string]bool)

	useDefaultRulesets := true
	if s.UseDefaultRulesets != nil {
		useDefaultRulesets = *s.UseDefaultRulesets
	}
	if useDefaultRulesets {
		for name := range rulesetToRules {
			enabled[name] = true
		}
	}
	if s.UseRulesets != nil {
		for _, rs := range *s.UseRulesets {
			if IsValidRuleset(rulesetToRules, rs) {
				enabled[rs] = true
			}
		}
	}
	if s.RulesetConfigs != nil {
		for name := range *s.RulesetConfigs {
			if IsValidRuleset(rulesetToRules, name) {
				enabled[name] = true
			}
		}
	}
	if s.IgnoreRulesets != nil {
		for _, rs := range *s.IgnoreRulesets {
			if IsValidRuleset(rulesetToRules, rs) {
				delete(enabled, rs)
			}
		}
	}
	return enabled
}

// FilterRulesByEnabledRulesets keeps rules whose id belongs to an enabled ruleset.
func FilterRulesByEnabledRulesets(rules []api.AiPrompt, enabled map[string]bool, rulesetToRules map[string][]string) []api.AiPrompt {
	if len(enabled) == 0 {
		return nil
	}
	allowed := make(map[string]bool)
	for rs := range enabled {
		for _, id := range GetRulesForRuleset(rulesetToRules, rs) {
			allowed[id] = true
		}
	}
	var out []api.AiPrompt
	for i := range rules {
		if allowed[rules[i].ID] {
			out = append(out, rules[i])
		}
	}
	return out
}

// IsExplicitAISastDisablement reports whether the sast config deliberately opted out of AI SAST
// scanning. This is true only when use-default-rulesets is false AND use-rulesets is absent or
// empty — meaning the user actively disabled all SAST rule coverage.
//
// Every other zero-rule outcome (legacy static-analysis configs, SCA-only configs, configs that
// list only classic SA rulesets) falls back to the default AI SAST rule set so that repositories
// without AI SAST awareness still receive coverage.
func IsExplicitAISastDisablement(s *Sast) bool {
	if s == nil {
		return false
	}
	if s.UseDefaultRulesets == nil || *s.UseDefaultRulesets {
		return false
	}
	return s.UseRulesets == nil || len(*s.UseRulesets) == 0
}

// FilterRulesBySastConfig applies SAIST ruleset filtering. When the filtered result is empty and
// the config does not represent an explicit AI SAST disablement, it falls back to all rules so
// that repositories using legacy or classic-SA-only configs still receive AI SAST coverage.
//
// The third return value is true when the fallback was applied. Callers should log this so that
// unexpected no-coverage situations are visible in local runs.
func FilterRulesBySastConfig(
	rules []api.AiPrompt,
	s *Sast,
	rulesetToRules map[string][]string,
) (enabled map[string]bool, filtered []api.AiPrompt, fallbackUsed bool) {
	enabled = EnabledSaistRulesetNames(s, rulesetToRules)
	filtered = FilterRulesByEnabledRulesets(rules, enabled, rulesetToRules)
	if len(filtered) == 0 && !IsExplicitAISastDisablement(s) {
		return enabled, rules, true
	}
	return enabled, filtered, false
}
