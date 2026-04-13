package codesecurity

import (
	"context"
	"slices"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/bmatcuk/doublestar/v4"
)

func sortedRulesetConfigKeys(m map[string]YamlRulesetConfig) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// FilterRuleConfigsToParentRuleset keeps only rule IDs that belong to rulesetName (GetRulesForRuleset).
func FilterRuleConfigsToParentRuleset(
	rulesetName string,
	ruleConfigs map[string]YamlRuleConfig,
	rulesetToRules map[string][]string,
) (filtered map[string]YamlRuleConfig, skipped []string) {
	allowed := make(map[string]bool)
	for _, id := range GetRulesForRuleset(rulesetToRules, rulesetName) {
		allowed[id] = true
	}
	for ruleID, cfg := range ruleConfigs {
		if allowed[ruleID] {
			if filtered == nil {
				filtered = make(map[string]YamlRuleConfig)
			}
			filtered[ruleID] = cfg
		} else {
			skipped = append(skipped, ruleID)
		}
	}
	slices.Sort(skipped)
	return filtered, skipped
}

// ForEachRulesetConfigPathFilter applies ruleset-level and scoped rule-level path configs for enabled rulesets.
func ForEachRulesetConfigPathFilter(
	ctx context.Context,
	rulesetConfigs *map[string]YamlRulesetConfig,
	enabledRulesets map[string]bool,
	rulesetToRules map[string][]string,
	apply func(map[string]YamlRuleConfig),
) {
	if rulesetConfigs == nil || apply == nil || len(*rulesetConfigs) == 0 {
		return
	}
	logger := log.FromContext(ctx)
	m := *rulesetConfigs
	for _, rulesetName := range sortedRulesetConfigKeys(m) {
		if !IsValidRuleset(rulesetToRules, rulesetName) {
			logger.Debugf("ruleset-configs contains unknown SAIST ruleset name: %s", rulesetName)
			continue
		}
		if !enabledRulesets[rulesetName] {
			continue
		}
		rulesetConfig := m[rulesetName]
		if rulesetConfig.OnlyPaths != nil || rulesetConfig.IgnorePaths != nil {
			ids := GetRulesForRuleset(rulesetToRules, rulesetName)
			if len(ids) > 0 {
				temp := make(map[string]YamlRuleConfig, len(ids))
				for _, ruleID := range ids {
					temp[ruleID] = YamlRuleConfig{
						OnlyPaths:   rulesetConfig.OnlyPaths,
						IgnorePaths: rulesetConfig.IgnorePaths,
					}
				}
				apply(temp)
			}
		}
		if rulesetConfig.RuleConfigs != nil {
			filtered, skipped := FilterRuleConfigsToParentRuleset(rulesetName, *rulesetConfig.RuleConfigs, rulesetToRules)
			if len(skipped) > 0 {
				logger.Debugf("ruleset-configs rule-configs keys not in parent ruleset %q: %v", rulesetName, skipped)
			}
			if len(filtered) > 0 {
				apply(filtered)
			}
		}
	}
}

func pathMatchesAnyPattern(filePath string, patterns []string) bool {
	for _, pattern := range patterns {
		matched, err := doublestar.Match(pattern, filePath)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// ApplyRuleConfigFilters applies rule-level only-paths / ignore-paths to a file→rules map.
func ApplyRuleConfigFilters(
	fileRuleMapping map[string][]string,
	ruleConfigs map[string]YamlRuleConfig,
) map[string][]string {
	if len(ruleConfigs) == 0 {
		return fileRuleMapping
	}
	filteredMapping := make(map[string][]string)
	for filePath, ruleIDs := range fileRuleMapping {
		var filteredRules []string
		for _, ruleID := range ruleIDs {
			ruleConfig, has := ruleConfigs[ruleID]
			if !has {
				filteredRules = append(filteredRules, ruleID)
				continue
			}
			if ruleConfig.OnlyPaths != nil && len(*ruleConfig.OnlyPaths) > 0 {
				if !pathMatchesAnyPattern(filePath, *ruleConfig.OnlyPaths) {
					continue
				}
			}
			if ruleConfig.IgnorePaths != nil && len(*ruleConfig.IgnorePaths) > 0 {
				if pathMatchesAnyPattern(filePath, *ruleConfig.IgnorePaths) {
					continue
				}
			}
			filteredRules = append(filteredRules, ruleID)
		}
		if len(filteredRules) > 0 {
			filteredMapping[filePath] = filteredRules
		}
	}
	return filteredMapping
}

func globalPathConfigActive(g *YamlGlobalConfig) bool {
	if g == nil {
		return false
	}
	if g.OnlyPaths != nil && len(*g.OnlyPaths) > 0 {
		return true
	}
	if g.IgnorePaths != nil && len(*g.IgnorePaths) > 0 {
		return true
	}
	return false
}

func filePathAllowedByGlobalConfig(filePath string, g *YamlGlobalConfig) bool {
	if !globalPathConfigActive(g) {
		return true
	}
	if g.OnlyPaths != nil && len(*g.OnlyPaths) > 0 {
		if !pathMatchesAnyPattern(filePath, *g.OnlyPaths) {
			return false
		}
	}
	if g.IgnorePaths != nil && len(*g.IgnorePaths) > 0 {
		if pathMatchesAnyPattern(filePath, *g.IgnorePaths) {
			return false
		}
	}
	return true
}

// ApplyGlobalPathFiltersToFileRuleMapping drops file keys that violate sast.global-config paths.
func ApplyGlobalPathFiltersToFileRuleMapping(
	fileRuleMapping map[string][]string,
	global *YamlGlobalConfig,
) map[string][]string {
	if !globalPathConfigActive(global) || len(fileRuleMapping) == 0 {
		return fileRuleMapping
	}
	out := make(map[string][]string)
	for filePath, ruleIDs := range fileRuleMapping {
		if filePathAllowedByGlobalConfig(filePath, global) {
			out[filePath] = ruleIDs
		}
	}
	return out
}
