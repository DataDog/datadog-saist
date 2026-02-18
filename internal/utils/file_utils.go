package utils

import (
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/bmatcuk/doublestar/v4"
)

func RuleMatchesFile(rule *api.AiPrompt, relPath string) bool {
	for _, g := range rule.Globs {
		if m, _ := doublestar.Match(g, relPath); m {
			return true
		}
	}
	return false
}
