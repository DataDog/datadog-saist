package codesecurity

import (
	"os"
	"strings"

	"github.com/DataDog/datadog-saist/internal/filtering"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/utils"
)

// SourceFile is minimal file metadata for rule matching (mirrors analysis.fileMeta fields used here).
type SourceFile struct {
	RelPath string
	AbsPath string
	Lang    model.Language
}

func languageKeyFromModel(lang model.Language) string {
	switch lang {
	case model.Go:
		return "go"
	case model.Java:
		return "java"
	case model.Python:
		return "python"
	case model.CSharp:
		return "csharp"
	case model.JavaScript:
		return "javascript"
	case model.TypeScript:
		return "typescript"
	case model.Kotlin:
		return "kotlin"
	default:
		return ""
	}
}

func buildRulesByLang(rules []api.AiPrompt) map[string][]api.AiPrompt {
	rulesByLang := make(map[string][]api.AiPrompt)
	for i := range rules {
		lang := ExtractLanguageFromRuleID(rules[i].ID)
		if lang == "" {
			continue
		}
		rulesByLang[lang] = append(rulesByLang[lang], rules[i])
	}
	return rulesByLang
}

func globMatchedRules(candidates []api.AiPrompt, relPath string) []api.AiPrompt {
	var globMatched []api.AiPrompt
	for i := range candidates {
		if utils.RuleMatchesFile(&candidates[i], relPath) {
			globMatched = append(globMatched, candidates[i])
		}
	}
	return globMatched
}

func anyRuleNeedsKeywords(globMatched []api.AiPrompt) bool {
	for i := range globMatched {
		if len(globMatched[i].FileSearchKeywords) > 0 {
			return true
		}
	}
	return false
}

func ruleIDsAfterKeywordFilter(f SourceFile, globMatched []api.AiPrompt) []string {
	if !anyRuleNeedsKeywords(globMatched) {
		ids := make([]string, 0, len(globMatched))
		for i := range globMatched {
			ids = append(ids, globMatched[i].ID)
		}
		return ids
	}
	content, err := os.ReadFile(f.AbsPath) //nolint:gosec // intentional scan target
	if err != nil {
		ids := make([]string, 0, len(globMatched))
		for i := range globMatched {
			ids = append(ids, globMatched[i].ID)
		}
		return ids
	}
	stripped := filtering.StripCodeForDetection(string(content), f.Lang)
	var ids []string
	for i := range globMatched {
		if ruleMatchesKeywords(&globMatched[i], stripped) {
			ids = append(ids, globMatched[i].ID)
		}
	}
	return ids
}

// MatchFilesToRules maps each file to applicable rule IDs (glob + FileSearchKeywords), aligned with
// code-workload-runner matchFilesToRules: keywords use stripped/lowercased code like filtering.ShouldAnalyze.
func MatchFilesToRules(files []SourceFile, rules []api.AiPrompt) map[string][]string {
	rulesByLang := buildRulesByLang(rules)
	out := make(map[string][]string)
	for _, f := range files {
		langKey := languageKeyFromModel(f.Lang)
		candidates := rulesByLang[langKey]
		globMatched := globMatchedRules(candidates, f.RelPath)
		if len(globMatched) == 0 {
			continue
		}
		ids := ruleIDsAfterKeywordFilter(f, globMatched)
		if len(ids) > 0 {
			out[f.RelPath] = ids
		}
	}
	return out
}

func ruleMatchesKeywords(rule *api.AiPrompt, strippedLowerCode string) bool {
	if len(rule.FileSearchKeywords) == 0 {
		return true
	}
	for _, kw := range rule.FileSearchKeywords {
		if strings.Contains(strippedLowerCode, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
