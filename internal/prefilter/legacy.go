package prefilter

import (
	"context"
	"github.com/DataDog/datadog-saist/internal/filtering"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"strings"
)

type Legacy struct{}

func (Legacy) Name() string { return "legacy" }

func (Legacy) Select(ctx context.Context, file File, rules []api.AiPrompt) (Result, error) {
	result := Result{}
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		decision := Decision{RuleID: rule.ID, Reason: "specialized_or_keyword"}
		if file.RequireKeywords && !MatchesKeywords(rule, file.StrippedCode) {
			decision.Reason = "config_keywords"
		} else {
			decision.Selected = filtering.ShouldAnalyze(&model.DetectionContext{
				Language: file.Language, Path: file.Path, Code: file.Code,
				StrippedCode: file.StrippedCode, Rule: rule,
			}, log.FromContext(ctx))
		}
		result.Decisions = append(result.Decisions, decision)
	}
	return result, nil
}

func MatchesKeywords(rule api.AiPrompt, strippedCode string) bool {
	if len(rule.FileSearchKeywords) == 0 {
		return true
	}
	for _, keyword := range rule.FileSearchKeywords {
		if strings.Contains(strippedCode, strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

type None struct{}

func (None) Name() string { return "none" }
func (None) Select(ctx context.Context, file File, rules []api.AiPrompt) (Result, error) {
	result := Result{}
	for _, rule := range rules {
		result.Decisions = append(result.Decisions, Decision{RuleID: rule.ID, Selected: true, Reason: "unfiltered"})
	}
	return result, ctx.Err()
}
