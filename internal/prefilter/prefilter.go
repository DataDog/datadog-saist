package prefilter

import (
	"context"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
)

type File struct {
	Path            string
	Language        model.Language
	Code            string
	StrippedCode    string
	RequireKeywords bool
}

type Decision struct {
	RuleID   string
	Selected bool
	Reason   string
	Error    string
	Score    *float64
}

type Usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type Result struct {
	Decisions []Decision
	Model     string
	Usage     Usage
}

// Select evaluates all candidate rules for one file. Errors are handled by the planner.
type Selector interface {
	Name() string
	Select(context.Context, File, []api.AiPrompt) (Result, error)
}
