package model

type File struct {
	Path string
	Hash string
}

type FileResult struct {
	Path           string
	Violations     []Violation
	InputTokens    int32
	OutputTokens   int32
	LLMCalls       int32
	RulesSucceeded []string
	RulesFailed    []string
}
