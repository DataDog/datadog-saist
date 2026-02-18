package model

type LLMResultViolation struct {
	StartLine   uint   `json:"startLine"`
	StartColumn uint   `json:"startColumn"`
	EndLine     uint   `json:"endLine"`
	EndColumn   uint   `json:"endColumn"`
	Reason      string `json:"reason"`
}

type LLMResult struct {
	Violations []LLMResultViolation `json:"violations"`
}
