package clients

import "context"

type LLMClient interface {
	GenerateContent(ctx context.Context, systemPrompt, userPrompt string, options *GenerateOptions) (*GenerateResponse, error)
}

type GenerateOptionSchema struct {
	Name        string
	Description string
	JsonSchema  any
}

type GenerateOptions struct {
	MaxTokens    int
	Temperature  float64
	ResponseType string
	Schema       GenerateOptionSchema
}

type GenerateResponse struct {
	Content      string
	InputTokens  int32
	OutputTokens int32
}
