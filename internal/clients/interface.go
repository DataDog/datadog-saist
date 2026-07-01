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

type aiGatewayTagsKey struct{}

func WithAIGatewayTags(ctx context.Context, tags map[string]string) context.Context {
	if len(tags) == 0 {
		return ctx
	}
	return context.WithValue(ctx, aiGatewayTagsKey{}, tags)
}

type GenerateResponse struct {
	Content      string
	InputTokens  int32
	OutputTokens int32
}
