package clients

import "context"

type LLMClient interface {
	GenerateContent(ctx context.Context, systemPrompt, userPrompt string, options *GenerateOptions) (*GenerateResponse, error)
}

// ToolDefinition describes a read-only function exposed to an agent.
type ToolDefinition struct {
	Name        string
	Description string
	Parameters  map[string]any
}

// ToolCall is a provider-neutral function call.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// Message preserves the transcript needed for multi-turn tool calling.
type Message struct {
	Role       string
	Content    string
	ToolCalls  []ToolCall
	ToolCallID string
}

type ToolGenerateResponse struct {
	Content      string
	ToolCalls    []ToolCall
	InputTokens  int32
	OutputTokens int32
}

// ToolCallingClient is implemented by providers that can execute tool loops.
type ToolCallingClient interface {
	GenerateWithTools(ctx context.Context, messages []Message, tools []ToolDefinition,
		options *GenerateOptions) (*ToolGenerateResponse, error)
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
