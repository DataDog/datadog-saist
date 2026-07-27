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
	TopP         *float64
	ResponseType string
	Schema       GenerateOptionSchema
}

type GenerateResponse struct {
	Content       string
	ReturnedModel string
	InputTokens   int32
	OutputTokens  int32
	UsageKnown    bool
}

// ToolDefinition describes a read-only tool the model may call during a
// tool-using loop. Parameters is a JSON Schema object describing the arguments.
type ToolDefinition struct {
	Name        string
	Description string
	Parameters  any
}

// ToolCall is a single tool invocation requested by the model. Arguments holds
// the raw JSON arguments string emitted by the model.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
}

// Message is a provider-agnostic chat message used to drive tool-calling loops.
// ToolCalls is set on assistant turns that requested tools. ToolCallID is set on
// tool-result turns to associate the result with the originating call.
type Message struct {
	Role       string // "system" | "user" | "assistant" | "tool"
	Content    string
	ToolCalls  []ToolCall
	ToolCallID string
}

// ToolGenerateResponse is the result of a single tool-capable generation turn.
// ToolCalls is empty when the model has produced its final answer.
type ToolGenerateResponse struct {
	Content       string
	ToolCalls     []ToolCall
	FinishReason  string
	ReturnedModel string
	InputTokens   int32
	OutputTokens  int32
	UsageKnown    bool
}

// AppliedSampling returns the sampling parameters sent to the provider. A nil
// value means the provider default is used.
func AppliedSampling(model string, options *GenerateOptions) (*float64, *float64) {
	if options == nil {
		return nil, nil
	}
	var temperature *float64
	if shouldSendOpenAITemperature(model) {
		value := options.Temperature
		temperature = &value
	}
	var topP *float64
	if options.TopP != nil {
		value := *options.TopP
		topP = &value
	}
	return temperature, topP
}

// ToolCallingClient is an optional capability interface implemented by clients
// that can carry tools through a multi-turn loop. The base LLMClient is
// unchanged, so clients that do not implement this simply fall back to a
// single-shot GenerateContent call.
type ToolCallingClient interface {
	GenerateWithTools(ctx context.Context, messages []Message, tools []ToolDefinition, options *GenerateOptions) (*ToolGenerateResponse, error)
}
