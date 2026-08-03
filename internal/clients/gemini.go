package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type GeminiClient struct {
	client *genai.Client
	model  string
}

// GenerateWithTools runs one Gemini function-calling turn. The supplied transcript
// is rebuilt on each call so the agent loop remains provider-neutral.
func (c *GeminiClient) GenerateWithTools(ctx context.Context, messages []Message, tools []ToolDefinition,
	options *GenerateOptions) (*ToolGenerateResponse, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("tool call requires messages")
	}
	modelValue := c.client.GenerativeModel(c.model)
	modelValue.SetMaxOutputTokens(int32(options.MaxTokens))
	modelValue.SetTemperature(float32(options.Temperature))
	if messages[0].Role == "system" {
		setGeminiSystemInstruction(modelValue, messages[0].Content)
	}
	if len(tools) > 0 {
		declarations := make([]*genai.FunctionDeclaration, 0, len(tools))
		for _, tool := range tools {
			declarations = append(declarations, &genai.FunctionDeclaration{Name: tool.Name, Description: tool.Description, Parameters: geminiSchema(tool.Parameters)})
		}
		modelValue.Tools = []*genai.Tool{{FunctionDeclarations: declarations}}
	} else if options.Schema.JsonSchema != nil {
		modelValue.ResponseMIMEType = ApplicationJsonHeader
		if schema, ok := options.Schema.JsonSchema.(*genai.Schema); ok {
			modelValue.ResponseSchema = schema
		}
	}
	chat := modelValue.StartChat()
	start := 0
	if messages[0].Role == "system" {
		start = 1
	}
	if len(messages)-start == 0 {
		return nil, fmt.Errorf("tool call requires a user message")
	}
	for i := start; i < len(messages)-1; i++ {
		chat.History = append(chat.History, geminiContent(messages[i], messages))
	}
	last := messages[len(messages)-1]
	var response *genai.GenerateContentResponse
	var err error
	if last.Role == "tool" {
		name := toolNameForID(messages, last.ToolCallID)
		payload := map[string]any{"content": last.Content}
		_ = json.Unmarshal([]byte(last.Content), &payload)
		response, err = chat.SendMessage(ctx, genai.FunctionResponse{Name: name, Response: payload})
	} else {
		response, err = chat.SendMessage(ctx, genai.Text(last.Content))
	}
	if err != nil {
		if strings.Contains(err.Error(), "429") || strings.Contains(strings.ToLower(err.Error()), "rate limit") {
			return nil, fmt.Errorf("%w: %v", ErrRateLimited, err)
		}
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}
	if len(response.Candidates) == 0 {
		return nil, fmt.Errorf("no response candidates returned from Gemini")
	}
	result := &ToolGenerateResponse{}
	if response.UsageMetadata != nil {
		result.InputTokens = response.UsageMetadata.PromptTokenCount
		result.OutputTokens = response.UsageMetadata.CandidatesTokenCount
	}
	for index, call := range response.Candidates[0].FunctionCalls() {
		arguments, _ := json.Marshal(call.Args)
		result.ToolCalls = append(result.ToolCalls, ToolCall{ID: fmt.Sprintf("gemini-%d", index), Name: call.Name, Arguments: string(arguments)})
	}
	if response.Candidates[0].Content != nil {
		for _, part := range response.Candidates[0].Content.Parts {
			if value, ok := part.(genai.Text); ok {
				result.Content += string(value)
			}
		}
	}
	return result, nil
}

func geminiContent(message Message, messages []Message) *genai.Content {
	if message.Role == "assistant" {
		parts := make([]genai.Part, 0, len(message.ToolCalls)+1)
		if message.Content != "" {
			parts = append(parts, genai.Text(message.Content))
		}
		for _, call := range message.ToolCalls {
			var args map[string]any
			_ = json.Unmarshal([]byte(call.Arguments), &args)
			parts = append(parts, genai.FunctionCall{Name: call.Name, Args: args})
		}
		return &genai.Content{Role: "model", Parts: parts}
	}
	if message.Role == "tool" {
		name := toolNameForID(messages, message.ToolCallID)
		return genai.NewUserContent(genai.FunctionResponse{Name: name, Response: map[string]any{"content": message.Content}})
	}
	return genai.NewUserContent(genai.Text(message.Content))
}

func toolNameForID(messages []Message, id string) string {
	for _, message := range messages {
		for _, call := range message.ToolCalls {
			if call.ID == id {
				return call.Name
			}
		}
	}
	return "unknown_tool"
}

func geminiSchema(raw map[string]any) *genai.Schema {
	schema := &genai.Schema{Type: genai.TypeObject, Properties: map[string]*genai.Schema{}}
	if properties, ok := raw["properties"].(map[string]any); ok {
		for name, value := range properties {
			if property, ok := value.(map[string]any); ok {
				schema.Properties[name] = geminiProperty(property)
			}
		}
	}
	if required, ok := raw["required"].([]string); ok {
		schema.Required = required
	}
	return schema
}

func geminiProperty(raw map[string]any) *genai.Schema {
	schema := &genai.Schema{Type: genai.TypeString}
	if description, ok := raw["description"].(string); ok {
		schema.Description = description
	}
	if raw["type"] == "integer" {
		schema.Type = genai.TypeInteger
	}
	return schema
}

func NewGeminiClient(ctx context.Context, modelName string) (*GeminiClient, error) {
	token, err := GetTokenGetter(model.ProviderGoogle).Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Gemini token: %w", err)
	}

	if token == "" {
		return nil, fmt.Errorf("gemini API key not provided via CLI flag or GOOGLE_API_KEY environment variable")
	}

	client, err := genai.NewClient(ctx, option.WithAPIKey(token))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	return &GeminiClient{
		client: client,
		model:  modelName,
	}, nil
}

func (c *GeminiClient) GenerateContent(ctx context.Context, systemPrompt,
	userPrompt string, options *GenerateOptions) (*GenerateResponse, error) {
	modelValue := c.client.GenerativeModel(c.model)
	modelValue.SetMaxOutputTokens(int32(options.MaxTokens))
	modelValue.SetTemperature(float32(options.Temperature))

	if options.ResponseType == ApplicationJsonHeader {
		modelValue.ResponseMIMEType = ApplicationJsonHeader
	}

	// Set response schema if provided
	if options.Schema.JsonSchema != nil {
		if schema, ok := options.Schema.JsonSchema.(*genai.Schema); ok {
			modelValue.ResponseSchema = schema
		}
	}
	setGeminiSystemInstruction(modelValue, systemPrompt)

	resp, err := modelValue.GenerateContent(ctx, genai.Text(userPrompt))
	if err != nil {
		// Check for rate limit error (HTTP 429) in the error message
		if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "rate limit") {
			return nil, fmt.Errorf("%w: %v", ErrRateLimited, err)
		}
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("no response candidates returned from Gemini")
	}

	if len(resp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("no content parts in Gemini response")
	}

	inputTokens := int32(0)
	outputTokens := int32(0)
	if resp.UsageMetadata != nil {
		inputTokens = resp.UsageMetadata.PromptTokenCount
		outputTokens = resp.UsageMetadata.CandidatesTokenCount
	}

	// Extract text content from the first part
	var content string
	if textPart, ok := resp.Candidates[0].Content.Parts[0].(genai.Text); ok {
		content = string(textPart)
	} else {
		return nil, fmt.Errorf("unexpected content type in Gemini response")
	}

	return &GenerateResponse{
		Content:      content,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}, nil
}

func setGeminiSystemInstruction(modelValue *genai.GenerativeModel, systemPrompt string) {
	modelValue.SystemInstruction = genai.NewUserContent(genai.Text(systemPrompt))
}
