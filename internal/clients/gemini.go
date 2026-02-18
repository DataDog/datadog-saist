package clients

import (
	"context"
	"fmt"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type GeminiClient struct {
	client *genai.Client
	model  string
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

	// Gemini handles system and user prompts differently
	prompt := fmt.Sprintf("System: %s\n\nUser: %s", systemPrompt, userPrompt)

	resp, err := modelValue.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
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
