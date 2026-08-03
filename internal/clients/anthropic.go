package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AnthropicClient struct {
	client  *http.Client
	model   string
	baseURL string
	apiKey  string
}

type anthropicRequest struct {
	Model        string                 `json:"model"`
	MaxTokens    int                    `json:"max_tokens"`
	Messages     []anthropicMessage     `json:"messages"`
	System       []anthropicTextBlock   `json:"system,omitempty"`
	OutputConfig *anthropicOutputConfig `json:"output_config,omitempty"`
	Tools        []anthropicTool        `json:"tools,omitempty"`
}

type anthropicOutputConfig struct {
	ResponseFormat *anthropicResponseFormat `json:"format,omitempty"`
}

type anthropicResponseFormat struct {
	Type       string `json:"type"`
	JSONSchema any    `json:"schema,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

type anthropicTextBlock struct {
	Type         string                 `json:"type"`
	Text         string                 `json:"text"`
	CacheControl *anthropicCacheControl `json:"cache_control,omitempty"`
}

type anthropicCacheControl struct {
	Type string `json:"type"`
}

type anthropicResponse struct {
	Content []anthropicContent `json:"content"`
	Usage   anthropicUsage     `json:"usage"`
}

type anthropicContent struct {
	Type  string         `json:"type"`
	Text  string         `json:"text"`
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Input map[string]any `json:"input"`
}

type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type anthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	OutputTokens             int `json:"output_tokens"`
}

func NewAnthropicClient(ctx context.Context, model string) (*AnthropicClient, error) {
	baseURL := GetHost("anthropic", "")
	token, err := GetTokenGetter("anthropic").Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Anthropic token: %w", err)
	}

	if token == "" {
		return nil, fmt.Errorf("anthropic API key not provided via CLI flag or ANTHROPIC_API_KEY environment variable")
	}

	return &AnthropicClient{
		client:  &http.Client{Timeout: 180 * time.Second}, // Increased timeout for consistency
		model:   model,
		baseURL: baseURL,
		apiKey:  token,
	}, nil
}

func (c *AnthropicClient) GenerateContent(ctx context.Context, systemPrompt, userPrompt string,
	options *GenerateOptions) (*GenerateResponse, error) {
	reqBody := buildAnthropicRequest(c.model, systemPrompt, userPrompt, options)

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("source", SOURCE)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func(r *http.Response) {
		_ = r.Body.Close()
	}(resp)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("%w: anthropic API error (status %d): %s", ErrRateLimited, resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("anthropic API error (status %d): %s", resp.StatusCode, string(body))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if len(anthropicResp.Content) == 0 {
		return nil, fmt.Errorf("no content in Anthropic response")
	}

	return &GenerateResponse{
		Content:      anthropicResp.Content[0].Text,
		InputTokens:  int32(anthropicResp.Usage.totalInputTokens()),
		OutputTokens: int32(anthropicResp.Usage.OutputTokens),
	}, nil
}

// GenerateWithTools drives one Anthropic tool-use turn using the Messages API.
func (c *AnthropicClient) GenerateWithTools(ctx context.Context, messages []Message, tools []ToolDefinition,
	options *GenerateOptions) (*ToolGenerateResponse, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("tool call requires messages")
	}
	reqBody := anthropicRequest{Model: c.model, MaxTokens: options.MaxTokens}
	start := 0
	if messages[0].Role == "system" {
		reqBody.System = []anthropicTextBlock{{Type: anthropicContentTypeText, Text: messages[0].Content}}
		start = 1
	}
	for _, tool := range tools {
		reqBody.Tools = append(reqBody.Tools, anthropicTool{Name: tool.Name, Description: tool.Description, InputSchema: tool.Parameters})
	}
	for _, message := range messages[start:] {
		reqBody.Messages = append(reqBody.Messages, anthropicMessage{Role: anthropicRole(message.Role), Content: anthropicContentForMessage(message, messages)})
	}
	if len(tools) == 0 && options.Schema.JsonSchema != nil {
		reqBody.OutputConfig = &anthropicOutputConfig{ResponseFormat: &anthropicResponseFormat{Type: "json_schema", JSONSchema: options.Schema.JsonSchema}}
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/v1/messages", bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("source", SOURCE)
	response, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("%w: anthropic API error %s", ErrRateLimited, string(body))
		}
		return nil, fmt.Errorf("anthropic API error %s", string(body))
	}
	var decoded anthropicResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, err
	}
	result := &ToolGenerateResponse{InputTokens: int32(decoded.Usage.totalInputTokens()), OutputTokens: int32(decoded.Usage.OutputTokens)}
	for _, content := range decoded.Content {
		if content.Type == "tool_use" {
			arguments, _ := json.Marshal(content.Input)
			result.ToolCalls = append(result.ToolCalls, ToolCall{ID: content.ID, Name: content.Name, Arguments: string(arguments)})
		} else if content.Type == "text" {
			result.Content += content.Text
		}
	}
	return result, nil
}

func anthropicRole(role string) string {
	if role == "assistant" {
		return "assistant"
	}
	return "user"
}
func anthropicContentForMessage(message Message, messages []Message) any {
	if message.Role == "assistant" && len(message.ToolCalls) > 0 {
		blocks := make([]map[string]any, 0, len(message.ToolCalls)+1)
		if message.Content != "" {
			blocks = append(blocks, map[string]any{"type": "text", "text": message.Content})
		}
		for _, call := range message.ToolCalls {
			var input map[string]any
			_ = json.Unmarshal([]byte(call.Arguments), &input)
			blocks = append(blocks, map[string]any{"type": "tool_use", "id": call.ID, "name": call.Name, "input": input})
		}
		return blocks
	}
	if message.Role == "tool" {
		return []map[string]any{{"type": "tool_result", "tool_use_id": message.ToolCallID, "content": message.Content}}
	}
	return message.Content
}

func (usage anthropicUsage) totalInputTokens() int {
	return usage.InputTokens + usage.CacheCreationInputTokens + usage.CacheReadInputTokens
}

func buildAnthropicRequest(model, systemPrompt, userPrompt string, options *GenerateOptions) anthropicRequest {
	messageContent := any(userPrompt)
	if cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix(userPrompt); cacheablePrefix != "" {
		messageContent = []anthropicTextBlock{
			{
				Type: anthropicContentTypeText,
				Text: cacheablePrefix,
				CacheControl: &anthropicCacheControl{
					Type: anthropicCacheControlTypeEphemeral,
				},
			},
			{
				Type: anthropicContentTypeText,
				Text: dynamicSuffix,
			},
		}
	}

	reqBody := anthropicRequest{
		Model:     model,
		MaxTokens: options.MaxTokens,
		System: []anthropicTextBlock{
			{
				Type: anthropicContentTypeText,
				Text: systemPrompt,
				CacheControl: &anthropicCacheControl{
					Type: anthropicCacheControlTypeEphemeral,
				},
			},
		},
		Messages: []anthropicMessage{
			{
				Role:    "user",
				Content: messageContent,
			},
		},
	}

	// Add response format with schema if provided
	if options.Schema.JsonSchema != nil {
		reqBody.OutputConfig = &anthropicOutputConfig{
			ResponseFormat: &anthropicResponseFormat{
				Type:       "json_schema",
				JSONSchema: options.Schema.JsonSchema,
			},
		}
	}
	return reqBody
}
