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
	Type string `json:"type"`
	Text string `json:"text"`
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
