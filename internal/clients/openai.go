package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
)

type OpenAIClient struct {
	client openai.Client
	model  string
}

const (
	source = "k9-saist"

	// AI Guard header keys for AI Gateway integration
	// https://datadoghq.atlassian.net/wiki/spaces/AIP/pages/5850009053/AI+Guard+integration+into+AI+Gateway

	// AIGuardModeHeader controls how AI Guard enforces its decision.
	//   - "shadow": AI Guard evaluates but never blocks the request.
	//   - "enforce": AI Guard may block the request (HTTP 422) on DENY/ABORT.
	AIGuardModeHeader = "x-ai-guard-mode"

	AiGuardModeShadow = "shadow" // shadow value for AIGuardModeHeader

	// AIGuardServiceEnvHeader identifies the environment of the calling service
	// (e.g. "staging", "prod") and is forwarded to AI Guard for attribution and logging.
	AIGuardServiceEnvHeader = "x-ai-guard-service-env"

	// AIGuardServiceNameHeader identifies the calling service name and is forwarded
	// to AI Guard for attribution, analytics, and allowlist/denylist logic.
	AIGuardServiceNameHeader = "x-ai-guard-service-name"

	AIGuardActionAllow = "ALLOW" // ALLOW value returned by AIGuard

	// AIGuardActionRequestHeader is returned by AI Gateway and indicates AI Guard's
	// decision (ALLOW/DENY/ABORT/CLIENT_ERROR) for the request phase check
	// (the user prompt).
	AIGuardActionRequestHeader = "x-ai-guard-action-request"

	// AIGuardActionResponseHeader is returned by AI Gateway and indicates AI Guard's
	// decision (ALLOW/DENY/ABORT/CLIENT_ERROR) for the response phase check
	// (model response).
	AIGuardActionResponseHeader = "x-ai-guard-action-response"
)

func NewOpenAIClient(ctx context.Context, model string, baseURL string, isAIGateway bool, aiGuardEnabled bool,
	orgID int64, isCustom bool) (*OpenAIClient, error) {
	host := GetHost("openai", baseURL)
	token, err := GetTokenGetter("openai").Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get OpenAI token: %w", err)
	}

	if token == "" {
		return nil, fmt.Errorf("OpenAI API key not provided via CLI flag or environment variables")
	}

	// Build client options with timeout configuration
	httpClient := &http.Client{
		Timeout: 180 * time.Second, // Set a generous client-level timeout
	}

	// Construct the API base URL - AI Gateway expects /v1 suffix
	apiBaseURL := host + "/v1"

	env := os.Getenv("DD_ENV")
	if env == "" {
		env = os.Getenv("dd_env")
	}

	// Debug: log the constructed URL
	if os.Getenv("DEBUG") != "" || baseURL != "" {
		log.FromContext(ctx).Debugf("OpenAI client using base URL: %s (original: %s)", apiBaseURL, baseURL)
	}

	clientOptions := []option.RequestOption{
		option.WithAPIKey(token),
		option.WithBaseURL(apiBaseURL),
		option.WithHTTPClient(httpClient),
	}

	if isAIGateway {
		clientOptions = append(clientOptions,
			option.WithHeader("source", source),
			option.WithHeader("org-id", fmt.Sprintf("%d", orgID)),
		)
		if aiGuardEnabled && !isCustom {
			clientOptions = append(clientOptions,
				option.WithHeader(AIGuardModeHeader, AiGuardModeShadow),
				option.WithHeader(AIGuardServiceEnvHeader, env),
				option.WithHeader(AIGuardServiceNameHeader, source))
		}
	}

	// Add custom headers from environment if specified
	if headersStr := os.Getenv("OPENAI_HEADERS"); headersStr != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersStr), &headers); err != nil {
			return nil, fmt.Errorf("failed to parse OPENAI_HEADERS: %w", err)
		}

		for key, value := range headers {
			clientOptions = append(clientOptions, option.WithHeader(key, value))
		}
	}

	// Override with bearer token if specified
	if bearerToken := os.Getenv("OPENAI_BEARER_TOKEN"); bearerToken != "" {
		clientOptions = append(clientOptions, option.WithHeader("Authorization", "Bearer "+bearerToken))
	}

	client := openai.NewClient(clientOptions...)
	return &OpenAIClient{
		client: client,
		model:  model,
	}, nil
}

func (c *OpenAIClient) GenerateContent(ctx context.Context, systemPrompt, userPrompt string,
	options *GenerateOptions) (*GenerateResponse, error) {
	params := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(systemPrompt),
			openai.UserMessage(userPrompt),
		},
		Model:       c.model,
		Temperature: openai.Float(options.Temperature),
		ResponseFormat: openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &openai.ResponseFormatJSONSchemaParam{JSONSchema: openai.ResponseFormatJSONSchemaJSONSchemaParam{
				Name:        options.Schema.Name,
				Description: openai.String(options.Schema.Description),
				Schema:      options.Schema.JsonSchema,
				Strict:      openai.Bool(true),
			}},
		},
	}

	// Some newer OpenAI models require MaxCompletionTokens instead of MaxTokens
	params.MaxCompletionTokens = openai.Int(int64(options.MaxTokens))

	completion, err := c.client.Chat.Completions.New(ctx, params)
	if err != nil {
		// Check for rate limit error (HTTP 429)
		var apiErr *openai.Error
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusTooManyRequests {
			return nil, fmt.Errorf("%w: %v", ErrRateLimited, err)
		}
		return nil, err
	}

	if len(completion.Choices) == 0 {
		return nil, fmt.Errorf("no response choices returned from OpenAI")
	}

	inputTokens := int32(0)
	outputTokens := int32(0)
	if completion.Usage.PromptTokens > 0 {
		inputTokens = int32(completion.Usage.PromptTokens)
		outputTokens = int32(completion.Usage.CompletionTokens)
	}

	return &GenerateResponse{
		Content:      completion.Choices[0].Message.Content,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
	}, nil
}
