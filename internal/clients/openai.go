package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openai/openai-go/v3/shared"
)

var protectedOpenAIHeaders = map[string]struct{}{
	"authorization":           {},
	"host":                    {},
	"org-id":                  {},
	"source":                  {},
	AIGuardModeHeader:         {},
	AIGuardServiceEnvHeader:   {},
	AIGuardServiceNameHeader:  {},
	AIGuardResponseSkipHeader: {},
}

type OpenAIClient struct {
	client openai.Client
	model  string
	source string
}

const (
	// SourceDefault is the default AI Gateway "source" header value, also used as
	// the AI-Guard service-name header, for the production SAIST verifier.
	SourceDefault = "k9-saist"

	// SourceAgenticBenchmark is the AI Gateway "source" header value used by the
	// agentic SAIST verifier benchmark so its traffic is attributable separately
	// from production verifier traffic.
	SourceAgenticBenchmark = "agentic-saist-verifier-benchmark"

	// source retains the default value for existing references in this package.
	source = SourceDefault

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

	// AIGuardResponseSkipHeader disables response-side analysis. The request is
	// the prompt-injection boundary, and response analysis adds serial latency.
	AIGuardResponseSkipHeader = "x-ai-guard-response-skip"

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

// NewOpenAIClient constructs an OpenAI-compatible client using the default AI
// Gateway source (SourceDefault). It preserves the original signature and
// behavior and delegates to NewOpenAIClientWithSource.
func NewOpenAIClient(ctx context.Context, model string, baseURL string, isAIGateway bool, aiGuardEnabled bool,
	orgID int64) (*OpenAIClient, error) {
	return NewOpenAIClientWithSource(ctx, model, baseURL, isAIGateway, aiGuardEnabled, orgID, SourceDefault)
}

// NewOpenAIClientWithSource constructs an OpenAI-compatible client and sets the
// AI Gateway "source" header (and the AI-Guard service-name header) to the
// provided source. Passing SourceDefault reproduces NewOpenAIClient behavior.
func NewOpenAIClientWithSource(ctx context.Context, model string, baseURL string, isAIGateway bool,
	aiGuardEnabled bool, orgID int64, source string) (*OpenAIClient, error) {
	host := GetHost("openai", baseURL)
	token, err := GetTokenGetter("openai").Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get OpenAI token: %w", err)
	}

	if token == "" {
		return nil, fmt.Errorf("OpenAI API key not provided via CLI flag or environment variables")
	}

	// Construct the API base URL - AI Gateway expects /v1 suffix
	apiBaseURL := strings.TrimSuffix(host, "/") + "/v1"

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
		option.WithMaxRetries(0),
	}

	if isAIGateway {
		clientOptions = append(clientOptions,
			option.WithHeader("source", source),
			option.WithHeader("org-id", fmt.Sprintf("%d", orgID)),
		)
		if aiGuardEnabled {
			clientOptions = append(clientOptions,
				option.WithHeader(AIGuardModeHeader, AiGuardModeShadow),
				option.WithHeader(AIGuardServiceEnvHeader, env),
				option.WithHeader(AIGuardServiceNameHeader, source),
				option.WithHeader(AIGuardResponseSkipHeader, "true"))
		}
	}

	// Add custom headers from environment if specified
	if headersStr := os.Getenv("OPENAI_HEADERS"); headersStr != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersStr), &headers); err != nil {
			return nil, fmt.Errorf("failed to parse OPENAI_HEADERS: %w", err)
		}

		for key, value := range headers {
			if _, protected := protectedOpenAIHeaders[strings.ToLower(strings.TrimSpace(key))]; protected {
				return nil, fmt.Errorf("OPENAI_HEADERS cannot set protected header %q", key)
			}
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
		source: source,
	}, nil
}

func (c *OpenAIClient) GenerateContent(ctx context.Context, systemPrompt, userPrompt string,
	options *GenerateOptions) (*GenerateResponse, error) {
	params := openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.SystemMessage(systemPrompt),
			openai.UserMessage(userPrompt),
		},
		Model: c.model,
		ResponseFormat: openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &openai.ResponseFormatJSONSchemaParam{JSONSchema: openai.ResponseFormatJSONSchemaJSONSchemaParam{
				Name:        options.Schema.Name,
				Description: openai.String(options.Schema.Description),
				Schema:      options.Schema.JsonSchema,
				Strict:      openai.Bool(true),
			}},
		},
	}
	temperature, topP := AppliedSampling(c.model, options)
	if temperature != nil {
		params.Temperature = openai.Float(*temperature)
	}
	if topP != nil {
		params.TopP = openai.Float(*topP)
	}

	// Some newer OpenAI models require MaxCompletionTokens instead of MaxTokens.
	// A zero value leaves the provider response length unbounded by this client.
	if options.MaxTokens > 0 {
		params.MaxCompletionTokens = openai.Int(int64(options.MaxTokens))
	}

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

	// TODO(agentic-saist-verifier-benchmark) capture the AI Gateway request ID
	// and Datadog trace and span IDs from the response headers so verifier runs
	// are traceable end to end. Deferred, needs the raw HTTP response.
	return &GenerateResponse{
		Content:       completion.Choices[0].Message.Content,
		ReturnedModel: completion.Model,
		InputTokens:   inputTokens,
		OutputTokens:  outputTokens,
		UsageKnown:    completion.Usage.PromptTokens > 0 || completion.Usage.CompletionTokens > 0,
	}, nil
}

// GenerateWithTools drives one tool-capable generation turn. It translates the
// provider-agnostic message list and tool definitions into the openai-go SDK,
// returns any tool calls the model requested, and reports token usage. When no
// tools are offered it forces the strict JSON ResponseFormat from options.Schema
// so the final loop turn always yields a parseable answer. While tools ARE
// offered, ResponseFormat is intentionally omitted because strict JSON
// suppresses tool calls on several providers. ToolChoice is left unset (auto).
func (c *OpenAIClient) GenerateWithTools(ctx context.Context, messages []Message,
	tools []ToolDefinition, options *GenerateOptions) (*ToolGenerateResponse, error) {
	params := openai.ChatCompletionNewParams{
		Messages: toOpenAIMessages(messages),
		Model:    c.model,
	}
	temperature, topP := AppliedSampling(c.model, options)
	if temperature != nil {
		params.Temperature = openai.Float(*temperature)
	}
	if topP != nil {
		params.TopP = openai.Float(*topP)
	}
	// Some newer OpenAI models require MaxCompletionTokens instead of MaxTokens.
	// A zero value leaves the provider response length unbounded by this client.
	if options.MaxTokens > 0 {
		params.MaxCompletionTokens = openai.Int(int64(options.MaxTokens))
	}

	if len(tools) > 0 {
		toolParams := make([]openai.ChatCompletionToolUnionParam, 0, len(tools))
		for _, t := range tools {
			fnDef := shared.FunctionDefinitionParam{
				Name:        t.Name,
				Description: openai.String(t.Description),
			}
			if paramMap, ok := t.Parameters.(map[string]any); ok {
				fnDef.Parameters = shared.FunctionParameters(paramMap)
			}
			toolParams = append(toolParams, openai.ChatCompletionFunctionTool(fnDef))
		}
		params.Tools = toolParams
	} else if options.Schema.JsonSchema != nil {
		params.ResponseFormat = openai.ChatCompletionNewParamsResponseFormatUnion{
			OfJSONSchema: &openai.ResponseFormatJSONSchemaParam{JSONSchema: openai.ResponseFormatJSONSchemaJSONSchemaParam{
				Name:        options.Schema.Name,
				Description: openai.String(options.Schema.Description),
				Schema:      options.Schema.JsonSchema,
				Strict:      openai.Bool(true),
			}},
		}
	}

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

	choice := completion.Choices[0]

	var toolCalls []ToolCall
	for _, tc := range choice.Message.ToolCalls {
		// Only function tool calls are issued by this client. Ignore any custom
		// tool calls (their Function fields are empty).
		if tc.Function.Name == "" {
			continue
		}
		toolCalls = append(toolCalls, ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}

	inputTokens := int32(0)
	outputTokens := int32(0)
	if completion.Usage.PromptTokens > 0 {
		inputTokens = int32(completion.Usage.PromptTokens)
		outputTokens = int32(completion.Usage.CompletionTokens)
	}

	// TODO(agentic-saist-verifier-benchmark) capture the AI Gateway request ID
	// and Datadog trace and span IDs from the response headers so verifier runs
	// are traceable end to end. Deferred, needs the raw HTTP response.
	return &ToolGenerateResponse{
		Content:       choice.Message.Content,
		ToolCalls:     toolCalls,
		FinishReason:  choice.FinishReason,
		ReturnedModel: completion.Model,
		InputTokens:   inputTokens,
		OutputTokens:  outputTokens,
		UsageKnown:    completion.Usage.PromptTokens > 0 || completion.Usage.CompletionTokens > 0,
	}, nil
}

func shouldSendOpenAITemperature(model string) bool {
	normalized := strings.TrimPrefix(strings.ToLower(model), "openai/")
	return !strings.HasPrefix(normalized, openAIGPT5ModelPrefix)
}

// toOpenAIMessages translates the provider-agnostic message list into the
// openai-go message union list, preserving assistant tool-call turns and tool
// result turns so multi-turn tool loops replay correctly.
func toOpenAIMessages(messages []Message) []openai.ChatCompletionMessageParamUnion {
	out := make([]openai.ChatCompletionMessageParamUnion, 0, len(messages))
	for _, m := range messages {
		switch m.Role {
		case "system":
			out = append(out, openai.SystemMessage(m.Content))
		case "tool":
			out = append(out, openai.ToolMessage(m.Content, m.ToolCallID))
		case "assistant":
			msg := openai.AssistantMessage(m.Content)
			if msg.OfAssistant != nil {
				for _, tc := range m.ToolCalls {
					msg.OfAssistant.ToolCalls = append(msg.OfAssistant.ToolCalls,
						openai.ChatCompletionMessageToolCallUnionParam{
							OfFunction: &openai.ChatCompletionMessageFunctionToolCallParam{
								ID: tc.ID,
								Function: openai.ChatCompletionMessageFunctionToolCallFunctionParam{
									Name:      tc.Name,
									Arguments: tc.Arguments,
								},
							},
						})
				}
			}
			out = append(out, msg)
		default:
			// "user" and any unrecognized role fall back to a user message so no
			// context is silently dropped.
			out = append(out, openai.UserMessage(m.Content))
		}
	}
	return out
}
