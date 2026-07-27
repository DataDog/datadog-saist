package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAIGPT5OmitsUnsupportedTemperature(t *testing.T) {
	requestBodies := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		requestBodies <- body
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{
  "id":"completion-one",
  "object":"chat.completion",
  "created":1,
  "model":"openai/gpt-5-mini",
  "choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`)
	}))
	defer server.Close()

	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("OPENAI_BEARER_TOKEN", "")

	client, err := NewOpenAIClient(context.Background(), "openai/gpt-5-mini", server.URL,
		false, false, 0)
	require.NoError(t, err)
	response, err := client.GenerateContent(context.Background(), "system", "user", &GenerateOptions{
		MaxTokens:   10,
		Temperature: 0,
		Schema: GenerateOptionSchema{
			Name:        "result",
			Description: "test result",
			JsonSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
			},
		},
	})
	require.NoError(t, err)
	if assert.NotNil(t, response) {
		assert.True(t, response.UsageKnown)
		assert.Equal(t, "openai/gpt-5-mini", response.ReturnedModel)
	}

	var requestBody map[string]any
	require.NoError(t, json.Unmarshal(<-requestBodies, &requestBody))
	_, present := requestBody["temperature"]
	assert.False(t, present)
}

func TestOpenAIUnboundedGenerationOmitsCompletionTokenLimit(t *testing.T) {
	requestBodies := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		requestBodies <- body
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{
  "id":"completion-one",
  "object":"chat.completion",
  "created":1,
  "model":"openai/gpt-5-mini",
  "choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`)
	}))
	defer server.Close()

	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("OPENAI_BEARER_TOKEN", "")

	client, err := NewOpenAIClient(context.Background(), "openai/gpt-5-mini", server.URL,
		false, false, 0)
	require.NoError(t, err)
	_, err = client.GenerateContent(context.Background(), "system", "user", &GenerateOptions{
		MaxTokens: 0,
		Schema: GenerateOptionSchema{
			Name:        "result",
			Description: "test result",
			JsonSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
			},
		},
	})
	require.NoError(t, err)

	var requestBody map[string]any
	require.NoError(t, json.Unmarshal(<-requestBodies, &requestBody))
	_, present := requestBody["max_completion_tokens"]
	assert.False(t, present)
}

func TestOpenAIGPT5ToolRequestOmitsUnsupportedTemperature(t *testing.T) {
	requestBodies := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		requestBodies <- body
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{
  "id":"completion-one",
  "object":"chat.completion",
  "created":1,
  "model":"openai/gpt-5-mini",
  "choices":[{"index":0,"message":{"role":"assistant","content":"done"},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`)
	}))
	defer server.Close()

	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("OPENAI_BEARER_TOKEN", "")

	client, err := NewOpenAIClient(context.Background(), "openai/gpt-5-mini", server.URL,
		false, false, 0)
	require.NoError(t, err)
	response, err := client.GenerateWithTools(context.Background(), []Message{
		{Role: "system", Content: "system"},
		{Role: "user", Content: "user"},
	}, []ToolDefinition{{
		Name: "read_file", Description: "read one file",
		Parameters: map[string]any{"type": "object"},
	}}, &GenerateOptions{MaxTokens: 10, Temperature: 1})
	require.NoError(t, err)
	if assert.NotNil(t, response) {
		assert.True(t, response.UsageKnown)
		assert.Equal(t, "openai/gpt-5-mini", response.ReturnedModel)
	}

	var requestBody map[string]any
	require.NoError(t, json.Unmarshal(<-requestBodies, &requestBody))
	_, present := requestBody["temperature"]
	assert.False(t, present)
}

func TestOpenAIDisablesAutomaticHTTPRetries(t *testing.T) {
	var requestCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		current := requestCount.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		if current == 1 {
			writer.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(writer, `{"error":{"message":"retryable failure","type":"server_error"}}`)
			return
		}
		_, _ = io.WriteString(writer, `{
  "id":"completion-one",
  "object":"chat.completion",
  "created":1,
  "model":"openai/test-model",
  "choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`)
	}))
	defer server.Close()

	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("OPENAI_BEARER_TOKEN", "")

	client, err := NewOpenAIClient(context.Background(), "openai/test-model", server.URL,
		false, false, 0)
	require.NoError(t, err)
	response, err := client.GenerateContent(context.Background(), "system", "user", &GenerateOptions{
		MaxTokens:   10,
		Temperature: 1,
		Schema: GenerateOptionSchema{
			Name:        "result",
			Description: "test result",
			JsonSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
			},
		},
	})

	require.Error(t, err)
	assert.Nil(t, response)
	assert.Equal(t, int32(1), requestCount.Load())
}

func TestOpenAIAIGuardHeadersUseShadowRequestOnlyAnalysis(t *testing.T) {
	headers := make(chan http.Header, 1)
	paths := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers <- request.Header.Clone()
		paths <- request.URL.Path
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{
  "id":"completion-one",
  "object":"chat.completion",
  "created":1,
  "model":"openai/test-model",
  "choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`)
	}))
	defer server.Close()

	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("DD_ENV", "test")
	t.Setenv("OPENAI_BEARER_TOKEN", "")
	t.Setenv("OPENAI_HEADERS", `{"x-experiment-id":"experiment-one"}`)

	client, err := NewOpenAIClient(context.Background(), "openai/test-model", server.URL+"/",
		true, true, 2)
	require.NoError(t, err)
	_, err = client.GenerateContent(context.Background(), "system", "user", &GenerateOptions{
		MaxTokens:   10,
		Temperature: 1,
		Schema: GenerateOptionSchema{
			Name:        "result",
			Description: "test result",
			JsonSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
			},
		},
	})
	require.NoError(t, err)

	requestHeaders := <-headers
	assert.Equal(t, "/v1/chat/completions", <-paths)
	assert.Equal(t, "Bearer test-token", requestHeaders.Get("Authorization"))
	assert.Equal(t, source, requestHeaders.Get("source"))
	assert.Equal(t, "2", requestHeaders.Get("org-id"))
	assert.Equal(t, AiGuardModeShadow, requestHeaders.Get(AIGuardModeHeader))
	assert.Equal(t, "test", requestHeaders.Get(AIGuardServiceEnvHeader))
	assert.Equal(t, source, requestHeaders.Get(AIGuardServiceNameHeader))
	assert.Equal(t, "true", requestHeaders.Get(AIGuardResponseSkipHeader))
	assert.Equal(t, "experiment-one", requestHeaders.Get("x-experiment-id"))
}

func TestOpenAIHeadersRejectAuthorizationOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "aUtHoRiZaTiOn")
}

func TestOpenAIHeadersRejectHostOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "Host")
}

func TestOpenAIHeadersRejectSourceOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "SoUrCe")
}

func TestOpenAIHeadersRejectOrganizationOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "ORG-ID")
}

func TestOpenAIHeadersRejectGuardModeOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "X-AI-Guard-Mode")
}

func TestOpenAIHeadersRejectGuardEnvironmentOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "X-AI-Guard-Service-Env")
}

func TestOpenAIHeadersRejectGuardServiceOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "X-AI-Guard-Service-Name")
}

func TestOpenAIHeadersRejectResponseSkipOverride(t *testing.T) {
	assertOpenAIProtectedHeaderRejected(t, "X-AI-Guard-Response-Skip")
}

func assertOpenAIProtectedHeaderRejected(t *testing.T, header string) {
	t.Helper()
	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("OPENAI_BEARER_TOKEN", "")
	t.Setenv("OPENAI_HEADERS", fmt.Sprintf(`{"%s":"attacker-controlled"}`, header))

	_, err := NewOpenAIClient(context.Background(), "openai/test-model", "https://example.com",
		true, true, 2)

	assert.EqualError(t, err, fmt.Sprintf("OPENAI_HEADERS cannot set protected header %q", header))
}

func TestNewOpenAIClientWithSourceCarriesBenchmarkSourceHeaders(t *testing.T) {
	headers := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		headers <- request.Header.Clone()
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{
  "id":"completion-one",
  "object":"chat.completion",
  "created":1,
  "model":"openai/test-model",
  "choices":[{"index":0,"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}],
  "usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}
}`)
	}))
	defer server.Close()

	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("DD_ENV", "test")
	t.Setenv("OPENAI_BEARER_TOKEN", "")

	client, err := NewOpenAIClientWithSource(context.Background(), "openai/test-model", server.URL,
		true, true, 2, SourceAgenticBenchmark)
	require.NoError(t, err)
	assert.Equal(t, SourceAgenticBenchmark, client.source)

	_, err = client.GenerateContent(context.Background(), "system", "user", &GenerateOptions{
		MaxTokens:   10,
		Temperature: 1,
		Schema: GenerateOptionSchema{
			Name:        "result",
			Description: "test result",
			JsonSchema: map[string]any{
				"type":                 "object",
				"additionalProperties": false,
			},
		},
	})
	require.NoError(t, err)

	requestHeaders := <-headers
	assert.Equal(t, SourceAgenticBenchmark, requestHeaders.Get("source"))
	assert.Equal(t, SourceAgenticBenchmark, requestHeaders.Get(AIGuardServiceNameHeader))
}

func TestNewOpenAIClientUsesDefaultSource(t *testing.T) {
	previousKey := GetProvidedAPIKey("openai")
	SetProvidedAPIKey("openai", "test-token")
	defer SetProvidedAPIKey("openai", previousKey)
	t.Setenv("OPENAI_BEARER_TOKEN", "")

	client, err := NewOpenAIClient(context.Background(), "openai/test-model", "https://example.com",
		true, true, 2)
	require.NoError(t, err)
	assert.Equal(t, SourceDefault, client.source)
}
