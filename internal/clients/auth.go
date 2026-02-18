package clients

import (
	"context"
	"fmt"
	"os"

	"github.com/DataDog/datadog-saist/internal/model"
)

const (
	SOURCE = "datadog-ai-static-analyzer"
)

type TokenGetter interface {
	Get(ctx context.Context) (string, error)
}

// Provider-specific API key storage
var providedAPIKeys = make(map[string]string)

func SetProvidedAPIKey(provider, key string) {
	providedAPIKeys[provider] = key
}

func GetProvidedAPIKey(provider string) string {
	return providedAPIKeys[provider]
}

func GetHost(provider, customURL string) string {
	if customURL != "" {
		return customURL
	}

	switch provider {
	case model.ProviderOpenAI:
		// Check for OPENAI_HOST first
		if host := os.Getenv("OPENAI_HOST"); host != "" {
			return "https://" + host
		}
		// Fall back to OPENAI_BASE_URL
		if host := os.Getenv("OPENAI_BASE_URL"); host != "" {
			return host
		}
		return "https://api.openai.com"
	case model.ProviderAnthropic:
		if host := os.Getenv("ANTHROPIC_BASE_URL"); host != "" {
			return host
		}
		return "https://api.anthropic.com"
	default:
		return ""
	}
}

func GetTokenGetter(provider string) TokenGetter {
	switch provider {
	case model.ProviderOpenAI:
		return &OpenAITokenGetter{}
	case model.ProviderAnthropic:
		return &AnthropicTokenGetter{}
	case model.ProviderGoogle:
		return &GeminiTokenGetter{}
	default:
		return &DefaultTokenGetter{provider: provider}
	}
}

type OpenAITokenGetter struct{}

func (t *OpenAITokenGetter) Get(ctx context.Context) (string, error) {
	// Check programmatically provided key first (from RunAnalysis function params)
	if key := GetProvidedAPIKey(model.ProviderOpenAI); key != "" {
		return key, nil
	}

	// For CLI usage, check environment variables
	// Check for bearer token first
	if bearerToken := os.Getenv("OPENAI_BEARER_TOKEN"); bearerToken != "" {
		return bearerToken, nil
	}

	// Fall back to standard OpenAI API key from environment
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return key, nil
	}

	return "", fmt.Errorf("no OpenAI authentication found: provide via function parameter or set OPENAI_API_KEY/OPENAI_BEARER_TOKEN env var")
}

type AnthropicTokenGetter struct{}

func (t *AnthropicTokenGetter) Get(ctx context.Context) (string, error) {
	// Check programmatically provided key first (from RunAnalysis function params)
	if key := GetProvidedAPIKey(model.ProviderAnthropic); key != "" {
		return key, nil
	}

	// For CLI usage, check environment variables
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return key, nil
	}

	return "", fmt.Errorf("no Anthropic authentication found: provide via function parameter or set ANTHROPIC_API_KEY env var")
}

type GeminiTokenGetter struct{}

func (t *GeminiTokenGetter) Get(ctx context.Context) (string, error) {
	// Check programmatically provided key first (from RunAnalysis function params)
	if key := GetProvidedAPIKey(model.ProviderGoogle); key != "" {
		return key, nil
	}

	// For CLI usage, check environment variables
	if key := os.Getenv("GOOGLE_API_KEY"); key != "" {
		return key, nil
	}

	return "", fmt.Errorf("no Gemini authentication found: provide via function parameter or set GOOGLE_API_KEY env var")
}

type DefaultTokenGetter struct {
	provider string
}

func (t *DefaultTokenGetter) Get(ctx context.Context) (string, error) {
	// Check programmatically provided key first (from RunAnalysis function params)
	if key := GetProvidedAPIKey(t.provider); key != "" {
		return key, nil
	}

	// For CLI usage, fallback to environment variable pattern
	if key := os.Getenv(t.provider + "_API_KEY"); key != "" {
		return key, nil
	}

	return "", fmt.Errorf("no %s authentication found: provide via function parameter or set %s_API_KEY env var", t.provider, t.provider)
}
