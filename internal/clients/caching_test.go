package clients

import (
	"encoding/json"
	"testing"

	"github.com/google/generative-ai-go/genai"
	"github.com/stretchr/testify/assert"
)

func TestOpenAIPromptCacheKeyGroupsStableSystemPrompts(t *testing.T) {
	first := openAIPromptCacheKey("openai/gpt-4.1-nano", 123, "stable instructions",
		"stable rule\n\n## Analyzed File\n\nPath: first.go")
	second := openAIPromptCacheKey("openai/gpt-4.1-nano", 123, "stable instructions",
		"stable rule\n\n## Analyzed File\n\nPath: second.go")
	changedRule := openAIPromptCacheKey("openai/gpt-4.1-nano", 123, "stable instructions",
		"different rule\n\n## Analyzed File\n\nPath: first.go")
	changedOrg := openAIPromptCacheKey("openai/gpt-4.1-nano", 456, "stable instructions",
		"stable rule\n\n## Analyzed File\n\nPath: first.go")
	changedModel := openAIPromptCacheKey("gpt-5.2", 123, "stable instructions",
		"stable rule\n\n## Analyzed File\n\nPath: first.go")

	assert.NotEmpty(t, first)
	assert.Equal(t, first, second)
	assert.NotEqual(t, first, changedRule)
	assert.NotEqual(t, first, changedOrg)
	assert.NotEqual(t, first, changedModel)
}

func TestOpenAIPromptCacheKeySkipsNonOpenAIModels(t *testing.T) {
	assert.Empty(t, openAIPromptCacheKey("gemini/gemini-2.5-flash", 123, "stable instructions", "stable rule"))
	assert.Empty(t, openAIPromptCacheKey("custom-model", 123, "stable instructions", "stable rule"))
}

func TestOpenAIPromptCacheKeySkipsUnknownPromptShape(t *testing.T) {
	assert.Empty(t, openAIPromptCacheKey("openai/gpt-4.1-nano", 123, "stable instructions", "dynamic prompt"))
}

func TestSplitPromptCacheablePrefix_DetectionPrompt(t *testing.T) {
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix("stable rule\n\n## Analyzed File\n\nPath: first.go")

	assert.Equal(t, "stable rule", cacheablePrefix)
	assert.Equal(t, "\n\n## Analyzed File\n\nPath: first.go", dynamicSuffix)
}

func TestSplitPromptCacheablePrefix_VerificationPrompt(t *testing.T) {
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix("stable rule\n\n  Request-Specific Finding:\n  File: first.go")

	assert.Equal(t, "stable rule", cacheablePrefix)
	assert.Equal(t, "\n\n  Request-Specific Finding:\n  File: first.go", dynamicSuffix)
}

func TestSplitPromptCacheablePrefix_LocationPrompt(t *testing.T) {
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix("stable rule\n\nRequest-Specific Finding:\nFile: first.go")

	assert.Equal(t, "stable rule", cacheablePrefix)
	assert.Equal(t, "\n\nRequest-Specific Finding:\nFile: first.go", dynamicSuffix)
}

func TestSplitPromptCacheablePrefix_UnknownPrompt(t *testing.T) {
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix("prompt without known boundary")

	assert.Empty(t, cacheablePrefix)
	assert.Equal(t, "prompt without known boundary", dynamicSuffix)
}

func TestBuildAnthropicRequestCachesStableSystemPrompt(t *testing.T) {
	req := buildAnthropicRequest("claude-sonnet-4-5", "stable instructions", "dynamic request", &GenerateOptions{
		MaxTokens: 123,
	})

	body, err := json.Marshal(req)
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"model": "claude-sonnet-4-5",
		"max_tokens": 123,
		"system": [{
			"type": "text",
			"text": "stable instructions",
			"cache_control": {"type": "ephemeral"}
		}],
		"messages": [{
			"role": "user",
			"content": "dynamic request"
		}]
	}`, string(body))
}

func TestAnthropicUsageTotalInputTokensIncludesCacheTokens(t *testing.T) {
	usage := anthropicUsage{
		InputTokens:              10,
		CacheCreationInputTokens: 20,
		CacheReadInputTokens:     30,
	}

	assert.Equal(t, 60, usage.totalInputTokens())
}

func TestBuildAnthropicRequestCachesStableUserPrefix(t *testing.T) {
	req := buildAnthropicRequest("claude-sonnet-4-5", "stable instructions",
		"stable rule\n\n## Analyzed File\n\nPath: first.go", &GenerateOptions{
			MaxTokens: 123,
		})

	body, err := json.Marshal(req)
	assert.NoError(t, err)
	assert.JSONEq(t, `{
		"model": "claude-sonnet-4-5",
		"max_tokens": 123,
		"system": [{
			"type": "text",
			"text": "stable instructions",
			"cache_control": {"type": "ephemeral"}
		}],
		"messages": [{
			"role": "user",
			"content": [{
				"type": "text",
				"text": "stable rule",
				"cache_control": {"type": "ephemeral"}
			}, {
				"type": "text",
				"text": "\n\n## Analyzed File\n\nPath: first.go"
			}]
		}]
	}`, string(body))
}

func TestSetGeminiSystemInstructionSeparatesStablePrompt(t *testing.T) {
	modelValue := &genai.GenerativeModel{}

	setGeminiSystemInstruction(modelValue, "stable instructions")

	assert.Equal(t, genai.NewUserContent(genai.Text("stable instructions")), modelValue.SystemInstruction)
}
