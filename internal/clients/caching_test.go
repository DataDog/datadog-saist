package clients

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/generative-ai-go/genai"
	"github.com/stretchr/testify/assert"
)

const (
	testOpenAIModel    = "openai/gpt-4.1-nano"
	testAnthropicModel = "claude-sonnet-4-5"
	testOrgID          = int64(123)
	testSystemPrompt   = "stable instructions"
	testStableRule     = "stable rule"
)

func detectionPrompt(rule, filePath string) string {
	return fmt.Sprintf("%s\n\n## Analyzed File\n\nPath: %s", rule, filePath)
}

func TestOpenAIPromptCacheKeyGroupsStableSystemPrompts(t *testing.T) {
	base := openAIPromptCacheKey(testOpenAIModel, testOrgID, testSystemPrompt, detectionPrompt(testStableRule, "first.go"))

	sameExceptFile := openAIPromptCacheKey(testOpenAIModel, testOrgID, testSystemPrompt, detectionPrompt(testStableRule, "second.go"))
	differentRule := openAIPromptCacheKey(testOpenAIModel, testOrgID, testSystemPrompt, detectionPrompt("different rule", "first.go"))
	differentOrg := openAIPromptCacheKey(testOpenAIModel, int64(456), testSystemPrompt, detectionPrompt(testStableRule, "first.go"))
	differentModel := openAIPromptCacheKey("gpt-5.2", testOrgID, testSystemPrompt, detectionPrompt(testStableRule, "first.go"))

	assert.NotEmpty(t, base)
	assert.Equal(t, base, sameExceptFile)
	assert.NotEqual(t, base, differentRule)
	assert.NotEqual(t, base, differentOrg)
	assert.NotEqual(t, base, differentModel)
}

func TestIsOpenAIModelName(t *testing.T) {
	matches := []string{
		"openai/gpt-4.1-nano", "gpt-4o", "chatgpt-4o-latest", "codex-mini",
		"o1", "o1-mini", "o1-preview",
		"o3", "o3-mini",
		"o4", "o4-mini",
	}
	for _, m := range matches {
		assert.True(t, isOpenAIModelName(m), "expected %q to be recognised as an OpenAI model", m)
	}

	nonMatches := []string{"gemini/gemini-2.5-flash", "custom-model", "o10-nova", "o13-turbo"}
	for _, m := range nonMatches {
		assert.False(t, isOpenAIModelName(m), "expected %q NOT to be recognised as an OpenAI model", m)
	}
}

func TestOpenAIPromptCacheKeySkipsNonOpenAIModels(t *testing.T) {
	assert.Empty(t, openAIPromptCacheKey("gemini/gemini-2.5-flash", testOrgID, testSystemPrompt, testStableRule))
	assert.Empty(t, openAIPromptCacheKey("custom-model", testOrgID, testSystemPrompt, testStableRule))
}

func TestOpenAIPromptCacheKeySkipsUnknownPromptShape(t *testing.T) {
	assert.Empty(t, openAIPromptCacheKey(testOpenAIModel, testOrgID, testSystemPrompt, "dynamic prompt without known boundary"))
}

func TestSplitPromptCacheablePrefix_DetectionPrompt(t *testing.T) {
	filePath := "first.go"
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix(detectionPrompt(testStableRule, filePath))

	assert.Equal(t, testStableRule, cacheablePrefix)
	assert.Equal(t, "\n\n## Analyzed File\n\nPath: "+filePath, dynamicSuffix)
}

func TestSplitPromptCacheablePrefix_VerificationPrompt(t *testing.T) {
	filePath := "first.go"
	input := fmt.Sprintf("%s\n\n  Request-Specific Finding:\n  File: %s", testStableRule, filePath)
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix(input)

	assert.Equal(t, testStableRule, cacheablePrefix)
	assert.Equal(t, "\n\n  Request-Specific Finding:\n  File: "+filePath, dynamicSuffix)
}

func TestSplitPromptCacheablePrefix_LocationPrompt(t *testing.T) {
	filePath := "first.go"
	input := fmt.Sprintf("%s\n\nRequest-Specific Finding:\nFile: %s", testStableRule, filePath)
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix(input)

	assert.Equal(t, testStableRule, cacheablePrefix)
	assert.Equal(t, "\n\nRequest-Specific Finding:\nFile: "+filePath, dynamicSuffix)
}

func TestSplitPromptCacheablePrefix_UnknownPrompt(t *testing.T) {
	input := "prompt without known boundary"
	cacheablePrefix, dynamicSuffix := splitPromptCacheablePrefix(input)

	assert.Empty(t, cacheablePrefix)
	assert.Equal(t, input, dynamicSuffix)
}

func TestBuildAnthropicRequestCachesStableSystemPrompt(t *testing.T) {
	req := buildAnthropicRequest(testAnthropicModel, testSystemPrompt, "dynamic request", &GenerateOptions{
		MaxTokens: 123,
	})

	body, err := json.Marshal(req)
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"model": %q,
		"max_tokens": 123,
		"system": [{
			"type": "text",
			"text": %q,
			"cache_control": {"type": "ephemeral"}
		}],
		"messages": [{
			"role": "user",
			"content": "dynamic request"
		}]
	}`, testAnthropicModel, testSystemPrompt), string(body))
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
	filePath := "first.go"
	req := buildAnthropicRequest(testAnthropicModel, testSystemPrompt, detectionPrompt(testStableRule, filePath), &GenerateOptions{
		MaxTokens: 123,
	})

	body, err := json.Marshal(req)
	assert.NoError(t, err)
	assert.JSONEq(t, fmt.Sprintf(`{
		"model": %q,
		"max_tokens": 123,
		"system": [{
			"type": "text",
			"text": %q,
			"cache_control": {"type": "ephemeral"}
		}],
		"messages": [{
			"role": "user",
			"content": [{
				"type": "text",
				"text": %q,
				"cache_control": {"type": "ephemeral"}
			}, {
				"type": "text",
				"text": "\n\n## Analyzed File\n\nPath: %s"
			}]
		}]
	}`, testAnthropicModel, testSystemPrompt, testStableRule, filePath), string(body))
}

func TestSetGeminiSystemInstructionSetsSystemInstruction(t *testing.T) {
	modelValue := &genai.GenerativeModel{}

	setGeminiSystemInstruction(modelValue, testSystemPrompt)

	assert.Equal(t, genai.NewUserContent(genai.Text(testSystemPrompt)), modelValue.SystemInstruction)
}
