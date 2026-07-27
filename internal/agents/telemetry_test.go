package agents

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/stretchr/testify/assert"
)

func TestApplyModelCallOptionsRecordsGPT5ProviderDefaultTemperature(t *testing.T) {
	topP := 0.9
	options := &clients.GenerateOptions{
		MaxTokens:   1024,
		Temperature: 0,
		TopP:        &topP,
	}
	call := ModelCallTelemetry{}

	applyModelCallOptions(&call, "openai/gpt-5-mini", options)

	assert.Nil(t, call.Temperature)
	if assert.NotNil(t, call.TopP) {
		assert.Equal(t, topP, *call.TopP)
	}
	assert.Equal(t, 1024, call.MaxTokens)
}
