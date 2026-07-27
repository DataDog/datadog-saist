package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAIGPT52CodexUsesItsOwnModelIdentity(t *testing.T) {
	selected, err := GetModel(OpenAIGPT52CodexName)
	require.NoError(t, err)

	assert.NotEqual(t, OpenAIGPT52.ID, selected.ID)
	assert.Equal(t, "gpt-5.2-codex", selected.ToAPIModelWithFormat(false))
	assert.Equal(t, "openai/gpt-5.2-codex", selected.ToAPIModelWithFormat(true))
}

func TestOpenAIGPT52UsesItsOwnModelIdentity(t *testing.T) {
	selected, err := GetModel(OpenAIGPT52Name)
	require.NoError(t, err)

	assert.NotEqual(t, OpenAIGPT52Codex.ID, selected.ID)
	assert.Equal(t, "gpt-5.2", selected.ToAPIModelWithFormat(false))
	assert.Equal(t, "openai/gpt-5.2", selected.ToAPIModelWithFormat(true))
}
