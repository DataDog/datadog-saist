package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLunaDirectProviderModel(t *testing.T) {
	m, err := GetModelOrPassthrough("openai-gpt5.6-luna", false)
	assert.NoError(t, err)
	assert.True(t, m.IsOpenAI())
	assert.False(t, m.IsCustom())
	assert.Equal(t, "gpt-5.6-luna", m.ToAPIModel())
	assert.Contains(t, GetAllModelStrings(), "openai-gpt5.6-luna")
	byID, ok := GetModelByID(m.ID)
	assert.True(t, ok)
	assert.Equal(t, m, byID)
}

func TestLunaGatewayModel(t *testing.T) {
	m, err := GetModelOrPassthrough("openai-gpt5.6-luna", true)
	assert.NoError(t, err)
	assert.Equal(t, "openai/gpt-5.6-luna", m.ToAPIModelWithFormat(true))
}
