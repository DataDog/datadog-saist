package model

import (
	"fmt"
	"strings"
)

const (
	// Provider names
	ProviderOpenAI    = "openai"
	ProviderAnthropic = "anthropic"
	ProviderGoogle    = "google"

	// OpenAI model names
	OpenAIGPT5MiniName   = "openai-gpt5-mini"
	OpenAIGPT52Name      = "openai-gpt5.2"
	OpenAIGPT52CodexName = "openai-gpt5.2-codex"

	// Anthropic model names
	Claude45SonnetName      = "claude-sonnet-4-5"
	Claude45SonnetInputName = "claude-4.5-sonnet"
	Claude45HaikuName       = "claude-haiku-4-5"
	Claude45HaikuInputName  = "claude-4.5-haiku"

	// Google model names
	Gemini25ProName       = "gemini-2.5-pro"
	Gemini25FlashName     = "gemini-2.5-flash"
	Gemini2FlashLiteName  = "gemini-2.0-flash-lite"
	Gemini3FlashName      = "gemini-3-flash-preview"
	Gemini3FlashInputName = "gemini-3-flash"

	// Mistral model names
	Devstral2Name = "devstral-2"

	// Qwen model names
	Qwen25Starcoder7bName = "qwen2.5-coder-7b"
)

type Model struct {
	ID          int
	Name        string
	Provider    string
	RawAPIModel string // When set, this is used directly for API calls (for custom AI Gateway models)
}

var (
	ModelUnknown = Model{ID: 0, Name: Unknown, Provider: Unknown}
	// OpenAI models
	OpenAIGPT5Mini   = Model{ID: 12, Name: OpenAIGPT5MiniName, Provider: ProviderOpenAI}
	OpenAIGPT52      = Model{ID: 13, Name: OpenAIGPT52Name, Provider: ProviderOpenAI}
	OpenAIGPT52Codex = Model{ID: 13, Name: OpenAIGPT52CodexName, Provider: ProviderOpenAI}

	// Anthropic models
	Claude45Sonnet = Model{ID: 34, Name: Claude45SonnetName, Provider: ProviderAnthropic}
	Claude45Haiku  = Model{ID: 35, Name: Claude45HaikuName, Provider: ProviderAnthropic}
	// Google models
	Gemini25Pro      = Model{ID: 51, Name: Gemini25ProName, Provider: ProviderGoogle}
	Gemini25Flash    = Model{ID: 52, Name: Gemini25FlashName, Provider: ProviderGoogle}
	Gemini2FlashLite = Model{ID: 53, Name: Gemini2FlashLiteName, Provider: ProviderGoogle}
	Gemini3Flash     = Model{ID: 54, Name: Gemini3FlashName, Provider: ProviderGoogle}
	// Mistral
	Devstral2 = Model{ID: 71, Name: Devstral2Name, Provider: "mistral"}
	// Qwen
	Qwen25Starcoder7b = Model{ID: 91, Name: Qwen25Starcoder7bName, Provider: "qwen"}
)

func (m Model) String() string {
	return m.Name
}

func GetModel(modelStr string) (Model, error) {
	cleanModelStr := strings.ToLower(strings.TrimSpace(modelStr))

	// Only support explicitly defined models
	switch cleanModelStr {
	case OpenAIGPT5MiniName:
		return OpenAIGPT5Mini, nil
	case OpenAIGPT52Name:
		return OpenAIGPT52, nil
	case OpenAIGPT52CodexName:
		return OpenAIGPT52Codex, nil
	case Claude45SonnetInputName:
		return Claude45Sonnet, nil
	case Claude45HaikuInputName:
		return Claude45Haiku, nil
	case Gemini25ProName:
		return Gemini25Pro, nil
	case Gemini25FlashName:
		return Gemini25Flash, nil
	case Gemini2FlashLiteName:
		return Gemini2FlashLite, nil
	case Gemini3FlashInputName:
		return Gemini3Flash, nil
	case Devstral2Name:
		return Devstral2, nil
	case Qwen25Starcoder7bName:
		return Qwen25Starcoder7b, nil

	default:
		availableModels := strings.Join(GetAllModelStrings(), ", ")
		return ModelUnknown, fmt.Errorf("unsupported model '%s'. Available models: %s", modelStr, availableModels)
	}
}

// GetModelOrPassthrough attempts to get a predefined model, but if allowPassthrough is true
// and the model is not found, it will accept any arbitrary string as a custom model.
// This is useful for AI Gateway scenarios where the model string can be arbitrary.
func GetModelOrPassthrough(modelStr string, allowPassthrough bool) (Model, error) {
	// Try predefined models first

	m, err := GetModel(modelStr)
	if err == nil {
		return m, nil
	}
	// If passthrough allowed (AI Gateway mode), accept any string
	if allowPassthrough {
		return Model{
			ID:          -1, // Negative ID for custom models
			Name:        modelStr,
			Provider:    Unknown,
			RawAPIModel: modelStr, // This being set indicates custom model
		}, nil
	}

	return ModelUnknown, err
}

func GetAllModels() []Model {
	return []Model{OpenAIGPT5Mini, Gemini25Pro, Gemini25Flash, Gemini2FlashLite, Gemini3Flash}
}

func GetAllModelStrings() []string {
	models := GetAllModels()
	result := make([]string, len(models))
	for i, model := range models {
		result[i] = model.String()
	}
	return result
}

// GetModelByID gets a model by its numeric ID and returns true if found, otherwise false.
func GetModelByID(id int) (Model, bool) {
	models := GetAllModels()
	for _, m := range models {
		if m.ID == id {
			return m, true
		}
	}
	return Model{}, false
}

func (m Model) ToAPIModel() string {
	return m.ToAPIModelWithFormat(false) // Default to direct provider format
}

func (m Model) ToAPIModelWithFormat(isAIGateway bool) string {
	// If RawAPIModel is set, this is a custom model - return it directly
	if m.RawAPIModel != "" {
		return m.RawAPIModel
	}

	if isAIGateway {
		return m.toAIGatewayFormat()
	}
	return m.toDirectProviderFormat()
}

func (m Model) toDirectProviderFormat() string {
	// Direct provider API format (original behavior)
	switch m.ID {
	case OpenAIGPT5Mini.ID:
		return "gpt-5-mini"
	case OpenAIGPT52.ID:
		return "gpt-5.2"
	case OpenAIGPT52Codex.ID:
		return "gpt-5.2-codex"
	case Gemini25Pro.ID:
		return Gemini25ProName
	case Gemini25Flash.ID:
		return Gemini25FlashName
	case Gemini2FlashLite.ID:
		return "gemini-2.0-flash-lite-preview"
	case Gemini3Flash.ID:
		return Gemini3FlashName
	case Claude45Sonnet.ID:
		return Claude45SonnetName
	case Claude45Haiku.ID:
		return Claude45HaikuName
	default:
		return Unknown
	}
}

func (m Model) toAIGatewayFormat() string {
	// AI Gateway expects provider/model format
	providerName := m.Provider
	if m.Provider == ProviderGoogle {
		providerName = "gemini" // AI Gateway uses "gemini" not "google"
	}

	switch m.ID {
	case OpenAIGPT5Mini.ID:
		return ProviderOpenAI + "/gpt-5-mini"
	case OpenAIGPT52.ID:
		return ProviderOpenAI + "/gpt-5.2"
	case OpenAIGPT52Codex.ID:
		return ProviderOpenAI + "/gpt-5.2-codex"
	case Claude45Sonnet.ID:
		return ProviderAnthropic + "/claude-sonnet-4-5-20250929"
	case Claude45Haiku.ID:
		return ProviderAnthropic + "/claude-3-haiku-20240307"
	case Gemini25Pro.ID:
		return "gemini/" + Gemini25ProName
	case Gemini25Flash.ID:
		return "gemini/" + Gemini25FlashName
	case Gemini3Flash.ID:
		return "gemini/" + Gemini3FlashName
	case Gemini2FlashLite.ID:
		return "gemini/gemini-2.0-flash-lite-preview"
	case Devstral2.ID:
		return "datadoginternal/mistralai/devstral-small-2"
	case Qwen25Starcoder7b.ID:
		return "datadoginternal/Qwen/Qwen2.5-Coder-7B"
	default:
		return providerName + "/" + m.Name
	}
}

func (m Model) IsOpenAI() bool {
	// Custom models (RawAPIModel set) return false
	if m.RawAPIModel != "" {
		return false
	}
	return m.Provider == ProviderOpenAI
}

func (m Model) IsAnthropic() bool {
	// Custom models (RawAPIModel set) return false
	if m.RawAPIModel != "" {
		return false
	}
	return m.Provider == ProviderAnthropic
}

func (m Model) IsGoogle() bool {
	// Custom models (RawAPIModel set) return false
	if m.RawAPIModel != "" {
		return false
	}
	return m.Provider == ProviderGoogle
}

func (m Model) IsCustom() bool {
	return m.RawAPIModel != ""
}

// RequiresMaxCompletionTokens returns true if this model requires MaxCompletionTokens instead of MaxTokens
func (m Model) RequiresMaxCompletionTokens() bool {
	// Newer OpenAI models (GPT-5 Mini, GPT-4.1 Mini) require MaxCompletionTokens
	return m.ID == OpenAIGPT5Mini.ID
}

// No dynamic model detection - all models must be explicitly defined above
