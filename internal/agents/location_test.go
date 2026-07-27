package agents

import (
	"context"
	"fmt"
	"testing"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

type locationSequenceClient struct {
	responses []*clients.GenerateResponse
	next      int
}

func (client *locationSequenceClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	if client.next >= len(client.responses) {
		return nil, fmt.Errorf("unexpected model call %d", client.next+1)
	}
	response := client.responses[client.next]
	client.next++
	return response, nil
}

func TestParseLocationDeterminationResult_DirectJSON(t *testing.T) {
	content := `{"startLine":10,"startColumn":1,"endLine":10,"endColumn":25}`
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(10), got.StartLine)
	assert.Equal(t, uint(1), got.StartColumn)
	assert.Equal(t, uint(10), got.EndLine)
	assert.Equal(t, uint(25), got.EndColumn)
}

func TestParseLocationDeterminationResult_JSONCodeBlock(t *testing.T) {
	content := "x\n```json\n{\"startLine\":3,\"startColumn\":5,\"endLine\":3,\"endColumn\":20}\n```\n"
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(3), got.StartLine)
	assert.Equal(t, uint(5), got.StartColumn)
}

func TestParseLocationDeterminationResult_WrappedContentObject(t *testing.T) {
	content := `{"content":{"startLine":7,"startColumn":2,"endLine":8,"endColumn":10}}`
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(7), got.StartLine)
	assert.Equal(t, uint(8), got.EndLine)
}

func TestParseLocationDeterminationResult_DirectPreferredOverEmptyContentWrapper(t *testing.T) {
	// Top-level coordinates must win; a zero "content" object must not mask valid fields.
	content := `{"startLine":4,"startColumn":1,"endLine":4,"endColumn":9,"content":{}}`
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(4), got.StartLine)
}

func TestParseLocationDeterminationResult_InvalidJSON(t *testing.T) {
	_, err := parseLocationDeterminationResult(`{not json`)
	assert.NotNil(t, err)
}

func TestPhysicalLineLocation(t *testing.T) {
	got, ok := physicalLineLocation("abc\nx\n", 2)
	assert.True(t, ok)
	assert.Equal(t, LocationDeterminationResultData{
		StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 2,
	}, got)

	_, ok = physicalLineLocation("abc", 2)
	assert.False(t, ok)
}

func TestValidateLocationDetermination_EndBeforeStart(t *testing.T) {
	err := validateLocationDetermination(LocationDeterminationResultData{
		StartLine: 5, StartColumn: 1, EndLine: 4, EndColumn: 10,
	})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "endLine")
}

func TestLocationFitsFile(t *testing.T) {
	d := LocationDeterminationResultData{StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 5}
	assert.True(t, locationFitsFile(d, "a\nb\nc"))
	assert.False(t, locationFitsFile(d, "onlyone"))
	assert.False(t, locationFitsFile(LocationDeterminationResultData{
		StartLine: 1, StartColumn: 1, EndLine: 99, EndColumn: 2,
	}, "a\nb"))
}

func TestVerifyCandidateIncludesLocationCallAndTokens(t *testing.T) {
	client := &locationSequenceClient{responses: []*clients.GenerateResponse{
		{
			Content:      `{"confirmed":true,"confidence":"high","reason":"verified"}`,
			InputTokens:  11,
			OutputTokens: 7,
		},
		{
			Content:      `{"startLine":1,"startColumn":1,"endLine":1,"endColumn":9}`,
			InputTokens:  3,
			OutputTokens: 2,
		},
	}}
	agent := &DetectionAgent{
		verificationLLMClient: client,
		agentOption:           &AgentOption{RequestTimeoutSec: 30},
	}
	scanData := &model.ScanData{
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule:             &api.AiPrompt{ID: "test-rule", Content: "test rule"},
	}
	candidate := model.LLMResultViolation{
		StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 9, Reason: "candidate",
	}

	violation, result, err := agent.VerifyCandidate(context.Background(), scanData, candidate)

	assert.NoError(t, err)
	assert.NotNil(t, violation)
	assert.Equal(t, int32(14), result.InputTokens)
	assert.Equal(t, int32(9), result.OutputTokens)
	assert.GreaterOrEqual(t, result.DurationMillis, int64(0))
	if assert.Len(t, result.Telemetry.ModelCalls, 2) {
		assert.Equal(t, ModelCallKindStandardVerification, result.Telemetry.ModelCalls[0].Kind)
		assert.Equal(t, ModelCallKindLocation, result.Telemetry.ModelCalls[1].Kind)
		if assert.NotNil(t, result.Telemetry.ModelCalls[0].Temperature) {
			assert.Equal(t, verificationTemperature, *result.Telemetry.ModelCalls[0].Temperature)
		}
		if assert.NotNil(t, result.Telemetry.ModelCalls[1].Temperature) {
			assert.Equal(t, locationTemperature, *result.Telemetry.ModelCalls[1].Temperature)
		}
		assert.Equal(t, verificationMaxTokens, result.Telemetry.ModelCalls[0].MaxTokens)
		assert.Equal(t, locationMaxTokens, result.Telemetry.ModelCalls[1].MaxTokens)
	}
}

func TestVerifyCandidatePreservesLocationUsageOnParseFailure(t *testing.T) {
	client := &locationSequenceClient{responses: []*clients.GenerateResponse{
		{
			Content:      `{"confirmed":true,"confidence":"high","reason":"verified"}`,
			InputTokens:  11,
			OutputTokens: 7,
		},
		{
			Content:      `{invalid`,
			InputTokens:  3,
			OutputTokens: 2,
		},
	}}
	agent := &DetectionAgent{
		verificationLLMClient: client,
		agentOption:           &AgentOption{RequestTimeoutSec: 30},
	}
	scanData := &model.ScanData{
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule:             &api.AiPrompt{ID: "test-rule", Content: "test rule"},
	}
	candidate := model.LLMResultViolation{
		StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 9, Reason: "candidate",
	}

	violation, result, err := agent.VerifyCandidate(context.Background(), scanData, candidate)

	assert.NoError(t, err)
	assert.NotNil(t, violation)
	assert.Equal(t, uint(1), violation.StartLine)
	assert.Equal(t, int32(14), result.InputTokens)
	assert.Equal(t, int32(9), result.OutputTokens)
	if assert.Len(t, result.Telemetry.ModelCalls, 2) {
		assert.Equal(t, ModelCallKindLocation, result.Telemetry.ModelCalls[1].Kind)
		assert.NotEmpty(t, result.Telemetry.ModelCalls[1].Error)
	}
}
