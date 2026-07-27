package agents

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvestigationPromptHashIsDeterministicAndSeparate(t *testing.T) {
	a, err := InvestigationPromptHash()
	require.NoError(t, err)
	b, err := InvestigationPromptHash()
	require.NoError(t, err)
	assert.Equal(t, a, b, "investigation prompt hash must be deterministic")

	contract, err := FinalVerifierContractHash()
	require.NoError(t, err)
	assert.NotEqual(t, contract, a, "investigation prompt must not be part of the final verifier contract")
}

func TestInvestigationUserPromptIsCollectOnly(t *testing.T) {
	scanData := &model.ScanData{
		RelativeFilePath: "internal/handler/user.go",
		NumberedFileText: "1: package handler",
		Rule:             &api.AiPrompt{ID: "datadog/go-sqli", Content: "rule content"},
	}
	violation := model.LLMResultViolation{StartLine: 2, Reason: "user input reaches db.Query"}
	prompt := getInvestigationUserPrompt(scanData, violation)

	assert.Contains(t, prompt, "Gather evidence only.")
	assert.Contains(t, prompt, "internal/handler/user.go")
	lower := strings.ToLower(prompt)
	for _, directive := range []string{"confirmed", "verdict", "confidence", "false positive", "true positive"} {
		assert.NotContains(t, lower, directive, "collect-only investigation prompt must not request a conclusion")
	}
}

func explorationAgent(t *testing.T, fake *fakeToolClient) *DetectionAgent {
	t.Helper()
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = fake
	return agent
}

func TestExploreForEvidenceProtocolFailsWithoutSuccessfulTool(t *testing.T) {
	fake := &fakeToolClient{
		fn: func(_ int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			// Never call a tool. The loop must force and then protocol-fail.
			return &clients.ToolGenerateResponse{Content: "I think it is fine, no need to look."}
		},
	}
	agent := explorationAgent(t, fake)
	agent.agentOption.AgenticMaxIterations = 3

	result, err := agent.exploreForEvidence(context.Background(), "sys", "user", "flagged.go",
		&VerificationTelemetry{})

	assert.NoError(t, err, "protocol failure is not a Go error")
	assert.True(t, result.ProtocolFailed(), "no successful tool call means protocol failure")
	assert.Zero(t, result.SuccessfulToolCalls)
	assert.Equal(t, LoopStopReasonNoSuccessfulTool, result.StopReason)
	assert.Equal(t, 3, fake.calls, "the loop should use the full turn budget while forcing tool use")

	// The reminder was issued to force tool use.
	var sawReminder bool
	for _, msgs := range fake.gotMsgs {
		for _, m := range msgs {
			if m.Role == "user" && m.Content == investigationToolReminder {
				sawReminder = true
			}
		}
	}
	assert.True(t, sawReminder, "the loop must remind the model that investigation is required")
}

func TestExploreForEvidenceCollectsRawTranscriptAndIgnoresProse(t *testing.T) {
	const prose = "I conclude this is a true positive and should be confirmed."
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if call == 0 {
				return &clients.ToolGenerateResponse{
					ToolCalls: []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
				}
			}
			// After a successful tool call, the model stops and offers prose. The
			// prose must be ignored and must never enter the evidence payload.
			return &clients.ToolGenerateResponse{Content: prose}
		},
	}
	agent := explorationAgent(t, fake)

	result, err := agent.exploreForEvidence(context.Background(), "sys", "user", "flagged.go",
		&VerificationTelemetry{})
	require.NoError(t, err)

	assert.Equal(t, LoopStopReasonReadyToAnswer, result.StopReason)
	assert.Equal(t, 1, result.SuccessfulToolCalls)
	require.Len(t, result.Events, 1)
	assert.Equal(t, "c1", result.Events[0].ToolCallID)
	assert.Equal(t, "read_file", result.Events[0].Tool)
	assert.Contains(t, result.Events[0].Result, "hello", "the exact tool result content must be captured")
	assert.True(t, result.NewInformationRetrieved, "reading a file other than the flagged file is new information")

	payload, err := SerializeEvidencePayload(result.Events)
	require.NoError(t, err)
	assert.NotContains(t, string(payload), prose, "agent prose must never enter the evidence payload")
}

func TestExploreForEvidenceForcesToolThenSucceeds(t *testing.T) {
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			switch call {
			case 0:
				return &clients.ToolGenerateResponse{Content: "the flagged file looks sufficient"}
			case 1:
				return &clients.ToolGenerateResponse{
					ToolCalls: []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
				}
			default:
				return &clients.ToolGenerateResponse{Content: "done"}
			}
		},
	}
	agent := explorationAgent(t, fake)

	result, err := agent.exploreForEvidence(context.Background(), "sys", "user", "flagged.go",
		&VerificationTelemetry{})
	require.NoError(t, err)

	assert.False(t, result.ProtocolFailed())
	assert.Equal(t, 1, result.SuccessfulToolCalls)
	assert.Equal(t, 3, fake.calls)
	assert.Equal(t, LoopStopReasonReadyToAnswer, result.StopReason)
}

func TestExploreForEvidenceUnsupportedClientIsNotProtocolNoise(t *testing.T) {
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = &basicOnlyClient{content: "unused"}

	result, err := agent.exploreForEvidence(context.Background(), "sys", "user", "flagged.go",
		&VerificationTelemetry{})

	assert.Error(t, err)
	assert.Equal(t, LoopStopReasonUnsupportedClient, result.StopReason)
	assert.Empty(t, result.Events)
}

func TestExploreForEvidenceEventsSerializeWithoutRawContentLeakToTelemetry(t *testing.T) {
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if call == 0 {
				return &clients.ToolGenerateResponse{
					ToolCalls: []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
				}
			}
			return &clients.ToolGenerateResponse{}
		},
	}
	agent := explorationAgent(t, fake)
	telemetry := &VerificationTelemetry{}

	result, err := agent.exploreForEvidence(context.Background(), "sys", "user", "flagged.go", telemetry)
	require.NoError(t, err)

	// Raw source content lives in the evidence payload (a protected artifact),
	// never in the content-free telemetry.
	encoded, err := json.Marshal(telemetry)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "hello")
	payload, err := SerializeEvidencePayload(result.Events)
	require.NoError(t, err)
	assert.Contains(t, string(payload), "hello")
}
