package agents

import (
	"context"
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// agenticVerifyStub drives both phases of the clean agentic verifier from one
// client. GenerateWithTools scripts the collect-only exploration. GenerateContent
// serves and records the shared final-verifier request, so tests can inspect the
// exact system and user strings the verifier received.
type agenticVerifyStub struct {
	explore      func(call int, msgs []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse
	exploreCalls int

	finalContent string
	finalErr     error
	finalCalls   int
	gotSystem    string
	gotUser      string
}

func (s *agenticVerifyStub) GenerateWithTools(_ context.Context, msgs []clients.Message,
	tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	resp := s.explore(s.exploreCalls, msgs, tools)
	s.exploreCalls++
	return resp, nil
}

func (s *agenticVerifyStub) GenerateContent(_ context.Context, systemPrompt, userPrompt string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	s.finalCalls++
	s.gotSystem = systemPrompt
	s.gotUser = userPrompt
	if s.finalErr != nil {
		return nil, s.finalErr
	}
	return &clients.GenerateResponse{Content: s.finalContent}, nil
}

func agenticVerifyScanData() (*model.ScanData, model.LLMResultViolation) {
	scanData := &model.ScanData{
		RelativeFilePath: "inside.txt",
		FileText:         "hello\nworld\n",
		Rule:             &api.AiPrompt{ID: "datadog/go-sqli", Content: "detect sql injection"},
	}
	violation := model.LLMResultViolation{StartLine: 1, EndLine: 1, Reason: "candidate flows to sink"}
	return scanData, violation
}

// readThenStop scripts an exploration that reads the sandbox file once and then
// signals it is done, producing a non-empty evidence transcript with one
// successful tool call.
func readThenStop(call int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
	if call == 0 {
		return &clients.ToolGenerateResponse{
			ToolCalls: []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
		}
	}
	return &clients.ToolGenerateResponse{}
}

func TestAgenticVerifyConfirmYieldsAgenticConfirm(t *testing.T) {
	stub := &agenticVerifyStub{
		explore:      readThenStop,
		finalContent: `{"confirmed":true,"confidence":"high","reason":"x"}`,
	}
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = stub
	scanData, violation := agenticVerifyScanData()

	result, err := agent.VerifyViolation(context.Background(), scanData, violation)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Confirmed)
	assert.Equal(t, EvidenceVerdictConfirm, result.FinalVerdict)
	assert.Equal(t, VerificationSourceAgentic, result.VerdictSource)
	assert.NotEmpty(t, result.EvidencePayloadHash)
	assert.Positive(t, result.SuccessfulToolCalls)
	assert.Equal(t, 1, stub.finalCalls)
}

func TestAgenticVerifyRejectYieldsAgenticReject(t *testing.T) {
	stub := &agenticVerifyStub{
		explore:      readThenStop,
		finalContent: `{"confirmed":false,"confidence":"high","reason":"input is sanitized"}`,
	}
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = stub
	scanData, violation := agenticVerifyScanData()

	result, err := agent.VerifyViolation(context.Background(), scanData, violation)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.Confirmed)
	assert.Equal(t, EvidenceVerdictReject, result.FinalVerdict)
	assert.Equal(t, VerificationSourceAgentic, result.VerdictSource)
	assert.NotEmpty(t, result.EvidencePayloadHash)
	assert.Equal(t, 1, stub.finalCalls)
}

// TestAgenticVerifyNeverAbstains proves the agentic arm only ever produces confirm
// or reject on the success path: the decision comes solely from the shared
// verifier's boolean, so abstain is never reachable.
func TestAgenticVerifyNeverAbstains(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    EvidenceVerdict
	}{
		{"confirm", `{"confirmed":true,"confidence":"high","reason":"exploitable"}`, EvidenceVerdictConfirm},
		{"reject", `{"confirmed":false,"confidence":"low","reason":"safe"}`, EvidenceVerdictReject},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &agenticVerifyStub{explore: readThenStop, finalContent: tc.content}
			agent := agenticAgent(tempSandbox(t))
			agent.verificationLLMClient = stub
			scanData, violation := agenticVerifyScanData()

			result, err := agent.VerifyViolation(context.Background(), scanData, violation)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tc.want, result.FinalVerdict)
			assert.NotEqual(t, EvidenceVerdictAbstain, result.FinalVerdict)
		})
	}
}

// TestAgenticVerifyProtocolFailureSkipsFinalVerifier proves that an exploration
// that never calls a tool returns ErrAgenticProtocolFailure and never invokes the
// shared final verifier.
func TestAgenticVerifyProtocolFailureSkipsFinalVerifier(t *testing.T) {
	stub := &agenticVerifyStub{
		explore: func(_ int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			return &clients.ToolGenerateResponse{Content: "I will not investigate."}
		},
		finalContent: `{"confirmed":true,"confidence":"high","reason":"must never run"}`,
	}
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = stub
	scanData, violation := agenticVerifyScanData()

	result, err := agent.VerifyViolation(context.Background(), scanData, violation)

	assert.ErrorIs(t, err, ErrAgenticProtocolFailure)
	assert.Nil(t, result)
	assert.Equal(t, 0, stub.finalCalls, "final verifier must not run on a protocol failure")
}

// TestAgenticFinalVerifierRequestMatchesStandardPlusEvidence proves the agentic
// arm's final request is the standard verifier request plus exactly one delimited
// repository-evidence section: the system message is the shared verifier system
// prompt, and the user message begins byte-identically with the standard user
// prompt followed by the evidence envelope.
func TestAgenticFinalVerifierRequestMatchesStandardPlusEvidence(t *testing.T) {
	stub := &agenticVerifyStub{
		explore:      readThenStop,
		finalContent: `{"confirmed":true,"confidence":"high","reason":"x"}`,
	}
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = stub
	scanData, violation := agenticVerifyScanData()

	_, err := agent.VerifyViolation(context.Background(), scanData, violation)
	require.NoError(t, err)

	assert.Equal(t, VerificationSystemPrompt, stub.gotSystem)
	standardPrefix := getVerificationUserPrompt(scanData, violation)
	assert.True(t, strings.HasPrefix(stub.gotUser, standardPrefix+"\n\n"+EvidenceEnvelopeHeader),
		"agentic final user prompt must be the standard prompt plus the delimited evidence envelope")
	assert.Contains(t, stub.gotUser, EvidenceEnvelopeHeader)
}
