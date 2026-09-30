package agents

import (
	"context"
	"testing"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

type singleStageClient struct {
	content    string
	calls      int
	userPrompt string
}

type accountingVerificationClient struct {
	calls int
}

func (c *accountingVerificationClient) GenerateContent(_ context.Context, system, _ string, _ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	c.calls++
	if system == LocationDeterminationSystemPrompt {
		return &clients.GenerateResponse{Content: `{"startLine":1,"startColumn":1,"endLine":1,"endColumn":13}`, InputTokens: 30, OutputTokens: 3}, nil
	}
	return &clients.GenerateResponse{Content: `{"confirmed":true,"confidence":"high","reason":"confirmed flow"}`, InputTokens: 20, OutputTokens: 4}, nil
}

func TestDetectionAccountsForVerificationAndLocationTokens(t *testing.T) {
	detection := &singleStageClient{content: `{"violations":[{"startLine":1,"startColumn":1,"endLine":1,"endColumn":13,"reason":"flow"}]}`}
	verification := &accountingVerificationClient{}
	agent := &DetectionAgent{llmClient: detection, verificationLLMClient: verification, agentOption: &AgentOption{RequestTimeoutSec: 120}}
	result, err := agent.basicDetection(context.Background(), singleStageScan())
	assert.NoError(t, err)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, 1, detection.calls)
	assert.Equal(t, 2, verification.calls)
	assert.Equal(t, int32(60), result.InputTokens)
	assert.Equal(t, int32(9), result.OutputTokens)
}

func (c *singleStageClient) GenerateContent(_ context.Context, _, user string, _ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	c.calls++
	c.userPrompt = user
	return &clients.GenerateResponse{Content: c.content, InputTokens: 10, OutputTokens: 2}, nil
}

func singleStageScan() *model.ScanData {
	return &model.ScanData{RelativeFilePath: "test.java", Rule: &api.AiPrompt{ID: "test-rule"},
		FileContent: &model.FileContent{Text: "sink(input);\nother(input);"}, UserPrompt: "rule plus numbered code and related files"}
}

func TestSingleStageReturnsMultipleFindingsWithOneCall(t *testing.T) {
	detection := &singleStageClient{}
	verification := &singleStageClient{content: `{"findings":[{"line":1,"reason":"first flow"},{"line":2,"reason":"second flow"}]}`}
	agent := &DetectionAgent{llmClient: detection, verificationLLMClient: verification, agentOption: &AgentOption{}}
	scan := singleStageScan()
	result, err := agent.AnalyzeSingleStage(context.Background(), scan)
	assert.NoError(t, err)
	assert.Equal(t, 0, detection.calls)
	assert.Equal(t, 1, verification.calls)
	assert.Equal(t, scan.UserPrompt, verification.userPrompt)
	assert.Len(t, result.Violations, 2)
	assert.Equal(t, uint(1), result.Violations[0].StartLine)
	assert.Equal(t, uint(2), result.Violations[1].StartLine)
	assert.Equal(t, "test-rule", result.Violations[0].Rule)
	assert.Equal(t, int32(10), result.InputTokens)
	assert.Equal(t, int32(2), result.OutputTokens)
}

func TestSingleStageEmptyArrayIsClean(t *testing.T) {
	client := &singleStageClient{content: `{"findings":[]}`}
	agent := &DetectionAgent{verificationLLMClient: client, agentOption: &AgentOption{}}
	result, err := agent.AnalyzeSingleStage(context.Background(), singleStageScan())
	assert.NoError(t, err)
	assert.Empty(t, result.Violations)
	assert.Equal(t, 1, client.calls)
}

func TestSingleStageMissingFindingsIsFailure(t *testing.T) {
	client := &singleStageClient{content: `{}`}
	agent := &DetectionAgent{verificationLLMClient: client, agentOption: &AgentOption{}}
	result, err := agent.AnalyzeSingleStage(context.Background(), singleStageScan())
	assert.ErrorContains(t, err, "findings array")
	assert.Empty(t, result.Violations)
	assert.Equal(t, int32(10), result.InputTokens)
	assert.Equal(t, 1, client.calls)
}

func TestSingleStageRejectsInvalidLocationsWithoutPartialFindings(t *testing.T) {
	client := &singleStageClient{content: `{"findings":[{"line":1,"reason":"valid"},{"line":99,"reason":"invalid"}]}`}
	agent := &DetectionAgent{verificationLLMClient: client, agentOption: &AgentOption{}}
	result, err := agent.AnalyzeSingleStage(context.Background(), singleStageScan())
	assert.ErrorContains(t, err, "line 99")
	assert.Empty(t, result.Violations)
	assert.Equal(t, int32(10), result.InputTokens)
	assert.Equal(t, 1, client.calls)
}
