package agents

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
	modelapi "github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

type scriptedToolClient struct {
	calls                int
	generateContentCalls int
	finalContent         string
}

func (c *scriptedToolClient) GenerateContent(context.Context, string, string, *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	c.generateContentCalls++
	return &clients.GenerateResponse{}, nil
}
func (c *scriptedToolClient) GenerateWithTools(_ context.Context, _ []clients.Message, tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	c.calls++
	if len(tools) == 0 {
		return &clients.ToolGenerateResponse{Content: c.finalContent}, nil
	}
	if c.calls == 1 {
		return &clients.ToolGenerateResponse{ToolCalls: []clients.ToolCall{{ID: "read", Name: "read_file", Arguments: `{"path":"source.go"}`}}}, nil
	}
	return &clients.ToolGenerateResponse{Content: "investigating"}, nil
}

func TestRunAgenticCarriesToolTranscript(t *testing.T) {
	root := t.TempDir()
	err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package sample\n"), 0600)
	assert.NoError(t, err)
	sandbox, err := agenttools.NewSandbox(root)
	assert.NoError(t, err)
	client := &scriptedToolClient{finalContent: `{"violations":[]}`}
	agent := &DetectionAgent{agentOption: &AgentOption{AgenticMaxIterations: 2, AgenticMaxToolCalls: 2}, sandbox: sandbox}
	run, err := agent.runAgentic(context.Background(), client, "detection", "system", "user", &clients.GenerateOptions{})
	assert.NoError(t, err)
	assert.Equal(t, 1, run.ToolCalls)
	assert.Equal(t, 3, client.calls)
}

func TestAgenticDetectionReturnsFinalFindingsWithoutValidation(t *testing.T) {
	root := t.TempDir()
	err := os.WriteFile(filepath.Join(root, "source.go"), []byte("dangerousCall(input)\n"), 0600)
	assert.NoError(t, err)
	sandbox, err := agenttools.NewSandbox(root)
	assert.NoError(t, err)
	detector := &scriptedToolClient{finalContent: `{"violations":[{"startLine":1,"startColumn":1,"endLine":1,"endColumn":21,"reason":"Untrusted input reaches dangerousCall."}]}`}
	validator := &scriptedToolClient{}
	agent := &DetectionAgent{
		llmClient:             detector,
		verificationLLMClient: validator,
		agentOption:           &AgentOption{Agentic: true, AgenticMaxIterations: 2, AgenticMaxToolCalls: 2},
		sandbox:               sandbox,
	}
	result, err := agent.basicDetection(context.Background(), &model.ScanData{
		SystemPrompt:     "system",
		UserPrompt:       "user",
		RelativeFilePath: "source.go",
		FileContent:      &model.FileContent{Text: "dangerousCall(input)\n"},
		Rule:             &modelapi.AiPrompt{ID: "rule"},
	})
	assert.NoError(t, err)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, "Untrusted input reaches dangerousCall.", result.Violations[0].Message)
	assert.Equal(t, 0, validator.calls)
	assert.Equal(t, 0, validator.generateContentCalls)
}
