package agents

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/stretchr/testify/assert"
)

type scriptedToolClient struct{ calls int }

func (c *scriptedToolClient) GenerateContent(context.Context, string, string, *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return nil, nil
}
func (c *scriptedToolClient) GenerateWithTools(_ context.Context, _ []clients.Message, tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	c.calls++
	if len(tools) == 0 {
		return &clients.ToolGenerateResponse{Content: `{"violations":[]}`}, nil
	}
	if c.calls == 1 {
		return &clients.ToolGenerateResponse{ToolCalls: []clients.ToolCall{{ID: "read", Name: "read_file", Arguments: `{"path":"source.go"}`}}}, nil
	}
	return &clients.ToolGenerateResponse{Content: "done"}, nil
}

func TestRunAgenticCarriesToolTranscript(t *testing.T) {
	root := t.TempDir()
	err := os.WriteFile(filepath.Join(root, "source.go"), []byte("package sample\n"), 0600)
	assert.NoError(t, err)
	sandbox, err := agenttools.NewSandbox(root)
	assert.NoError(t, err)
	client := &scriptedToolClient{}
	agent := &DetectionAgent{agentOption: &AgentOption{AgenticMaxIterations: 2, AgenticMaxToolCalls: 2}, sandbox: sandbox}
	run, err := agent.runAgentic(context.Background(), client, "detection", "system", "user", &clients.GenerateOptions{})
	assert.NoError(t, err)
	assert.Equal(t, 1, run.ToolCalls)
	assert.Contains(t, run.trajectory(), "source.go")
}
