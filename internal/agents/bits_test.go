package agents

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	modelapi "github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestBitsRunnerParsesResult(t *testing.T) {
	directory := t.TempDir()
	command := filepath.Join(directory, "bits")
	err := os.WriteFile(command, []byte("#!/bin/sh\nprintf '%s' '{\"result\":\"{\\\"violations\\\":[]}\"}'\n"), 0700)
	assert.NoError(t, err)
	runner := NewBitsRunner(command)
	result, err := runner.Run(context.Background(), &model.ScanData{
		RepositoryRoot: directory,
		SystemPrompt:   "system",
		UserPrompt:     "user",
		Rule:           &modelapi.AiPrompt{ID: "rule"},
	})
	assert.NoError(t, err)
	assert.Equal(t, `{"violations":[]}`, result)
}

func TestBitsPromptRequiresReadOnlyFinalDecision(t *testing.T) {
	prompt := bitsPrompt(&model.ScanData{SystemPrompt: "system", UserPrompt: "user"})
	assert.Contains(t, prompt, "only read-only tools")
	assert.Contains(t, prompt, "Return only JSON")
}
