package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model"
)

type BitsRunner interface {
	Run(context.Context, *model.ScanData) (string, error)
}

type bitsRunner struct {
	command string
}

func NewBitsRunner(command string) BitsRunner {
	if command == "" {
		command = "bits"
	}
	return &bitsRunner{command: command}
}

func (runner *bitsRunner) Run(ctx context.Context, scanData *model.ScanData) (string, error) {
	prompt := bitsPrompt(scanData)
	command := exec.CommandContext(ctx, runner.command, "--new-agent", "-p", prompt, "--output-format", "json")
	command.Dir = scanData.RepositoryRoot
	output, err := command.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("run bits: %w", err)
	}
	return bitsResult(output)
}

func bitsPrompt(scanData *model.ScanData) string {
	return `You are the final security decision maker for this SAIst scan. You may inspect the repository using only read-only tools. Do not edit files, run shell commands, use network tools, or rely on memory from another task. Return only JSON matching this schema: {"violations":[{"startLine":number,"startColumn":number,"endLine":number,"endColumn":number,"reason":string}]}. Report a violation only when repository evidence confirms it matches the rule. For data-flow findings, identify a concrete source, sink, dataflow, and applicable sanitization. Each location must identify the concrete sink line.

System prompt:
` + scanData.SystemPrompt + `

Scan request:
` + scanData.UserPrompt
}

func bitsResult(output []byte) (string, error) {
	var response struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(output, &response); err == nil && strings.TrimSpace(response.Result) != "" {
		return response.Result, nil
	}
	content := strings.TrimSpace(string(output))
	if !json.Valid([]byte(content)) {
		return "", fmt.Errorf("bits returned invalid JSON")
	}
	return content, nil
}
