package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
)

type singleStageFinding struct {
	Line   uint   `json:"line"`
	Reason string `json:"reason"`
}

type singleStageResponse struct {
	Findings []singleStageFinding `json:"findings"`
}

func (agent *DetectionAgent) AnalyzeSingleStage(ctx context.Context, scan *model.ScanData) (*DetectionResult, error) {
	if scan.FileContent == nil || scan.Rule == nil || scan.UserPrompt == "" {
		return nil, fmt.Errorf("single-stage requires source, rule and analysis context")
	}
	timeout := agent.agentOption.RequestTimeoutSec
	if timeout <= 0 {
		timeout = 180
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	ctx = clients.WithAIGatewayTags(ctx, withCallType(scan.Tags, "single_stage"))
	response, err := agent.verificationLLMClient.GenerateContent(ctx, singleStageSystemPrompt, scan.UserPrompt, &clients.GenerateOptions{
		MaxTokens: 8192, Temperature: 1, ResponseType: "application/json",
		Schema: clients.GenerateOptionSchema{Name: "single_stage_findings", JsonSchema: clients.GenerateSchema[singleStageResponse]()},
	})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("single-stage returned no response")
	}
	result := &DetectionResult{Path: scan.RelativeFilePath, InputTokens: response.InputTokens, OutputTokens: response.OutputTokens}
	var decoded singleStageResponse
	if err := json.Unmarshal([]byte(response.Content), &decoded); err != nil {
		return result, fmt.Errorf("invalid single-stage JSON: %w", err)
	}
	if decoded.Findings == nil {
		return result, fmt.Errorf("single-stage response must contain a findings array")
	}
	violations := make([]model.Violation, 0, len(decoded.Findings))
	for _, finding := range decoded.Findings {
		location, ok := physicalLineLocation(scan.FileContent.Text, finding.Line)
		if !ok || strings.TrimSpace(model.GetLineContent(scan.FileContent.Text, finding.Line)) == "" || strings.TrimSpace(finding.Reason) == "" {
			return result, fmt.Errorf("invalid single-stage finding at line %d", finding.Line)
		}
		violations = append(violations, model.Violation{
			Rule: scan.Rule.ID, Cwe: scan.Rule.Cwe, Path: scan.RelativeFilePath, Message: finding.Reason,
			StartLine: location.StartLine, EndLine: location.EndLine,
			StartColumn: location.StartColumn, EndColumn: location.EndColumn,
		})
	}
	result.Violations = violations
	return result, nil
}
