// nolint:lll
package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/utils"
)

func locationDeterminationOptions() clients.GenerateOptions {
	return clients.GenerateOptions{
		MaxTokens:    locationMaxTokens,
		ResponseType: verificationResponseType,
		Temperature:  locationTemperature,
		Schema: clients.GenerateOptionSchema{
			Name:        "location",
			Description: "SARIF-style region for a verified vulnerability",
			JsonSchema:  clients.GenerateSchema[LocationDeterminationResultData](),
		},
	}
}

const LocationDeterminationSystemPrompt = `You are a security expert. A vulnerability was already verified as a true positive.
Your only task is to choose the SARIF-style source line for that single finding: where the dangerous sink lives in the file.

Rules:
- Line and column numbers are 1-based and refer to the numbered code snippet provided.
- endColumn is exclusive (the column after the last included character), matching common SARIF conventions.
- Your primary decision is startLine: choose the sink line where the dangerous operation occurs.
- Do not choose distant helper lines, source lines, setup lines, or nearby block boundaries.
- startLine/startColumn/endLine/endColumn must bound real text in the snippet; do not invent lines outside the file.
- Columns will be normalized to the whole physical line after this response; prefer startColumn=1 and endLine=startLine.
- Output JSON only with the four location fields: startLine, startColumn, endLine, endColumn.`

const LocationDeterminationUserPrompt = `File: %s

Original detection (from the scanner):
- startLine: %d, startColumn: %d, endLine: %d, endColumn: %d
- Finding summary: %s

Verification (already passed — true positive):
- confidence: %s
- analysis: %s

Determine the best sink line for reporting this issue. Use the detection region as a hint only; adjust if verification identifies a different sink line.

Numbered source:
%s

Rule / detector prompt that produced the detection:
%s

Respond with JSON only:
{
  "startLine": <uint>,
  "startColumn": <uint>,
  "endLine": <uint>,
  "endColumn": <uint>
}`

type LocationDeterminationResultData struct {
	StartLine   uint `json:"startLine"`
	StartColumn uint `json:"startColumn"`
	EndLine     uint `json:"endLine"`
	EndColumn   uint `json:"endColumn"`
}

type LocationDeterminationResult struct {
	LocationDeterminationResultData
	InputTokens  int32
	OutputTokens int32
	Telemetry    *VerificationTelemetry
}

func getLocationDeterminationUserPrompt(
	scanData *model.ScanData,
	violation model.LLMResultViolation,
	verification *VerificationResult,
) string {
	numberedCode := scanData.NumberedFileText
	if numberedCode == "" {
		numberedCode = utils.AddLineNumbers(scanData.FileText)
	}
	return fmt.Sprintf(
		LocationDeterminationUserPrompt,
		scanData.RelativeFilePath,
		violation.StartLine,
		violation.StartColumn,
		violation.EndLine,
		violation.EndColumn,
		violation.Reason,
		verification.Confidence,
		verification.Reason,
		numberedCode,
		scanData.Rule.Content,
	)
}

func validateLocationDetermination(d LocationDeterminationResultData) error {
	if d.StartLine == 0 {
		return fmt.Errorf("startLine is required and must be > 0")
	}
	if d.StartColumn == 0 {
		return fmt.Errorf("startColumn is required and must be > 0")
	}
	if d.EndLine == 0 {
		return fmt.Errorf("endLine is required and must be > 0")
	}
	if d.EndColumn == 0 {
		return fmt.Errorf("endColumn is required and must be > 0")
	}
	if d.EndLine < d.StartLine {
		return fmt.Errorf("endLine (%d) cannot be before startLine (%d)", d.EndLine, d.StartLine)
	}
	if d.EndLine == d.StartLine && d.EndColumn < d.StartColumn {
		return fmt.Errorf("endColumn (%d) cannot be before startColumn (%d) on the same line",
			d.EndColumn, d.StartColumn)
	}
	return nil
}

func fileLineCount(fileText string) uint {
	if fileText == "" {
		return 0
	}
	return uint(strings.Count(fileText, "\n") + 1)
}

func locationFitsFile(d LocationDeterminationResultData, fileText string) bool {
	n := fileLineCount(fileText)
	if n == 0 {
		return false
	}
	if d.StartLine > n || d.EndLine > n {
		return false
	}
	return true
}

func physicalLineLocation(fileText string, lineNumber uint) (LocationDeterminationResultData, bool) {
	if lineNumber == 0 {
		return LocationDeterminationResultData{}, false
	}
	lines := strings.Split(fileText, "\n")
	if int(lineNumber) > len(lines) {
		return LocationDeterminationResultData{}, false
	}
	endColumn := uint(len(lines[lineNumber-1]) + 1)
	if endColumn == 1 {
		endColumn = 2
	}
	return LocationDeterminationResultData{
		StartLine:   lineNumber,
		StartColumn: 1,
		EndLine:     lineNumber,
		EndColumn:   endColumn,
	}, true
}

func parseLocationDeterminationResult(content string) (LocationDeterminationResultData, error) {
	jsonContent := strings.TrimSpace(content)

	var direct LocationDeterminationResultData
	if err := json.Unmarshal([]byte(jsonContent), &direct); err == nil && direct.StartLine > 0 {
		return direct, nil
	}

	var wrapped struct {
		Content LocationDeterminationResultData `json:"content"`
	}
	if err := json.Unmarshal([]byte(jsonContent), &wrapped); err == nil && wrapped.Content.StartLine > 0 {
		return wrapped.Content, nil
	}

	jsonContent = extractJSONFromCodeBlock(jsonContent)

	var data LocationDeterminationResultData
	err := json.Unmarshal([]byte(jsonContent), &data)
	if err == nil && data.StartLine == 0 {
		err = fmt.Errorf("missing startLine")
	}
	if err != nil {
		return LocationDeterminationResultData{}, fmt.Errorf("failed to parse location determination response: %w", err)
	}
	return data, nil
}

func (agent *DetectionAgent) DetermineViolationLocation(ctx context.Context, scanData *model.ScanData,
	violation model.LLMResultViolation, verification *VerificationResult) (*LocationDeterminationResult, error) {
	logger := log.FromContext(ctx)
	userPrompt := getLocationDeterminationUserPrompt(scanData, violation, verification)
	options := locationDeterminationOptions()

	telemetry := prepareVerificationTelemetry(verification.Telemetry)
	verification.Telemetry = telemetry
	inputBefore := telemetry.InputTokens
	outputBefore := telemetry.OutputTokens
	response, err := agent.verificationGenerateContentWithTelemetry(ctx, scanData, violation.StartLine,
		LocationDeterminationSystemPrompt, userPrompt, &options, telemetry, ModelCallKindLocation)
	result := &LocationDeterminationResult{
		InputTokens:  telemetry.InputTokens - inputBefore,
		OutputTokens: telemetry.OutputTokens - outputBefore,
		Telemetry:    telemetry,
	}
	if err != nil {
		return result, err
	}

	locData, err := parseLocationDeterminationResult(response.Content)
	if err != nil {
		telemetry.markLastModelCallError(err)
		if agent.agentOption.DebugEnabled {
			logger.Warnf("[debug] location determination parse failed for %s:%d, using detection region: %s",
				scanData.RelativeFilePath, violation.StartLine, err)
		}
		return result, err
	}
	if err := validateLocationDetermination(locData); err != nil {
		telemetry.markLastModelCallError(err)
		if agent.agentOption.DebugEnabled {
			logger.Warnf("[debug] location determination validation failed for %s:%d: %s",
				scanData.RelativeFilePath, violation.StartLine, err)
		}
		return result, err
	}
	if !locationFitsFile(locData, scanData.FileText) {
		telemetry.markLastModelCallError(fmt.Errorf("location out of file range"))
		if agent.agentOption.DebugEnabled {
			logger.Warnf("[debug] location determination out of range for %s (lines %d-%d)",
				scanData.RelativeFilePath, locData.StartLine, locData.EndLine)
		}
		return result, fmt.Errorf("location out of file range")
	}
	if stableLocation, ok := physicalLineLocation(scanData.FileText, locData.StartLine); ok {
		locData = stableLocation
	}

	result.LocationDeterminationResultData = locData
	return result, nil
}
