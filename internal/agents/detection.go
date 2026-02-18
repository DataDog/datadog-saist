package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	pkgerrors "github.com/pkg/errors"
)

type DetectionAgent struct {
	llmClient             clients.LLMClient
	requestTimeoutSec     int
	verificationLLMClient clients.LLMClient
	// Temporary to avoid larger refactor: this should be handled with log levels, not booleans
	debugEnabled bool
}

type AgentOption struct {
	DetectionModel    model.Model
	ValidationModel   model.Model
	OpenAiBaseUrl     string
	RequestTimeoutSec int
	IsAIGateway       bool
	AIGuardEnabled    bool
	OrgID             int64
	// Temporary to avoid larger refactor: this should be handled with log levels, not booleans
	DebugEnabled bool
}

type DetectionResult struct {
	Violations   []model.Violation
	Path         string
	InputTokens  int32
	OutputTokens int32
}

type VerificationResultInternal struct {
	Confirmed    bool
	Confidence   string // "high", "low"
	Reason       string
	InputTokens  int32
	OutputTokens int32
}

type VerificationResultData struct {
	Confirmed  bool   `json:"confirmed"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

type VerificationResult struct {
	VerificationResultData
	InputTokens  int32 `json:"input_tokens"`
	OutputTokens int32 `json:"output_tokens"`
}

func NewDetectionAgent(ctx context.Context, agentOption *AgentOption) (*DetectionAgent, error) {
	var client clients.LLMClient
	var err error
	var verificationClient clients.LLMClient

	// If a base URL is provided, always use OpenAI client (for custom endpoints like AI Gateway)
	if agentOption.OpenAiBaseUrl != "" {
		client, _ = clients.NewOpenAIClient(
			ctx,
			agentOption.DetectionModel.ToAPIModelWithFormat(agentOption.IsAIGateway),
			agentOption.OpenAiBaseUrl,
			agentOption.IsAIGateway,
			agentOption.AIGuardEnabled,
			agentOption.OrgID,
			agentOption.DetectionModel.IsCustom(),
		)
		verificationClient, err = clients.NewOpenAIClient(
			ctx,
			agentOption.ValidationModel.ToAPIModelWithFormat(agentOption.IsAIGateway),
			agentOption.OpenAiBaseUrl,
			agentOption.IsAIGateway,
			agentOption.AIGuardEnabled,
			agentOption.OrgID,
			agentOption.ValidationModel.IsCustom(),
		)
	} else {
		// No base URL - use provider-specific clients based on model detection
		if agentOption.DetectionModel.RawAPIModel != "" {
			// Custom model requires baseURL
			return nil, pkgerrors.New("custom models require --openai-base-url to be specified")
		}

		// Create detection client based on detection model provider
		switch {
		case agentOption.DetectionModel.IsOpenAI():
			client, _ = clients.NewOpenAIClient(
				ctx,
				agentOption.DetectionModel.ToAPIModelWithFormat(false), // Direct format for native OpenAI
				"", // empty base URL = use default OpenAI endpoint
				agentOption.IsAIGateway,
				agentOption.AIGuardEnabled,
				agentOption.OrgID,
				agentOption.DetectionModel.IsCustom(),
			)
		case agentOption.DetectionModel.IsGoogle():
			client, _ = clients.NewGeminiClient(ctx, agentOption.DetectionModel.ToAPIModelWithFormat(false))
		case agentOption.DetectionModel.IsAnthropic():
			client, _ = clients.NewAnthropicClient(ctx, agentOption.DetectionModel.ToAPIModelWithFormat(false))
		default:
			return nil, model.ErrUnsupportedModel
		}

		// Create verification client based on validation model provider
		switch {
		case agentOption.ValidationModel.IsOpenAI():
			verificationClient, err = clients.NewOpenAIClient(
				ctx,
				agentOption.ValidationModel.ToAPIModelWithFormat(false),
				"",
				agentOption.IsAIGateway,
				agentOption.AIGuardEnabled,
				agentOption.OrgID,
				agentOption.ValidationModel.IsCustom(),
			)
		case agentOption.ValidationModel.IsGoogle():
			verificationClient, err = clients.NewGeminiClient(ctx, agentOption.ValidationModel.ToAPIModelWithFormat(false))
		case agentOption.ValidationModel.IsAnthropic():
			verificationClient, err = clients.NewAnthropicClient(ctx, agentOption.ValidationModel.ToAPIModelWithFormat(false))
		default:
			return nil, model.ErrUnsupportedModel
		}
	}

	if err != nil {
		return nil, err
	}

	return &DetectionAgent{
		llmClient:             client,
		verificationLLMClient: verificationClient,
		requestTimeoutSec:     agentOption.RequestTimeoutSec,
		debugEnabled:          agentOption.DebugEnabled,
	}, nil
}

// repairTruncatedJSON attempts to repair truncated JSON strings that are cut off mid-field
// This commonly happens when LLM responses are truncated due to token limits
func repairTruncatedJSON(content string) (*model.LLMResult, error) {
	trimmed := strings.TrimSpace(content)

	// Check if content appears to be truncated (doesn't end with } and contains violations structure)
	if strings.HasSuffix(trimmed, "}") || !strings.Contains(content, "violations") {
		return nil, errors.New("content does not appear to be truncated")
	}

	// First, fix literal newlines within JSON strings (invalid JSON)
	fixedContent := fixLiteralNewlines(content)

	// Try to complete a truncated string field
	// This handles cases where the JSON is cut off in the middle of a string value
	// Example: "reason": "Some text that is cut off mid-sen
	// We add closing quote, then all necessary closing brackets/braces
	var result model.LLMResult
	repairStrategies := []string{
		// Most common: truncated in middle of reason string
		fixedContent + "\"\n    }\n  ]\n}",
		// Truncated with different indentation
		fixedContent + "\"}\n]\n}",
		// Truncated right after opening quote
		fixedContent + "\n    }\n  ]\n}",
		// Truncated without any closing structures
		fixedContent + "\"}]}",
	}

	for _, repaired := range repairStrategies {
		err := json.Unmarshal([]byte(repaired), &result)
		if err == nil {
			if err := validateViolationLocations(&result); err != nil {
				// If validation fails, try next strategy
				continue
			}
			return &result, nil
		}
	}

	return nil, errors.New("unable to repair truncated JSON")
}

// fixLiteralNewlines replaces literal newlines within JSON string values with escaped newlines
// This fixes invalid JSON that has literal line breaks inside string fields
// nolint: gocyclo
func fixLiteralNewlines(content string) string {
	var result strings.Builder
	inString := false
	escaped := false
	afterColon := false

	for i := 0; i < len(content); i++ {
		ch := content[i]

		if escaped {
			result.WriteByte(ch)
			escaped = false
			continue
		}

		if ch == '\\' {
			result.WriteByte(ch)
			escaped = true
			continue
		}

		// Track if we're after a colon (field value position)
		if ch == ':' {
			afterColon = true
			result.WriteByte(ch)
			continue
		}

		// Opening quote for string value
		if ch == '"' {
			if !inString && afterColon {
				inString = true
			} else if inString {
				inString = false
				afterColon = false
			}
			result.WriteByte(ch)
			continue
		}

		// Handle newlines inside strings
		if ch == '\n' {
			if inString {
				// Replace literal newline with escaped newline
				result.WriteString("\\n")
			} else {
				// Keep newline outside strings
				result.WriteByte(ch)
			}
			continue
		}

		// Skip carriage returns entirely
		if ch == '\r' {
			continue
		}

		// Reset afterColon if we hit a non-whitespace that's not a quote
		if afterColon && ch != ' ' && ch != '\t' && ch != '\n' && ch != '"' {
			if ch == '{' || ch == '[' {
				afterColon = false
			}
		}

		result.WriteByte(ch)
	}

	return result.String()
}

// validateViolationLocations validates that all violations have required location fields
func validateViolationLocations(result *model.LLMResult) error {
	for i, v := range result.Violations {
		if v.StartLine == 0 {
			return fmt.Errorf("violation %d: startLine is required and must be > 0", i)
		}
		if v.StartColumn == 0 {
			return fmt.Errorf("violation %d: startColumn is required and must be > 0", i)
		}
		if v.EndLine == 0 {
			return fmt.Errorf("violation %d: endLine is required and must be > 0", i)
		}
		if v.EndColumn == 0 {
			return fmt.Errorf("violation %d: endColumn is required and must be > 0", i)
		}
		if v.EndLine < v.StartLine {
			return fmt.Errorf("violation %d: endLine (%d) cannot be before startLine (%d)", i, v.EndLine, v.StartLine)
		}
		if v.EndLine == v.StartLine && v.EndColumn < v.StartColumn {
			return fmt.Errorf("violation %d: endColumn (%d) cannot be before startColumn (%d) on the same line",
				i, v.EndColumn, v.StartColumn)
		}
	}
	return nil
}

// nolint: gocyclo
func getViolationsFromContent(content string) (*model.LLMResult, error) {
	var result model.LLMResult
	if strings.Contains(content, "NO VIOLATION AMIGO") {
		return nil, nil
	}

	// try to parse if content is wrapped in a "content" field
	var wrapped struct {
		Content string `json:"content"`
	}
	err := json.Unmarshal([]byte(content), &wrapped)
	if err == nil && wrapped.Content != "" {
		result = model.LLMResult{} // Reset result
		err = json.Unmarshal([]byte(wrapped.Content), &result)
		if err == nil {
			if err := validateViolationLocations(&result); err != nil {
				return nil, fmt.Errorf("validation failed: %w", err)
			}
			return &result, nil
		}

		// If parsing failed, try to repair truncated JSON
		// The content field in outer JSON might have been truncated, cutting off the inner JSON
		repairedResult, repairErr := repairTruncatedJSON(wrapped.Content)
		if repairErr == nil {
			return repairedResult, nil
		}
	}

	// try to just unmarshall the result
	err = json.Unmarshal([]byte(content), &result)
	if err == nil {
		if err := validateViolationLocations(&result); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &result, nil
	}

	// If direct JSON parsing failed, try to repair truncated JSON
	repairedResult, repairErr := repairTruncatedJSON(content)
	if repairErr == nil {
		return repairedResult, nil
	}

	// try to find a ```json <content> ``` and decode it
	jsonContent := content
	// Check if content contains JSON code blocks
	if strings.Contains(content, "```json") {
		// Find the JSON code block
		startIndex := strings.Index(content, "```json")
		if startIndex != -1 {
			// Move past the ```json marker
			startIndex += 7
			// Find the closing ```
			endIndex := strings.Index(content[startIndex:], "```")
			if endIndex != -1 {
				// Extract the JSON content between the markers
				jsonContent = strings.TrimSpace(content[startIndex : startIndex+endIndex])
			}
		}
	}

	err = json.Unmarshal([]byte(jsonContent), &result)
	if err == nil {
		if err := validateViolationLocations(&result); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &result, nil
	}

	// Check if content contains JSON code blocks
	if strings.Contains(content, "```") {
		// Find the JSON code block
		startIndex := strings.Index(content, "```")
		if startIndex != -1 {
			// Move past the ```json marker
			startIndex += 3
			// Find the closing ```
			endIndex := strings.Index(content[startIndex:], "```")
			if endIndex != -1 {
				// Extract the JSON content between the markers
				jsonContent = strings.TrimSpace(content[startIndex : startIndex+endIndex])
			}
		}
	}

	err = json.Unmarshal([]byte(jsonContent), &result)
	if err == nil {
		if err := validateViolationLocations(&result); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		return &result, nil
	}

	return nil, pkgerrors.New("cannot unmarshall JSON")
}

// nolint: gocyclo
func (agent *DetectionAgent) basicDetection(ctx context.Context, scanData *model.ScanData) (*DetectionResult, error) {
	violations := make([]model.Violation, 0)

	options := &clients.GenerateOptions{
		MaxTokens:    2192,
		ResponseType: "application/json",
		Temperature:  1.0, // default temperature
		Schema: clients.GenerateOptionSchema{
			Name:        "results",
			Description: "list of violations from the analysis",
			JsonSchema:  clients.GenerateSchema[model.LLMResult](),
		},
	}

	// Ensure we have a reasonable timeout (minimum 180 seconds)
	// Increased from 30s to 180s because OpenAI context can be longer for complex code analysis
	timeout := agent.requestTimeoutSec
	if timeout <= 0 {
		timeout = 180 // Default to 180 seconds if not set - longer timeout needed for complex code analysis
		if agent.debugEnabled {
			log.FromContext(ctx).Info("[debug] No timeout set, using default 180 seconds")
		}
	}

	contextWithDeadline, cancelFunc := context.WithDeadline(ctx, time.Now().Add(time.Second*time.Duration(timeout)))
	defer cancelFunc()

	if agent.debugEnabled {
		log.FromContext(ctx).Info(fmt.Sprintf("querying llm for rule:%s and %s", scanData.Rule.ID, scanData.RelativeFilePath))
	}
	response, err := agent.llmClient.GenerateContent(contextWithDeadline, scanData.SystemPrompt, scanData.UserPrompt, options)
	if err != nil {
		if agent.debugEnabled {
			// Check if it's a context deadline error
			if errors.Is(err, context.DeadlineExceeded) {
				log.FromContext(ctx).Warnf("[debug] timeout after %d seconds for file %s: %s", timeout, scanData.RelativeFilePath, err)
			} else {
				log.FromContext(ctx).Warnf("[debug] re-trying file %s because of error: %s", scanData.RelativeFilePath, err)
			}
		}
		return nil, err
	}

	content := response.Content
	inputTokens := response.InputTokens
	outputTokens := response.OutputTokens

	if strings.Contains(content, "NO VIOLATION AMIGO") {
		return &DetectionResult{
			Violations:   violations,
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			Path:         scanData.RelativeFilePath,
		}, nil
	}

	result, err := getViolationsFromContent(content)
	if err != nil {
		if agent.debugEnabled {
			log.FromContext(ctx).Info(
				fmt.Sprintf("[debug] re-trying file %s because we got an error when getting the violations %v, content: |%s|",
					scanData.RelativeFilePath, err, content),
				log.String("content", content),
			)
		}
		return nil, err
	}

	if agent.debugEnabled && result != nil {
		log.FromContext(ctx).
			Info(fmt.Sprintf("[%s] Found %d violations in %s",
				scanData.Rule.ID, len(result.Violations), scanData.RelativeFilePath))
	}

	// Verify violations in parallel since they are independent
	// Use a semaphore to limit concurrent verification calls
	const maxConcurrentVerifications = 3
	sem := make(chan struct{}, maxConcurrentVerifications)

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, r := range result.Violations {
		wg.Add(1)
		go func(violation model.LLMResultViolation) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Check context cancellation
			if ctx.Err() != nil {
				return
			}

			// Verify violation using higher fidelity model
			vResult, err := agent.VerifyViolation(ctx, scanData, violation)
			if err != nil {
				if agent.debugEnabled {
					log.FromContext(ctx).
						Info(fmt.Sprintf("failed to verify result for filepath %s for rule %s with err: %s: ",
							scanData.RelativeFilePath, scanData.Rule.ID, err.Error()))
				}
				return
			}

			if vResult.Confirmed {
				mu.Lock()
				violations = append(violations, model.Violation{
					StartLine:   violation.StartLine,
					StartColumn: violation.StartColumn,
					EndLine:     violation.EndLine,
					EndColumn:   violation.EndColumn,
					Path:        scanData.RelativeFilePath,
					Rule:        scanData.Rule.ID,
					Message:     violation.Reason,
					Cwe:         scanData.Rule.CWE,
				})
				mu.Unlock()
			} else if agent.debugEnabled {
				log.FromContext(ctx).Debug(fmt.Sprintf("found unconfirmed false positive: %s for %s",
					scanData.RelativeFilePath, scanData.Rule.ID))
			}
		}(r)
	}
	wg.Wait()

	return &DetectionResult{
		Violations:   violations,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		Path:         scanData.RelativeFilePath,
	}, nil
}

func (agent *DetectionAgent) VerifyViolation(ctx context.Context, scanData *model.ScanData,
	violation model.LLMResultViolation) (*VerificationResult, error) {
	logger := log.FromContext(ctx)
	userPrompt := getVerificationUserPrompt(scanData, violation)
	options := &clients.GenerateOptions{
		MaxTokens:    2048, // Less than initial detection since we're just verifying
		ResponseType: "application/json",
		Temperature:  1.0,
		Schema: clients.GenerateOptionSchema{
			Name:        "results",
			Description: "verify if a violation is a false positive or not",
			JsonSchema:  clients.GenerateSchema[VerificationResultData](),
		},
	}

	contextWithDeadline, cancelFunc := context.WithDeadline(ctx, time.Now().
		Add(time.Second*time.Duration(agent.requestTimeoutSec)))
	defer cancelFunc()

	response, err := agent.verificationLLMClient.GenerateContent(contextWithDeadline,
		VerificationSystemPrompt, userPrompt, options)
	if err != nil {
		if agent.debugEnabled {
			logger.Warnf("[debug] verification failed for %s:%d: %s",
				scanData.RelativeFilePath, violation.StartLine, err)
		}
		return nil, err
	}

	content := response.Content

	verificationData, err := parseVerificationResult(ctx, content, agent.debugEnabled)
	if err != nil {
		if agent.debugEnabled {
			logger.Warnf("[debug] verification parsing failed for %s:%d: %s",
				scanData.RelativeFilePath, violation.StartLine, err)
		}
		return nil, err
	}

	res := VerificationResult{

		InputTokens:  response.InputTokens,
		OutputTokens: response.OutputTokens,
	}
	res.Confirmed = verificationData.Confirmed
	res.Confidence = verificationData.Confidence
	res.Reason = verificationData.Reason
	return &res, nil
}

func (agent *DetectionAgent) Detect(ctx context.Context, scanData *model.ScanData) (*DetectionResult, error) {
	for i := 0; i < 3; i++ {
		res, err := agent.basicDetection(ctx, scanData)
		if err != nil {
			// Don't retry on rate limit - fail fast
			if clients.IsRateLimitError(err) {
				log.FromContext(ctx).Warnf("[fail-fast] rate limit detected, stopping analysis: %s", err)
				return nil, err
			}
			if agent.debugEnabled {
				log.FromContext(ctx).Warnf("[re-trying] detected error: %s", err)
			}
			continue
		} else {
			return res, nil
		}
	}

	if agent.debugEnabled {
		log.FromContext(ctx).Warnf("\"max number of attempts exceeded for file %s", scanData.RelativeFilePath)
	}
	return nil, pkgerrors.New("max analysis attempts exceeded")
}
