package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/candidates"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	pkgerrors "github.com/pkg/errors"
)

// aIGatewayFallbackModel is the model used automatically when rate limit (429) is hit with AI Gateway.
// Uses a different provider to avoid shared rate limits.
const aIGatewayFallbackModel = "openai/gpt-4.1-nano"

// ErrAgenticProtocolFailure indicates the agentic exploration phase ended without
// a single successfully executed tool call. It is an operational failure, not a
// verdict: the shared final verifier is never called for it and no decision is
// invented.
var ErrAgenticProtocolFailure = errors.New("agentic exploration produced no successful tool call")

type DetectionAgent struct {
	llmClient             clients.LLMClient
	verificationLLMClient clients.LLMClient

	agentOption *AgentOption

	// sandbox is non-nil only in agentic mode. It constrains all agent tool file
	// access to the scan root. When nil, the tool loops fall back to single-shot.
	sandbox *agenttools.Sandbox
	// scanRootRelative maps scan-relative paths to the repository-root sandbox.
	scanRootRelative string

	// Prevents retrying fallback when it also returns 429 (verification can be called for many violations)
	verificationFallbackAttempted bool
	verificationFallbackMu        sync.Mutex
	verificationActiveModel       string
}

type AgentOption struct {
	DetectionModel  model.Model
	ValidationModel model.Model
	OpenAiBaseUrl   string
	// Source sets the AI Gateway "source" header (and AI-Guard service name) on
	// the constructed clients. Empty defaults to clients.SourceDefault. The
	// verifier benchmark sets clients.SourceAgenticBenchmark so its traffic is
	// attributed to the correct rate-limit bucket rather than the production
	// source.
	Source            string
	RequestTimeoutSec int
	IsAIGateway       bool
	// DisableProviderFallback preserves the configured model when AI Gateway
	// returns a rate limit error.
	DisableProviderFallback bool
	AIGuardEnabled          bool
	OrgID                   int64
	// Temporary to avoid larger refactor: this should be handled with log levels, not booleans
	DebugEnabled bool

	// AgenticDetection enables the tool-using detection loop.
	AgenticDetection bool
	// AgenticVerification enables the tool-using verification loop.
	AgenticVerification bool
	// ScanRoot sandboxes all agent tool file access. Typically the scan
	// directory (AnalysisOptions.Directory).
	ScanRoot string
	// AgenticMaxIterations bounds model-to-tool round trips per detection or
	// verification unit.
	AgenticMaxIterations int
	// AgenticMaxToolCalls bounds total tool calls per detection or verification unit.
	AgenticMaxToolCalls int

	RepositoryID      string
	RepositorySHA     string
	RepositoryDirty   bool
	CandidateScanRoot string
	CandidateExporter *candidates.Exporter
}

// SetSymbolIndex installs the existing repository symbol index for agentic
// definition and reference searches. It is safe to call with nil or when
// agentic tools are unavailable.
func (agent *DetectionAgent) SetSymbolIndex(index agenttools.SymbolIndex) {
	if agent == nil || agent.sandbox == nil {
		return
	}
	agent.sandbox.SetSymbolIndex(index)
}

// SetProjectSymbolIndex installs SAIST's tree-sitter index and maps its
// scan-relative paths into the repository-root tool sandbox.
func (agent *DetectionAgent) SetProjectSymbolIndex(project *model.AiContextProject) {
	if agent == nil || agent.sandbox == nil || project == nil {
		return
	}
	agent.sandbox.SetSymbolIndex(agenttools.NewProjectSymbolIndexWithPrefix(project, agent.scanRootRelative))
}

type DetectionResult struct {
	Violations   []model.Violation
	Path         string
	InputTokens  int32
	OutputTokens int32
	ModelCalls   int32
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

type VerificationVerdictSource string

type VerificationFallbackReason string

type VerificationResult struct {
	VerificationResultData
	InputTokens              int32                      `json:"input_tokens"`
	OutputTokens             int32                      `json:"output_tokens"`
	RawVerdict               EvidenceVerdict            `json:"raw_verdict,omitempty"`
	ValidatedVerdict         EvidenceVerdict            `json:"validated_verdict,omitempty"`
	Evidence                 *StructuredVerdict         `json:"evidence,omitempty"`
	EvidenceValidationErrors []EvidenceValidationError  `json:"evidence_validation_errors,omitempty"`
	FinalVerdict             EvidenceVerdict            `json:"final_verdict"`
	VerdictSource            VerificationVerdictSource  `json:"verdict_source"`
	FallbackUsed             bool                       `json:"fallback_used"`
	FallbackReason           VerificationFallbackReason `json:"fallback_reason,omitempty"`
	FallbackVerdict          EvidenceVerdict            `json:"fallback_verdict,omitempty"`
	AgenticError             string                     `json:"agentic_error,omitempty"`
	FallbackError            string                     `json:"fallback_error,omitempty"`
	AgenticInputTokens       int32                      `json:"agentic_input_tokens"`
	AgenticOutputTokens      int32                      `json:"agentic_output_tokens"`
	FallbackInputTokens      int32                      `json:"fallback_input_tokens"`
	FallbackOutputTokens     int32                      `json:"fallback_output_tokens"`
	DurationMillis           int64                      `json:"duration_ms"`
	Telemetry                *VerificationTelemetry     `json:"telemetry,omitempty"`

	// Agentic exploration accounting. These are populated only by the agentic arm
	// so downstream can record what the collect-only exploration observed before
	// the shared final verifier decided. They never influence the decision.
	EvidencePayloadHash string `json:"evidence_payload_hash,omitempty"`
	// EvidencePayload is the exact serialized transcript passed to the final
	// verifier. It is held in memory only (never serialized into the content-free
	// trajectory) so the runner can persist it to the protected evidence store.
	EvidencePayload         []byte `json:"-"`
	InvestigationTurns      int    `json:"investigation_turns,omitempty"`
	SuccessfulToolCalls     int    `json:"successful_tool_calls,omitempty"`
	DistinctFilesRead       int    `json:"distinct_files_read,omitempty"`
	NewInformationRetrieved bool   `json:"new_information_retrieved,omitempty"`
}

func (result *VerificationResult) Abstained() bool {
	if result == nil {
		return false
	}
	if result.FinalVerdict != "" {
		return result.FinalVerdict == EvidenceVerdictAbstain
	}
	return result.ValidatedVerdict == EvidenceVerdictAbstain
}

func NewDetectionAgent(ctx context.Context, agentOption *AgentOption) (*DetectionAgent, error) {
	var client clients.LLMClient
	var err error
	var verificationClient clients.LLMClient

	// If a base URL is provided, always use OpenAI client (for custom endpoints like AI Gateway)
	if agentOption.OpenAiBaseUrl != "" {
		gatewaySource := agentOption.Source
		if gatewaySource == "" {
			gatewaySource = clients.SourceDefault
		}
		client, _ = clients.NewOpenAIClientWithSource(
			ctx,
			agentOption.DetectionModel.ToAPIModelWithFormat(agentOption.IsAIGateway),
			agentOption.OpenAiBaseUrl,
			agentOption.IsAIGateway,
			agentOption.AIGuardEnabled,
			agentOption.OrgID,
			gatewaySource,
		)
		verificationClient, err = clients.NewOpenAIClientWithSource(
			ctx,
			agentOption.ValidationModel.ToAPIModelWithFormat(agentOption.IsAIGateway),
			agentOption.OpenAiBaseUrl,
			agentOption.IsAIGateway,
			agentOption.AIGuardEnabled,
			agentOption.OrgID,
			gatewaySource,
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

	var sandbox *agenttools.Sandbox
	var scanRootRelative string
	if (agentOption.AgenticDetection || agentOption.AgenticVerification) && agentOption.ScanRoot != "" {
		sandboxRoot := agenttools.FindRepoRoot(agentOption.ScanRoot)
		sb, sbErr := agenttools.NewSandboxWithPriority(sandboxRoot, agentOption.ScanRoot)
		if sbErr != nil {
			// Disable agentic file tools rather than failing the scan. The loop
			// falls back to single-shot when the sandbox is nil.
			log.FromContext(ctx).Warnf("agentic tools disabled: cannot sandbox scan root %q: %v",
				sandboxRoot, sbErr)
		} else {
			sandbox = sb
			relativeRoot, relErr := filepath.Rel(sb.Root(), sb.SearchPriority())
			if relErr != nil {
				return nil, fmt.Errorf("resolve scan root relative to repository: %w", relErr)
			}
			if relativeRoot != "." {
				scanRootRelative = filepath.ToSlash(relativeRoot)
			}
		}
	}

	return &DetectionAgent{
		llmClient:               client,
		verificationLLMClient:   verificationClient,
		verificationActiveModel: agentOption.ValidationModel.ToAPIModelWithFormat(agentOption.IsAIGateway),
		agentOption:             agentOption,
		sandbox:                 sandbox,
		scanRootRelative:        scanRootRelative,
	}, nil
}

func (agent *DetectionAgent) repositoryRelativePath(scanData *model.ScanData) string {
	if scanData.RepositoryRelativeFilePath != "" {
		return path.Clean(filepath.ToSlash(scanData.RepositoryRelativeFilePath))
	}
	if agent.scanRootRelative == "" {
		return path.Clean(filepath.ToSlash(scanData.RelativeFilePath))
	}
	return path.Join(agent.scanRootRelative, filepath.ToSlash(scanData.RelativeFilePath))
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
func (agent *DetectionAgent) discoverCandidates(ctx context.Context, scanData *model.ScanData) (
	[]model.LLMResultViolation, int32, int32, int32, error,
) {
	options := &clients.GenerateOptions{
		MaxTokens:    detectionMaxTokens,
		ResponseType: "application/json",
		Temperature:  1.0, // default temperature
		Schema: clients.GenerateOptionSchema{
			Name:        "results",
			Description: "list of violations from the analysis",
			JsonSchema:  clients.GenerateSchema[model.LLMResult](),
		},
	}

	timeout := agent.agentOption.RequestTimeoutSec

	if agent.agentOption.DebugEnabled {
		log.FromContext(ctx).Info(fmt.Sprintf("querying llm for rule:%s and %s", scanData.Rule.ID, scanData.RelativeFilePath))
	}

	var content string
	var inputTokens, outputTokens int32
	var modelCalls int32
	var err error
	if agent.agentOption.AgenticDetection {
		// Tool-using loop applies its own per-call deadline internally.
		content, inputTokens, outputTokens, modelCalls, err =
			agent.detectWithToolsAccounting(ctx, scanData, options, timeout)
	} else {
		modelCalls = 1
		contextWithDeadline, cancelFunc := withOptionalTimeout(ctx, timeout)
		defer cancelFunc()
		started := time.Now()
		var resp *clients.GenerateResponse
		resp, err = agent.llmClient.GenerateContent(contextWithDeadline, scanData.SystemPrompt, scanData.UserPrompt, options)
		call := ModelCallTelemetry{
			Sequence:      1,
			Attempt:       1,
			Kind:          ModelCallKindSingleShot,
			Model:         agent.agentOption.DetectionModel.ToAPIModelWithFormat(agent.agentOption.IsAIGateway),
			LatencyMillis: time.Since(started).Milliseconds(),
		}
		applyModelCallOptions(&call,
			agent.agentOption.DetectionModel.ToAPIModelWithFormat(agent.agentOption.IsAIGateway), options)
		if resp != nil {
			content = resp.Content
			inputTokens = resp.InputTokens
			outputTokens = resp.OutputTokens
			call.ReturnedModel = resp.ReturnedModel
			call.InputTokens = resp.InputTokens
			call.OutputTokens = resp.OutputTokens
			call.UsageKnown = resp.UsageKnown || resp.InputTokens != 0 || resp.OutputTokens != 0
		}
		if err != nil {
			call.Error = err.Error()
		}
		log.FromContext(ctx).Info("standard detection accounting",
			log.String("phase", "detection"),
			log.String("unit", fmt.Sprintf("%s rule=%s", scanData.RelativeFilePath, scanData.Rule.ID)),
			log.Any("model_call_record", call),
		)
	}
	if err != nil {
		if agent.agentOption.DebugEnabled {
			// Check if it's a context deadline error
			if timeout > 0 && errors.Is(err, context.DeadlineExceeded) {
				log.FromContext(ctx).Warnf("[debug] timeout after %d seconds for file %s: %s", timeout, scanData.RelativeFilePath, err)
			} else {
				log.FromContext(ctx).Warnf("[debug] re-trying file %s because of error: %s", scanData.RelativeFilePath, err)
			}
		}
		return nil, inputTokens, outputTokens, modelCalls, err
	}

	if strings.Contains(content, "NO VIOLATION AMIGO") {
		return []model.LLMResultViolation{}, inputTokens, outputTokens, modelCalls, nil
	}

	result, err := getViolationsFromContent(content)
	if err != nil {
		if agent.agentOption.DebugEnabled {
			log.FromContext(ctx).Info(
				fmt.Sprintf("[debug] re-trying file %s because we got an error when getting the violations %v, content: |%s|",
					scanData.RelativeFilePath, err, content),
				log.String("content", content),
			)
		}
		return nil, inputTokens, outputTokens, modelCalls, err
	}

	if agent.agentOption.DebugEnabled && result != nil {
		log.FromContext(ctx).
			Info(fmt.Sprintf("[%s] Found %d violations in %s",
				scanData.Rule.ID, len(result.Violations), scanData.RelativeFilePath))
	}

	return result.Violations, inputTokens, outputTokens, modelCalls, nil
}

type candidateVerificationBatch struct {
	Violations   []model.Violation
	InputTokens  int32
	OutputTokens int32
	ModelCalls   int32
}

func (agent *DetectionAgent) verifyCandidates(ctx context.Context, scanData *model.ScanData,
	candidates []model.LLMResultViolation) candidateVerificationBatch {
	result := candidateVerificationBatch{Violations: make([]model.Violation, 0)}

	// Verify violations in parallel since they are independent
	// Use a semaphore to limit concurrent verification calls
	const maxConcurrentVerifications = 3
	sem := make(chan struct{}, maxConcurrentVerifications)

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, r := range candidates {
		wg.Add(1)
		go func(violation model.LLMResultViolation) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			confirmed, vResult, err := agent.VerifyCandidate(ctx, scanData, violation)
			if vResult != nil {
				mu.Lock()
				result.InputTokens += vResult.InputTokens
				result.OutputTokens += vResult.OutputTokens
				if vResult.Telemetry != nil {
					result.ModelCalls += int32(len(vResult.Telemetry.ModelCalls))
				}
				mu.Unlock()
			}
			if err != nil {
				if agent.agentOption.DebugEnabled {
					log.FromContext(ctx).
						Info(fmt.Sprintf("failed to verify result for filepath %s for rule %s with err: %s: ",
							scanData.RelativeFilePath, scanData.Rule.ID, err.Error()))
				}
				if agent.agentOption.AgenticVerification {
					retained := retainUnverifiedCandidate(scanData, violation)
					mu.Lock()
					result.Violations = append(result.Violations, retained)
					mu.Unlock()
				}
				return
			}

			if confirmed != nil {
				mu.Lock()
				result.Violations = append(result.Violations, *confirmed)
				mu.Unlock()
			} else if vResult.Abstained() {
				retained := retainUnverifiedCandidate(scanData, violation)
				mu.Lock()
				result.Violations = append(result.Violations, retained)
				mu.Unlock()
			} else if vResult != nil && agent.agentOption.DebugEnabled {
				log.FromContext(ctx).Debug(fmt.Sprintf("found unconfirmed false positive: %s for %s",
					scanData.RelativeFilePath, scanData.Rule.ID))
			}
		}(r)
	}
	wg.Wait()
	return result
}

func retainUnverifiedCandidate(scanData *model.ScanData, candidate model.LLMResultViolation) model.Violation {
	return model.Violation{
		StartLine:   candidate.StartLine,
		StartColumn: candidate.StartColumn,
		EndLine:     candidate.EndLine,
		EndColumn:   candidate.EndColumn,
		Path:        scanData.RelativeFilePath,
		Rule:        scanData.Rule.ID,
		Message:     candidate.Reason,
		Cwe:         scanData.Rule.Cwe,
	}
}

func (agent *DetectionAgent) exportCandidates(scanData *model.ScanData,
	discovered []model.LLMResultViolation) error {
	exporter := agent.agentOption.CandidateExporter
	if exporter == nil {
		return nil
	}

	detectionMode := candidates.DetectionModeStandard
	if agent.agentOption.AgenticDetection {
		detectionMode = candidates.DetectionModeAgentic
	}
	for _, violation := range discovered {
		candidate, err := candidates.NewCandidate(candidates.NewCandidateInput{
			RepositoryID:     agent.agentOption.RepositoryID,
			RepositorySHA:    agent.agentOption.RepositorySHA,
			RepositoryDirty:  agent.agentOption.RepositoryDirty,
			ScanRoot:         agent.agentOption.CandidateScanRoot,
			RelativeFilePath: scanData.RelativeFilePath,
			Source:           []byte(scanData.FileText),
			Rule:             *scanData.Rule,
			StartLine:        violation.StartLine,
			StartColumn:      violation.StartColumn,
			EndLine:          violation.EndLine,
			EndColumn:        violation.EndColumn,
			DetectionReason:  violation.Reason,
			DetectionMode:    detectionMode,
		})
		if err != nil {
			return fmt.Errorf("build candidate for %s:%d: %w",
				scanData.RelativeFilePath, violation.StartLine, err)
		}
		if err := exporter.Append(candidate); err != nil {
			return fmt.Errorf("export candidate %s: %w", candidate.ID, err)
		}
	}
	return nil
}

func (agent *DetectionAgent) VerifyCandidate(ctx context.Context, scanData *model.ScanData,
	violation model.LLMResultViolation) (confirmed *model.Violation, vResult *VerificationResult, err error) {
	started := time.Now()
	defer func() {
		if vResult == nil {
			return
		}
		vResult.DurationMillis = time.Since(started).Milliseconds()
		if agent.agentOption.AgenticVerification {
			agent.logVerificationSummary(ctx, scanData, violation, vResult)
		}
	}()

	vResult, err = agent.VerifyViolation(ctx, scanData, violation)
	if err != nil {
		return nil, vResult, err
	}
	if vResult == nil {
		retained := retainUnverifiedCandidate(scanData, violation)
		return &retained, retainedVerificationResult(nil, FallbackAgenticFailure, nil,
			fmt.Errorf("verification returned no result"), false), nil
	}
	switch vResult.FinalVerdict {
	case EvidenceVerdictReject:
		return nil, vResult, nil
	case EvidenceVerdictAbstain:
		retained := retainUnverifiedCandidate(scanData, violation)
		return &retained, vResult, nil
	case EvidenceVerdictConfirm:
	default:
		unsupportedVerdict := vResult.FinalVerdict
		retained := retainUnverifiedCandidate(scanData, violation)
		vResult.FinalVerdict = EvidenceVerdictAbstain
		vResult.VerdictSource = VerificationSourceRetained
		vResult.Confirmed = false
		if vResult.FallbackError == "" {
			vResult.FallbackError = fmt.Sprintf("unsupported final verdict %q", unsupportedVerdict)
		}
		return &retained, vResult, nil
	}

	message := vResult.Reason
	if message == "" {
		message = violation.Reason
	}
	located := violation
	if fallbackLocation, ok := physicalLineLocation(scanData.FileText, violation.StartLine); ok {
		located.StartLine = fallbackLocation.StartLine
		located.StartColumn = fallbackLocation.StartColumn
		located.EndLine = fallbackLocation.EndLine
		located.EndColumn = fallbackLocation.EndColumn
	}
	locRes, locErr := agent.DetermineViolationLocation(ctx, scanData, violation, vResult)
	if locRes != nil {
		vResult.InputTokens += locRes.InputTokens
		vResult.OutputTokens += locRes.OutputTokens
	}
	if locErr == nil {
		located.StartLine = locRes.StartLine
		located.StartColumn = locRes.StartColumn
		located.EndLine = locRes.EndLine
		located.EndColumn = locRes.EndColumn
	} else {
		log.FromContext(ctx).Info(fmt.Sprintf(
			"location determination skipped for %s:%d, using detection region: %v",
			scanData.RelativeFilePath, violation.StartLine, locErr))
	}

	confirmed = &model.Violation{
		StartLine:   located.StartLine,
		StartColumn: located.StartColumn,
		EndLine:     located.EndLine,
		EndColumn:   located.EndColumn,
		Path:        scanData.RelativeFilePath,
		Rule:        scanData.Rule.ID,
		Message:     message,
		Cwe:         scanData.Rule.Cwe,
	}
	return confirmed, vResult, nil
}

func (agent *DetectionAgent) logVerificationSummary(ctx context.Context, scanData *model.ScanData,
	violation model.LLMResultViolation, result *VerificationResult) {
	telemetry := prepareVerificationTelemetry(result.Telemetry)
	candidateID := scanData.CandidateID
	if candidateID == "" {
		candidateID = fmt.Sprintf("%s#%d#%s", agent.repositoryRelativePath(scanData),
			violation.StartLine, scanData.Rule.ID)
	}
	searchTruncations := 0
	for _, call := range telemetry.ToolCalls {
		if call.Name == agenttools.ToolSearchCode && call.Truncated {
			searchTruncations++
		}
	}

	log.FromContext(ctx).Info("agentic verification summary",
		log.String("candidate_id", candidateID),
		log.String("phase", "verification"),
		log.String("model", telemetry.activeModel),
		log.Int("iterations", telemetry.InvestigationIterations),
		log.Int("model_calls", len(telemetry.ModelCalls)),
		log.Int("tool_calls", telemetry.RequestedToolCalls),
		log.Int("search_truncations", searchTruncations),
		log.Int32("input_tokens", result.InputTokens),
		log.Int32("output_tokens", result.OutputTokens),
		log.Int64("duration_ms", result.DurationMillis),
		log.String("stop_reason", string(telemetry.StopReason)),
		log.String("raw_agentic_verdict", string(result.RawVerdict)),
		log.String("validated_verdict", string(result.ValidatedVerdict)),
		log.String("final_verdict", string(result.FinalVerdict)),
		log.String("final_source", string(result.VerdictSource)),
		log.Bool("fallback_used", result.FallbackUsed),
		log.String("fallback_reason", string(result.FallbackReason)),
		log.String("fallback_verdict", string(result.FallbackVerdict)),
		log.String("provider_fallback_reason", telemetry.ProviderFallbackReason),
		log.Int("evidence_citation_count", evidenceCitationCount(result.Evidence)),
		log.Any("model_call_records", telemetry.ModelCalls),
		log.Any("tool_call_records", telemetry.ToolCalls),
	)
}

func evidenceCitationCount(evidence *StructuredVerdict) int {
	if evidence == nil {
		return 0
	}
	count := len(evidence.Flow) + len(evidence.Guards) + len(evidence.Counterevidence)
	if evidence.Sink != nil {
		count++
	}
	if evidence.Source != nil {
		count++
	}
	return count
}

func (agent *DetectionAgent) VerificationMode() string {
	if agent.agentOption.AgenticVerification {
		return "agentic"
	}
	return "standard"
}

func (agent *DetectionAgent) verificationClientSnapshot() (clients.LLMClient, string) {
	agent.verificationFallbackMu.Lock()
	defer agent.verificationFallbackMu.Unlock()
	modelName := agent.verificationActiveModel
	if modelName == "" && agent.agentOption != nil {
		modelName = agent.agentOption.ValidationModel.ToAPIModelWithFormat(agent.agentOption.IsAIGateway)
	}
	return agent.verificationLLMClient, modelName
}

func (agent *DetectionAgent) verificationProviderFallback(ctx context.Context,
	failedModel string) (clients.LLMClient, string, bool, error) {
	agent.verificationFallbackMu.Lock()
	defer agent.verificationFallbackMu.Unlock()

	if agent.agentOption == nil || agent.agentOption.DisableProviderFallback {
		return nil, agent.verificationActiveModel, false, nil
	}
	if agent.verificationFallbackAttempted {
		if agent.verificationLLMClient != nil && agent.verificationActiveModel != failedModel {
			return agent.verificationLLMClient, agent.verificationActiveModel, true, nil
		}
		return nil, agent.verificationActiveModel, false, nil
	}
	agent.verificationFallbackAttempted = true
	fallbackClient, err := clients.NewOpenAIClient(ctx, aIGatewayFallbackModel,
		agent.agentOption.OpenAiBaseUrl, agent.agentOption.IsAIGateway,
		agent.agentOption.AIGuardEnabled, agent.agentOption.OrgID)
	if err != nil {
		return nil, agent.verificationActiveModel, false, err
	}
	agent.verificationLLMClient = fallbackClient
	agent.verificationActiveModel = aIGatewayFallbackModel
	return fallbackClient, aIGatewayFallbackModel, true, nil
}

func (agent *DetectionAgent) ValidateVerificationMode() error {
	if !agent.agentOption.AgenticVerification {
		return nil
	}
	if agent.sandbox == nil {
		return fmt.Errorf("agentic verification requires a repository sandbox")
	}
	verificationClient, _ := agent.verificationClientSnapshot()
	if _, ok := verificationClient.(clients.ToolCallingClient); !ok {
		return fmt.Errorf("agentic verification requires a tool-calling client")
	}
	return nil
}

func (agent *DetectionAgent) basicDetection(ctx context.Context, scanData *model.ScanData) (*DetectionResult, error) {
	candidates, inputTokens, outputTokens, modelCalls, err := agent.discoverCandidates(ctx, scanData)
	if err != nil {
		return &DetectionResult{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			ModelCalls:   modelCalls,
			Path:         scanData.RelativeFilePath,
		}, err
	}
	if err := agent.exportCandidates(scanData, candidates); err != nil {
		return &DetectionResult{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
			ModelCalls:   modelCalls,
			Path:         scanData.RelativeFilePath,
		}, err
	}
	verification := agent.verifyCandidates(ctx, scanData, candidates)

	return &DetectionResult{
		Violations:   verification.Violations,
		InputTokens:  inputTokens + verification.InputTokens,
		OutputTokens: outputTokens + verification.OutputTokens,
		ModelCalls:   modelCalls + verification.ModelCalls,
		Path:         scanData.RelativeFilePath,
	}, nil
}

func (agent *DetectionAgent) Close() error {
	if agent.agentOption.CandidateExporter == nil {
		return nil
	}
	return agent.agentOption.CandidateExporter.Close()
}

func (agent *DetectionAgent) verificationGenerateContent(ctx context.Context, scanData *model.ScanData,
	violationLine uint, systemPrompt, userPrompt string, options *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return agent.verificationGenerateContentWithTelemetry(ctx, scanData, violationLine,
		systemPrompt, userPrompt, options, nil, ModelCallKindStandardVerification)
}

func (agent *DetectionAgent) verificationGenerateContentWithTelemetry(ctx context.Context, scanData *model.ScanData,
	violationLine uint, systemPrompt, userPrompt string, options *clients.GenerateOptions,
	telemetry *VerificationTelemetry, callKind ModelCallKind) (*clients.GenerateResponse, error) {
	logger := log.FromContext(ctx)
	telemetry = prepareVerificationTelemetry(telemetry)
	verificationClient, activeModel := agent.verificationClientSnapshot()
	telemetry.activeModel = activeModel
	timeout := agent.agentOption.RequestTimeoutSec
	generate := func(client clients.LLMClient, kind ModelCallKind) (*clients.GenerateResponse, error) {
		callCtx, cancel := withOptionalTimeout(ctx, timeout)
		response, _, err := agent.generateContentWithTelemetry(callCtx, client,
			systemPrompt, userPrompt, options, telemetry, telemetry.nextAttempt(), kind)
		cancel()
		return response, err
	}

	response, err := generate(verificationClient, callKind)
	if err != nil && clients.IsRateLimitError(err) && agent.agentOption.IsAIGateway &&
		!agent.agentOption.DisableProviderFallback {
		telemetry.ProviderFallbackReason = "rate_limit"
		fallbackClient, fallbackModel, retry, clientErr :=
			agent.verificationProviderFallback(ctx, activeModel)
		if clientErr != nil {
			logger.Warnf("Failed to create fallback verification client: %s", clientErr)
		} else if retry {
			logger.Warnf("Verification rate limit detected, switching to fallback validation model: %s",
				fallbackModel)
			telemetry.activeModel = fallbackModel
			response, err = generate(fallbackClient, ModelCallKindProviderFallback)
			if err != nil && agent.agentOption.DebugEnabled {
				logger.Warnf("[debug] verification client call failed with fallback model for %s:%d: %s",
					scanData.RelativeFilePath, violationLine, err)
			}
		}
	}

	if err != nil {
		if agent.agentOption.DebugEnabled {
			logger.Warnf("[debug] verification client call failed for %s:%d: %s",
				scanData.RelativeFilePath, violationLine, err)
		}
		return nil, err
	}

	return response, nil
}

func (agent *DetectionAgent) VerifyViolation(ctx context.Context, scanData *model.ScanData,
	violation model.LLMResultViolation) (*VerificationResult, error) {
	if !agent.agentOption.AgenticVerification {
		return agent.verifyViolationStandard(ctx, scanData, violation, nil, ModelCallKindStandardVerification)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Capability check. A missing sandbox or a non-tool-calling client is an
	// operational failure, not a verdict and not an abstain.
	if err := agent.ValidateVerificationMode(); err != nil {
		return nil, fmt.Errorf("agentic verification unavailable: %w", err)
	}

	// Collect-only repository exploration. The exploration never decides; it only
	// gathers a raw tool transcript for the shared final verifier.
	telemetry := prepareVerificationTelemetry(&VerificationTelemetry{})
	exploration, err := agent.exploreForEvidence(ctx, InvestigationSystemPrompt,
		getInvestigationUserPrompt(scanData, violation), agent.repositoryRelativePath(scanData), telemetry)
	if err != nil {
		return nil, err
	}
	if exploration.ProtocolFailed() {
		// No successful tool call. Do not call the final verifier and do not invent
		// a decision.
		return nil, ErrAgenticProtocolFailure
	}

	payload, err := SerializeEvidencePayload(exploration.Events)
	if err != nil {
		return nil, err
	}
	envelope := RenderEvidenceEnvelope(payload)

	// The binary decision comes only from the shared final verifier: the same call
	// the standard arm makes, plus one delimited repository-evidence section.
	final, err := agent.runFinalVerifier(ctx, scanData, violation, envelope, telemetry,
		ModelCallKindAgenticFinalVerification)
	if err != nil {
		return nil, err
	}
	final.VerdictSource = VerificationSourceAgentic
	final.EvidencePayloadHash = EvidencePayloadHash(payload)
	final.EvidencePayload = payload
	final.InputTokens = telemetry.InputTokens
	final.OutputTokens = telemetry.OutputTokens
	final.AgenticInputTokens = exploration.InputTokens
	final.AgenticOutputTokens = exploration.OutputTokens
	final.InvestigationTurns = exploration.InvestigationTurns
	final.SuccessfulToolCalls = exploration.SuccessfulToolCalls
	final.DistinctFilesRead = exploration.DistinctFilesRead
	final.NewInformationRetrieved = exploration.NewInformationRetrieved
	return final, nil
}

// runFinalVerifier issues the shared final-verifier request and decodes its
// binary verdict. Both arms call it identically: the standard arm passes an empty
// evidenceSuffix, and the agentic arm passes one delimited repository-evidence
// section that is appended to the standard user prompt. The system prompt and
// decoding options are always the standard ones, so when evidenceSuffix is empty
// the request is byte-identical to the standard arm. The decision comes only from
// parseVerificationResult and is confirm or reject. It never abstains. The caller
// sets VerdictSource.
func (agent *DetectionAgent) runFinalVerifier(ctx context.Context, scanData *model.ScanData,
	violation model.LLMResultViolation, evidenceSuffix string, telemetry *VerificationTelemetry,
	callKind ModelCallKind) (*VerificationResult, error) {
	logger := log.FromContext(ctx)
	telemetry = prepareVerificationTelemetry(telemetry)
	stageInputBefore := telemetry.InputTokens
	stageOutputBefore := telemetry.OutputTokens
	userPrompt := getVerificationUserPrompt(scanData, violation)
	if evidenceSuffix != "" {
		userPrompt += "\n\n" + evidenceSuffix
	}
	options := standardVerificationOptions()
	response, err := agent.verificationGenerateContentWithTelemetry(ctx, scanData, violation.StartLine,
		VerificationSystemPrompt, userPrompt, &options, telemetry, callKind)
	stageInputTokens := telemetry.InputTokens - stageInputBefore
	stageOutputTokens := telemetry.OutputTokens - stageOutputBefore
	if err != nil {
		return &VerificationResult{
			InputTokens:  stageInputTokens,
			OutputTokens: stageOutputTokens,
			Telemetry:    telemetry,
		}, err
	}
	var content string
	if response != nil {
		content = response.Content
	}

	verificationData, err := parseVerificationResult(ctx, content, agent.agentOption.DebugEnabled)
	if err != nil {
		telemetry.markLastModelCallError(err)
		if agent.agentOption.DebugEnabled {
			logger.Warnf("[debug] verification parsing failed for %s:%d: %s",
				scanData.RelativeFilePath, violation.StartLine, err)
		}
		return &VerificationResult{
			InputTokens:  stageInputTokens,
			OutputTokens: stageOutputTokens,
			Telemetry:    telemetry,
		}, err
	}

	res := VerificationResult{
		InputTokens:  stageInputTokens,
		OutputTokens: stageOutputTokens,
		Telemetry:    telemetry,
	}
	res.Confirmed = verificationData.Confirmed
	res.Confidence = verificationData.Confidence
	res.Reason = verificationData.Reason
	if verificationData.Confirmed {
		res.RawVerdict = EvidenceVerdictConfirm
		res.ValidatedVerdict = EvidenceVerdictConfirm
	} else {
		res.RawVerdict = EvidenceVerdictReject
		res.ValidatedVerdict = EvidenceVerdictReject
	}
	res.FinalVerdict = res.ValidatedVerdict
	return &res, nil
}

// verifyViolationStandard runs the shared final verifier with no repository
// evidence, so its request is byte-identical to the frozen standard baseline. It
// only tags the verdict source as standard.
func (agent *DetectionAgent) verifyViolationStandard(ctx context.Context, scanData *model.ScanData,
	violation model.LLMResultViolation, telemetry *VerificationTelemetry,
	callKind ModelCallKind) (*VerificationResult, error) {
	result, err := agent.runFinalVerifier(ctx, scanData, violation, "", telemetry, callKind)
	if result != nil {
		result.VerdictSource = VerificationSourceStandard
	}
	return result, err
}

func retainedVerificationResult(result *VerificationResult, reason VerificationFallbackReason,
	agenticErr, fallbackErr error, fallbackUsed bool) *VerificationResult {
	if result == nil {
		result = &VerificationResult{}
	}
	result.Confirmed = false
	result.Confidence = string(EvidenceConfidenceLow)
	result.Reason = "Verification could not reach a reliable verdict."
	if result.ValidatedVerdict == "" {
		result.ValidatedVerdict = EvidenceVerdictAbstain
	}
	result.FinalVerdict = EvidenceVerdictAbstain
	result.VerdictSource = VerificationSourceRetained
	result.FallbackUsed = fallbackUsed
	result.FallbackReason = reason
	if agenticErr != nil {
		result.AgenticError = agenticErr.Error()
	}
	if fallbackErr != nil {
		result.FallbackError = fallbackErr.Error()
	}
	if result.Telemetry != nil {
		result.Telemetry.FallbackReason = string(reason)
	}
	return result
}

func (agent *DetectionAgent) Detect(ctx context.Context, scanData *model.ScanData) (*DetectionResult, error) {
	accumulated := &DetectionResult{Path: scanData.RelativeFilePath}
	for i := 0; i < 3; i++ {
		res, err := agent.basicDetection(ctx, scanData)
		if err != nil {
			if res != nil {
				accumulated.InputTokens += res.InputTokens
				accumulated.OutputTokens += res.OutputTokens
				accumulated.ModelCalls += res.ModelCalls
			}
			// On rate limit with AI Gateway, try hardcoded fallback model once
			if clients.IsRateLimitError(err) && agent.agentOption.IsAIGateway &&
				!agent.agentOption.DisableProviderFallback && i == 0 {
				log.FromContext(ctx).Warnf("Rate limit detected, switching to fallback detection model: %s",
					aIGatewayFallbackModel)

				fallbackClient, clientErr := clients.NewOpenAIClient(ctx,
					aIGatewayFallbackModel,
					agent.agentOption.OpenAiBaseUrl,
					agent.agentOption.IsAIGateway,
					agent.agentOption.AIGuardEnabled,
					agent.agentOption.OrgID)

				if clientErr == nil {
					agent.llmClient = fallbackClient
					continue // Retry with fallback
				}
				log.FromContext(ctx).Warnf("Failed to create fallback client: %s", clientErr)
			}

			// Fail fast on rate limit if no fallback or already tried fallback
			if clients.IsRateLimitError(err) {
				log.FromContext(ctx).Warnf("[fail-fast] rate limit detected, stopping analysis: %s", err)
				return accumulated, err
			}

			if agent.agentOption.DebugEnabled {
				log.FromContext(ctx).Warnf("[re-trying] detected error: %s", err)
			}
			continue
		} else {
			res.InputTokens += accumulated.InputTokens
			res.OutputTokens += accumulated.OutputTokens
			res.ModelCalls += accumulated.ModelCalls
			return res, nil
		}
	}

	if agent.agentOption.DebugEnabled {
		log.FromContext(ctx).Warnf("\"max number of attempts exceeded for file %s", scanData.RelativeFilePath)
	}
	return accumulated, pkgerrors.New("max analysis attempts exceeded")
}
