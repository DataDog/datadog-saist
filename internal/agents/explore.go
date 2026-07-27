// nolint:lll
package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/utils"
)

// investigationPromptContract enumerates the agentic exploration prompt and
// budget contract. It is hashed separately from the shared final-verifier
// contract and is never part of FinalVerifierContractHash.
func investigationPromptContract() []any {
	return []any{
		InvestigationSystemPrompt,
		InvestigationUserPrompt,
		investigationToolReminder,
		agenticMaxInvestigationTurns,
		agenticMaxToolCallsPerTurn,
		agenticMaxTotalToolCalls,
		agenticMaxDistinctFilesRead,
		agenticTotalToolOutputBudgetBytes,
	}
}

// InvestigationPromptHash identifies the agentic exploration prompt and budget
// contract. It is recorded on agentic trajectories and is independent of the
// shared final-verifier contract hash.
func InvestigationPromptHash() (string, error) {
	encoded, err := json.Marshal(investigationPromptContract())
	if err != nil {
		return "", fmt.Errorf("encode investigation prompt contract, %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// getInvestigationUserPrompt renders the collect-only investigation user prompt
// for one candidate. It uses the same flagged source context as the standard
// verifier so the exploration starts from identical preloaded information.
func getInvestigationUserPrompt(scanData *model.ScanData, violation model.LLMResultViolation) string {
	numberedCode := scanData.NumberedFileText
	if numberedCode == "" {
		numberedCode = utils.AddLineNumbers(scanData.FileText)
	}
	return fmt.Sprintf(
		InvestigationUserPrompt,
		scanData.RelativeFilePath,
		violation.StartLine,
		violation.Reason,
		numberedCode,
		scanData.Rule.Content,
	)
}

// explorationResult is the product of the collect-only exploration phase. Its
// only substantive output is Events, the ordered raw tool transcript. It carries
// no verdict, recommendation, interpretation, or summary. A trajectory with
// SuccessfulToolCalls == 0 is an agentic protocol failure and the final verifier
// must not be called for it.
type explorationResult struct {
	Events                  []EvidenceEvent
	SuccessfulToolCalls     int
	ExecutedToolCalls       int
	DistinctFilesRead       int
	NewInformationRetrieved bool
	InvestigationTurns      int
	StopReason              LoopStopReason
	InputTokens             int32
	OutputTokens            int32
}

// ProtocolFailed reports whether the exploration ended without a single
// successfully executed tool call.
func (r explorationResult) ProtocolFailed() bool {
	return r.SuccessfulToolCalls == 0
}

// exploreForEvidence runs the bounded, collect-only exploration phase for one
// verification candidate. It offers the read-only tools with no response schema
// so tool calls are not suppressed, records every tool interaction as an ordered
// EvidenceEvent (including the exact result content shown to the model), and
// NEVER asks for or accepts a verdict, summary, or interpretation. The model's
// prose is ignored entirely.
//
// It forces tool use until the first successful call: if the model tries to
// finish before any tool has succeeded, it is reminded and the loop continues
// within the fixed turn budget. If no tool call succeeds before the budget is
// exhausted, StopReason is LoopStopReasonNoSuccessfulTool and ProtocolFailed
// reports true; the caller must record an agentic protocol failure and must not
// call the final verifier.
func (agent *DetectionAgent) exploreForEvidence(ctx context.Context, systemPrompt, userPrompt, flaggedPath string,
	telemetry *VerificationTelemetry) (explorationResult, error) {
	telemetry = prepareVerificationTelemetry(telemetry)
	result := explorationResult{StopReason: LoopStopReasonNoSuccessfulTool}

	client, activeModel := agent.verificationClientSnapshot()
	if telemetry.activeModel == "" {
		telemetry.activeModel = activeModel
	}
	tc, ok := client.(clients.ToolCallingClient)
	if !ok || agent.sandbox == nil {
		if !ok {
			result.StopReason = LoopStopReasonUnsupportedClient
		} else {
			result.StopReason = LoopStopReasonSandboxUnavailable
		}
		telemetry.StopReason = result.StopReason
		return result, fmt.Errorf("agentic exploration requires a tool-capable client and a repository sandbox")
	}

	// Anchor the default search scope at the flagged file's directory so a
	// search_code call that omits path_glob starts locally and only widens toward
	// the repository root when nearby scopes are too sparse. The anchor is carried
	// per candidate on the context, leaving the shared sandbox immutable and safe
	// for concurrent candidates.
	ctx = agenttools.WithSearchAnchor(ctx, path.Dir(flaggedPath))

	perCallTimeout := agent.agentOption.RequestTimeoutSec
	attempt := telemetry.nextAttempt()

	maxTurns := agent.agentOption.AgenticMaxIterations
	if maxTurns <= 0 {
		maxTurns = agenticMaxInvestigationTurns
	}
	maxTotalToolCalls := agent.agentOption.AgenticMaxToolCalls
	if maxTotalToolCalls <= 0 {
		maxTotalToolCalls = agenticMaxTotalToolCalls
	}

	loopOptions := clients.GenerateOptions{}
	if agenticMinCompletionTokens > 0 {
		loopOptions.MaxTokens = agenticMinCompletionTokens
	}

	tools := agenttools.Definitions()
	msgs := []clients.Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}
	seen := map[string]bool{}
	distinctFiles := map[string]bool{}
	outputBytes := 0
	outputBudgetExhausted := false

	for turn := 0; turn < maxTurns; turn++ {
		result.InvestigationTurns++
		callCtx, cancel := withOptionalTimeout(ctx, perCallTimeout)
		resp, modelSeq, err := agent.generateWithToolsTelemetry(callCtx, tc, msgs, tools, &loopOptions,
			telemetry, attempt, ModelCallKindAgenticInvestigation)
		cancel()
		if resp != nil {
			result.InputTokens += resp.InputTokens
			result.OutputTokens += resp.OutputTokens
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			result.StopReason = LoopStopReasonInvestigationCallFailed
			telemetry.StopReason = result.StopReason
			return result, ctxErr
		}
		if err != nil {
			result.StopReason = LoopStopReasonInvestigationCallFailed
			telemetry.StopReason = result.StopReason
			return result, err
		}

		if len(resp.ToolCalls) == 0 {
			if result.SuccessfulToolCalls == 0 {
				// Force tool use: remind and continue within the fixed budget. The
				// model's prose is never carried into the final verifier.
				msgs = append(msgs, clients.Message{Role: "assistant", Content: resp.Content})
				msgs = append(msgs, clients.Message{Role: "user", Content: investigationToolReminder})
				continue
			}
			// Exploration complete. The model's prose is deliberately ignored.
			result.StopReason = LoopStopReasonReadyToAnswer
			telemetry.StopReason = result.StopReason
			return result, nil
		}

		msgs = append(msgs, clients.Message{Role: "assistant", Content: resp.Content, ToolCalls: resp.ToolCalls})

		callsThisTurn := 0
		for _, call := range resp.ToolCalls {
			toolStart := time.Now()
			readPath, isRead := readFilePathArgument(call)
			var out string
			var disposition ToolCallDisposition
			switch {
			case callsThisTurn >= agenticMaxToolCallsPerTurn:
				out, disposition = toolBudgetNote, ToolCallDispositionBudgetRefused
			case result.ExecutedToolCalls >= maxTotalToolCalls || outputBudgetExhausted:
				out, disposition = toolBudgetNote, ToolCallDispositionBudgetRefused
			case isRead && !distinctFiles[readPath] && len(distinctFiles) >= agenticMaxDistinctFilesRead:
				out, disposition = toolBudgetNote, ToolCallDispositionBudgetRefused
			default:
				out, disposition = agent.execToolWithDisposition(ctx, call, seen, perCallTimeout)
				callsThisTurn++
				if disposition == ToolCallDispositionExecuted {
					result.ExecutedToolCalls++
					outputBytes += len([]byte(out))
					if outputBytes >= agenticTotalToolOutputBudgetBytes {
						outputBudgetExhausted = true
					}
				}
			}

			metadata := agenttools.InspectResult(out)
			telemetry.addToolCall(ToolCallTelemetry{
				ModelCallSequence: modelSeq,
				ToolCallID:        call.ID,
				Name:              call.Name,
				Arguments:         call.Arguments,
				ResultBytes:       len([]byte(out)),
				Truncated:         metadata.Truncated,
				Incomplete:        metadata.Incomplete,
				StopReason:        metadata.StopReason,
				FilesScanned:      metadata.FilesScanned,
				SearchScope:       metadata.SearchScope,
				Error:             metadata.Error,
				Disposition:       disposition,
				LatencyMillis:     time.Since(toolStart).Milliseconds(),
			})

			result.Events = append(result.Events, NewEvidenceEvent(len(result.Events)+1, call.ID, call.Name,
				call.Arguments, string(disposition), out))

			if disposition == ToolCallDispositionExecuted && metadata.Error == "" {
				result.SuccessfulToolCalls++
				if isRead {
					distinctFiles[readPath] = true
					if readPath != flaggedPath {
						result.NewInformationRetrieved = true
					}
				} else {
					result.NewInformationRetrieved = true
				}
			}

			msgs = append(msgs, clients.Message{Role: "tool", ToolCallID: call.ID, Content: out})

			if ctxErr := ctx.Err(); ctxErr != nil {
				result.StopReason = LoopStopReasonInvestigationCallFailed
				telemetry.StopReason = result.StopReason
				return result, ctxErr
			}
		}
		result.DistinctFilesRead = len(distinctFiles)

		if outputBudgetExhausted {
			result.StopReason = LoopStopReasonToolOutputBudgetExhausted
			break
		}
		if result.ExecutedToolCalls >= maxTotalToolCalls {
			result.StopReason = LoopStopReasonToolCallBudgetExhausted
			break
		}
	}

	if result.SuccessfulToolCalls == 0 {
		result.StopReason = LoopStopReasonNoSuccessfulTool
		telemetry.StopReason = result.StopReason
		return result, nil
	}
	if result.StopReason == LoopStopReasonNoSuccessfulTool {
		result.StopReason = LoopStopReasonIterationBudgetExhausted
	}
	telemetry.StopReason = result.StopReason
	return result, nil
}

// readFilePathArgument returns the repository-relative path for a read_file tool
// call so the distinct-file budget and new-information tracking can be applied.
func readFilePathArgument(call clients.ToolCall) (string, bool) {
	if call.Name != agenttools.ToolReadFile {
		return "", false
	}
	var args struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
		return "", true
	}
	return args.Path, true
}
