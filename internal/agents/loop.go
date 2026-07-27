package agents

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
)

// runToolLoop drives a bounded tool-using conversation against client in two
// phases. The investigation phase offers the read-only tools with no
// response_format (so the model can actually emit tool calls) and lets it read
// cross-file context until it stops requesting tools or a budget is hit. The
// verdict phase then makes one tools-off call with the original options, so
// GenerateWithTools applies the strict response_format and the final answer is
// as disciplined as the single-shot baseline. When the client cannot carry tools
// (native Gemini/Anthropic) or no sandbox is configured, it preserves the exact
// single-shot behavior with one call. A positive perCallTimeoutSec wraps each
// model and local tool call. Returned token counts are summed across every
// call. phase and unitLabel identify the caller (e.g. "detection",
// "file.go rule=go-sqli").
// Detection keeps its always-on loop summary log. Verification exposes the
// richer per-candidate telemetry instead.
func (agent *DetectionAgent) runToolLoop(ctx context.Context, client clients.LLMClient,
	systemPrompt, userPrompt string, options *clients.GenerateOptions, perCallTimeoutSec int,
	phase, unitLabel, ruleID string) (string, int32, int32, error) {
	telemetry := &VerificationTelemetry{}
	content, inputTokens, outputTokens, err := agent.runToolLoopWithTelemetry(ctx, client,
		systemPrompt, userPrompt, options, perCallTimeoutSec, phase, unitLabel, ruleID, telemetry)
	if phase == "detection" {
		agent.logLoopSummary(ctx, phase, unitLabel, telemetry.InvestigationIterations,
			telemetry.RequestedToolCalls, inputTokens, outputTokens, string(telemetry.StopReason))
	}
	return content, inputTokens, outputTokens, err
}

// runToolLoopWithTelemetry runs one bounded agentic attempt and appends
// content-free model and tool accounting to telemetry.
func (agent *DetectionAgent) runToolLoopWithTelemetry(ctx context.Context, client clients.LLMClient,
	systemPrompt, userPrompt string, options *clients.GenerateOptions, perCallTimeoutSec int,
	phase, unitLabel, ruleID string, telemetry *VerificationTelemetry) (string, int32, int32, error) {
	telemetry = prepareVerificationTelemetry(telemetry)
	attempt := telemetry.nextAttempt()
	if telemetry.activeModel == "" && agent.agentOption != nil {
		modelValue := agent.agentOption.DetectionModel
		if phase == "verification" {
			modelValue = agent.agentOption.ValidationModel
		}
		telemetry.activeModel = modelValue.ToAPIModelWithFormat(agent.agentOption.IsAIGateway)
	}

	tc, ok := client.(clients.ToolCallingClient)
	if !ok || agent.sandbox == nil {
		if !ok {
			telemetry.StopReason = LoopStopReasonUnsupportedClient
		} else {
			telemetry.StopReason = LoopStopReasonSandboxUnavailable
		}
		callCtx, cancel := withOptionalTimeout(ctx, perCallTimeoutSec)
		resp, _, err := agent.generateContentWithTelemetry(callCtx, client, systemPrompt,
			userPrompt, options, telemetry, attempt, ModelCallKindSingleShot)
		cancel()
		if ctxErr := ctx.Err(); ctxErr != nil {
			telemetry.StopReason = LoopStopReasonInvestigationCallFailed
			if resp != nil {
				return "", resp.InputTokens, resp.OutputTokens, ctxErr
			}
			return "", 0, 0, ctxErr
		}
		if err != nil {
			if resp != nil {
				return "", resp.InputTokens, resp.OutputTokens, err
			}
			return "", 0, 0, err
		}
		return resp.Content, resp.InputTokens, resp.OutputTokens, nil
	}

	// Tool-using turns need more completion headroom than the single-shot budget.
	// Clone the options so the non-agentic path's budget is never affected.
	loopOptions := *options
	if loopOptions.MaxTokens > 0 && loopOptions.MaxTokens < agenticMinCompletionTokens {
		loopOptions.MaxTokens = agenticMinCompletionTokens
	}

	maxIterations := agent.agentOption.AgenticMaxIterations
	if maxIterations <= 0 {
		maxIterations = defaultAgenticMaxIterations
	}
	maxToolCalls := agent.agentOption.AgenticMaxToolCalls
	if maxToolCalls <= 0 {
		maxToolCalls = defaultAgenticMaxToolCalls
	}

	tools := agenttools.Definitions()
	systemContent := systemPrompt + "\n\n" + agenticToolNudge
	if phase == "detection" {
		systemContent += "\n\n" + agenticEnumerateSitesNudge
	}
	msgs := []clients.Message{
		{Role: "system", Content: systemContent},
		{Role: "user", Content: userPrompt},
	}
	seen := map[string]bool{}
	var inTok, outTok int32
	toolCallCount := 0
	outputChars := 0
	outputBudgetExhausted := false
	investigationSummary := ""
	telemetry.StopReason = LoopStopReasonIterationBudgetExhausted

	for range maxIterations {
		telemetry.InvestigationIterations++
		callCtx, cancel := withOptionalTimeout(ctx, perCallTimeoutSec)
		resp, modelCallSequence, err := agent.generateWithToolsTelemetry(callCtx, tc, msgs, tools,
			&loopOptions, telemetry, attempt, ModelCallKindAgenticInvestigation)
		cancel()
		if resp != nil {
			inTok += resp.InputTokens
			outTok += resp.OutputTokens
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			telemetry.StopReason = LoopStopReasonInvestigationCallFailed
			return "", inTok, outTok, ctxErr
		}
		if err != nil {
			telemetry.StopReason = LoopStopReasonInvestigationCallFailed
			return "", inTok, outTok, err
		}

		if len(resp.ToolCalls) == 0 {
			if phase == "verification" && strings.TrimSpace(resp.Content) != "" {
				investigationSummary = strings.TrimSpace(resp.Content)
				msgs = append(msgs, clients.Message{Role: "assistant", Content: investigationSummary})
			}
			// Model is done investigating. Fall through to the verdict call, which
			// re-derives the answer under the strict response_format.
			telemetry.StopReason = LoopStopReasonReadyToAnswer
			break
		}

		// Record the assistant turn (with its tool calls) so the history replays.
		msgs = append(msgs, clients.Message{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		})

		for _, call := range resp.ToolCalls {
			toolStart := time.Now()
			var out string
			var disposition ToolCallDisposition
			switch {
			case toolCallCount >= maxToolCalls || outputBudgetExhausted:
				out = toolBudgetNote
				disposition = ToolCallDispositionBudgetRefused
			default:
				out, disposition = agent.execToolWithDisposition(ctx, call, seen, perCallTimeoutSec)
				toolCallCount++
				outputChars += len(out)
				if outputChars >= agenticToolOutputCharBudget {
					outputBudgetExhausted = true
				}
			}
			metadata := agenttools.InspectResult(out)
			telemetry.addToolCall(ToolCallTelemetry{
				ModelCallSequence: modelCallSequence,
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
			msgs = append(msgs, clients.Message{
				Role:       "tool",
				ToolCallID: call.ID,
				Content:    out,
			})
			if err := ctx.Err(); err != nil {
				telemetry.StopReason = LoopStopReasonInvestigationCallFailed
				return "", inTok, outTok, err
			}
		}

		if outputBudgetExhausted {
			telemetry.StopReason = LoopStopReasonToolOutputBudgetExhausted
			break
		}
		if toolCallCount >= maxToolCalls {
			telemetry.StopReason = LoopStopReasonToolCallBudgetExhausted
			break
		}
	}

	if phase == "verification" {
		if investigationSummary == "" {
			telemetry.SummaryRequested = true
			msgs = append(msgs, clients.Message{Role: "user", Content: investigationSummaryRequest})
			summaryOptions := loopOptions
			summaryOptions.ResponseType = ""
			summaryOptions.Schema = clients.GenerateOptionSchema{}
			summaryCtx, summaryCancel := withOptionalTimeout(ctx, perCallTimeoutSec)
			summary, _, summaryErr := agent.generateWithToolsTelemetry(summaryCtx, tc, msgs, nil,
				&summaryOptions, telemetry, attempt, ModelCallKindAgenticSummary)
			summaryCancel()
			if summary != nil {
				inTok += summary.InputTokens
				outTok += summary.OutputTokens
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				telemetry.StopReason = LoopStopReasonSummaryCallFailed
				return "", inTok, outTok, ctxErr
			}
			if summaryErr != nil {
				telemetry.StopReason = LoopStopReasonSummaryCallFailed
				return "", inTok, outTok, summaryErr
			}
			investigationSummary = strings.TrimSpace(summary.Content)
			if investigationSummary == "" {
				telemetry.StopReason = LoopStopReasonEmptySummary
				return "", inTok, outTok, fmt.Errorf("agentic verification returned an empty investigation summary")
			}
			msgs = append(msgs, clients.Message{Role: "assistant", Content: investigationSummary})
		}
		msgs = append(msgs, clients.Message{Role: "user", Content: structuredVerdictRequest})
	}

	// The verdict phase makes one tools-off call over the gathered context. With no tools
	// offered, GenerateWithTools applies the strict response_format from the
	// original options, so every agentic answer is as disciplined as the
	// single-shot baseline. The investigation turns above run schema-free so tools
	// can fire. This turn is where the actual finding JSON is produced.
	verdictCtx, cancel := withOptionalTimeout(ctx, perCallTimeoutSec)
	verdict, _, err := agent.generateWithToolsTelemetry(verdictCtx, tc, msgs, nil, options,
		telemetry, attempt, ModelCallKindAgenticVerdict)
	cancel()
	if verdict != nil {
		inTok += verdict.InputTokens
		outTok += verdict.OutputTokens
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		telemetry.StopReason = LoopStopReasonVerdictCallFailed
		return "", inTok, outTok, ctxErr
	}
	if err != nil {
		telemetry.StopReason = LoopStopReasonVerdictCallFailed
		return "", inTok, outTok, err
	}
	return verdict.Content, inTok, outTok, nil
}

// execTool dispatches a single tool call to the sandboxed tool registry,
// deduplicating identical calls so the model cannot loop on the same request.
func (agent *DetectionAgent) execTool(ctx context.Context, call clients.ToolCall, seen map[string]bool,
	perCallTimeoutSec int) string {
	out, _ := agent.execToolWithDisposition(ctx, call, seen, perCallTimeoutSec)
	return out
}

func (agent *DetectionAgent) execToolWithDisposition(ctx context.Context, call clients.ToolCall,
	seen map[string]bool, perCallTimeoutSec int) (string, ToolCallDisposition) {
	key := call.Name + "\x00" + call.Arguments
	if seen[key] {
		return toolDuplicateNote, ToolCallDispositionDuplicate
	}
	seen[key] = true

	toolCtx, cancel := withOptionalTimeout(ctx, perCallTimeoutSec)
	out := agenttools.ExecuteContext(toolCtx, agent.sandbox, call.Name, call.Arguments)
	cancel()
	metadata := agenttools.InspectResult(out)
	disposition := ToolCallDispositionExecuted
	if call.Name == agenttools.ToolSearchCode &&
		(metadata.StopReason == agenttools.StopReasonInvalidArguments ||
			metadata.StopReason == agenttools.StopReasonPathGlobRequired) {
		disposition = ToolCallDispositionInvalidArgs
	}
	if agent.agentOption.DebugEnabled {
		log.FromContext(ctx).Debugf("[agentic] tool %s(%s) -> %d bytes",
			call.Name, truncateForLog(call.Arguments, 200), len(out))
	}
	return out, disposition
}

func (agent *DetectionAgent) generateWithToolsTelemetry(ctx context.Context, client clients.ToolCallingClient,
	messages []clients.Message, tools []clients.ToolDefinition, options *clients.GenerateOptions,
	telemetry *VerificationTelemetry, attempt int, kind ModelCallKind) (*clients.ToolGenerateResponse, int, error) {
	started := time.Now()
	response, err := client.GenerateWithTools(ctx, messages, tools, options)
	if response == nil && err == nil {
		err = fmt.Errorf("tool-capable model call returned a nil response")
	}
	call := ModelCallTelemetry{
		Attempt:       attempt,
		Kind:          kind,
		Model:         telemetry.activeModel,
		LatencyMillis: time.Since(started).Milliseconds(),
	}
	applyModelCallOptions(&call, telemetry.activeModel, options)
	if response != nil {
		call.ReturnedModel = response.ReturnedModel
		call.InputTokens = response.InputTokens
		call.OutputTokens = response.OutputTokens
		call.UsageKnown = response.UsageKnown || response.InputTokens != 0 || response.OutputTokens != 0
		call.FinishReason = response.FinishReason
	}
	if err != nil {
		call.Error = err.Error()
	}
	sequence := telemetry.addModelCall(call)
	return response, sequence, err
}

func (agent *DetectionAgent) generateContentWithTelemetry(ctx context.Context, client clients.LLMClient,
	systemPrompt, userPrompt string, options *clients.GenerateOptions, telemetry *VerificationTelemetry,
	attempt int, kind ModelCallKind) (*clients.GenerateResponse, int, error) {
	started := time.Now()
	response, err := client.GenerateContent(ctx, systemPrompt, userPrompt, options)
	if response == nil && err == nil {
		err = fmt.Errorf("model call returned a nil response")
	}
	call := ModelCallTelemetry{
		Attempt:       attempt,
		Kind:          kind,
		Model:         telemetry.activeModel,
		LatencyMillis: time.Since(started).Milliseconds(),
	}
	applyModelCallOptions(&call, telemetry.activeModel, options)
	if response != nil {
		call.ReturnedModel = response.ReturnedModel
		call.InputTokens = response.InputTokens
		call.OutputTokens = response.OutputTokens
		call.UsageKnown = response.UsageKnown || response.InputTokens != 0 || response.OutputTokens != 0
	}
	if err != nil {
		call.Error = err.Error()
	}
	sequence := telemetry.addModelCall(call)
	return response, sequence, err
}

// logLoopSummary emits a one-line, always-on summary of how a tool loop
// concluded (iteration count, tool calls made, and why it stopped), so
// tool-call engagement can be audited from ordinary run logs without enabling
// -debug. Runs via defer, so it fires exactly once per unit regardless of
// which exit path (success or error) the loop took.
func (agent *DetectionAgent) logLoopSummary(ctx context.Context, phase, unitLabel string,
	iterations, toolCalls int, inTok, outTok int32, reason string) {
	log.FromContext(ctx).Infof(
		"[agentic] tool-loop summary phase=%s unit=%q iterations=%d tool_calls=%d used_tools=%t input_tokens=%d output_tokens=%d reason=%s",
		phase, unitLabel, iterations, toolCalls, toolCalls > 0, inTok, outTok, reason)
}

// detectWithTools runs the detection prompt through a tool-using loop on the
// detection client and returns the final content plus aggregated token counts.
func (agent *DetectionAgent) detectWithTools(ctx context.Context, scanData *model.ScanData,
	options *clients.GenerateOptions, perCallTimeoutSec int) (string, int32, int32, error) {
	unitLabel := fmt.Sprintf("%s rule=%s", scanData.RelativeFilePath, scanData.Rule.ID)
	return agent.runToolLoop(ctx, agent.llmClient, scanData.SystemPrompt, scanData.UserPrompt, options, perCallTimeoutSec,
		"detection", unitLabel, scanData.Rule.ID)
}

func withOptionalTimeout(ctx context.Context, timeoutSec int) (context.Context, context.CancelFunc) {
	if timeoutSec <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
}

func (agent *DetectionAgent) detectWithToolsAccounting(ctx context.Context, scanData *model.ScanData,
	options *clients.GenerateOptions, perCallTimeoutSec int) (string, int32, int32, int32, error) {
	unitLabel := fmt.Sprintf("%s rule=%s", scanData.RelativeFilePath, scanData.Rule.ID)
	telemetry := prepareVerificationTelemetry(&VerificationTelemetry{})
	content, inputTokens, outputTokens, err := agent.runToolLoopWithTelemetry(ctx, agent.llmClient,
		scanData.SystemPrompt, scanData.UserPrompt, options, perCallTimeoutSec,
		"detection", unitLabel, scanData.Rule.ID, telemetry)
	agent.logLoopSummary(ctx, "detection", unitLabel, telemetry.InvestigationIterations,
		telemetry.RequestedToolCalls, inputTokens, outputTokens, string(telemetry.StopReason))
	log.FromContext(ctx).Info("agentic detection accounting",
		log.String("phase", "detection"),
		log.String("unit", unitLabel),
		log.Int("model_calls", len(telemetry.ModelCalls)),
		log.Int("tool_calls", telemetry.RequestedToolCalls),
		log.Int32("input_tokens", inputTokens),
		log.Int32("output_tokens", outputTokens),
		log.String("stop_reason", string(telemetry.StopReason)),
		log.Any("model_call_records", telemetry.ModelCalls),
		log.Any("tool_call_records", telemetry.ToolCalls),
	)
	return content, inputTokens, outputTokens, int32(len(telemetry.ModelCalls)), err
}

// verifyWithTools runs the verification prompt through a tool-using loop on the
// verification client. On an AI Gateway rate limit it performs the same
// one-time fallback-model swap as the single-shot verification path, then
// retries the loop once. unitLabel identifies the finding being verified.
func (agent *DetectionAgent) verifyWithTools(ctx context.Context, systemPrompt, userPrompt, unitLabel, ruleID string,
	options *clients.GenerateOptions) (string, int32, int32, error) {
	telemetry := &VerificationTelemetry{}
	return agent.verifyWithToolsTelemetry(ctx, systemPrompt, userPrompt, unitLabel, ruleID, options, telemetry)
}

// verifyWithToolsTelemetry runs agentic verification and preserves accounting
// across a one-time provider fallback.
func (agent *DetectionAgent) verifyWithToolsTelemetry(ctx context.Context, systemPrompt, userPrompt,
	unitLabel, ruleID string, options *clients.GenerateOptions,
	telemetry *VerificationTelemetry) (string, int32, int32, error) {
	telemetry = prepareVerificationTelemetry(telemetry)
	timeout := agent.agentOption.RequestTimeoutSec

	verificationClient, activeModel := agent.verificationClientSnapshot()
	telemetry.activeModel = activeModel
	content, inTok, outTok, err := agent.runToolLoopWithTelemetry(ctx, verificationClient,
		systemPrompt, userPrompt, options, timeout, "verification", unitLabel, ruleID, telemetry)
	if err == nil || !clients.IsRateLimitError(err) || !agent.agentOption.IsAIGateway ||
		agent.agentOption.DisableProviderFallback {
		return content, inTok, outTok, err
	}
	telemetry.ProviderFallbackReason = "rate_limit"
	telemetry.AttemptStopReasons = append(telemetry.AttemptStopReasons, telemetry.StopReason)
	fallbackClient, fallbackModel, retry, clientErr := agent.verificationProviderFallback(ctx, activeModel)
	if clientErr != nil {
		log.FromContext(ctx).Warnf("Failed to create fallback verification client: %s", clientErr)
		return content, inTok, outTok, err
	}
	if !retry {
		return content, inTok, outTok, err
	}

	log.FromContext(ctx).Warnf("Verification rate limit detected, switching to fallback validation model: %s",
		fallbackModel)
	telemetry.activeModel = fallbackModel
	fallbackContent, fallbackInTok, fallbackOutTok, fallbackErr := agent.runToolLoopWithTelemetry(ctx,
		fallbackClient, systemPrompt, userPrompt, options, timeout,
		"verification", unitLabel, ruleID, telemetry)
	telemetry.AttemptStopReasons = append(telemetry.AttemptStopReasons, telemetry.StopReason)
	return fallbackContent, inTok + fallbackInTok, outTok + fallbackOutTok, fallbackErr
}

// truncateForLog shortens a string for debug logging.
func truncateForLog(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
