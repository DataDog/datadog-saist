package agents

import (
	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
)

// ModelCallKind identifies the role of one model request in verification.
type ModelCallKind string

// ToolCallDisposition explains whether a requested tool actually executed.
type ToolCallDisposition string

// LoopStopReason identifies the exact condition that ended an agentic loop.
type LoopStopReason string

// ModelCallTelemetry records model accounting without model response content.
type ModelCallTelemetry struct {
	Sequence      int           `json:"sequence"`
	Attempt       int           `json:"attempt"`
	Kind          ModelCallKind `json:"kind"`
	Model         string        `json:"model,omitempty"`
	ReturnedModel string        `json:"returned_model,omitempty"`
	Temperature   *float64      `json:"temperature"`
	TopP          *float64      `json:"top_p"`
	MaxTokens     int           `json:"max_tokens"`
	LatencyMillis int64         `json:"latency_ms"`
	InputTokens   int32         `json:"input_tokens"`
	OutputTokens  int32         `json:"output_tokens"`
	UsageKnown    bool          `json:"usage_known"`
	FinishReason  string        `json:"finish_reason,omitempty"`
	Error         string        `json:"error,omitempty"`
}

func applyModelCallOptions(call *ModelCallTelemetry, model string, options *clients.GenerateOptions) {
	call.Temperature, call.TopP = clients.AppliedSampling(model, options)
	if options != nil {
		call.MaxTokens = options.MaxTokens
	}
}

// ToolCallTelemetry records one model-requested tool call. Raw tool result
// content is deliberately excluded.
type ToolCallTelemetry struct {
	Sequence          int                             `json:"sequence"`
	ModelCallSequence int                             `json:"model_call_sequence"`
	ToolCallID        string                          `json:"tool_call_id"`
	Name              string                          `json:"name"`
	Arguments         string                          `json:"arguments"`
	ResultBytes       int                             `json:"result_bytes"`
	Truncated         bool                            `json:"truncated"`
	Incomplete        bool                            `json:"incomplete"`
	StopReason        string                          `json:"stop_reason,omitempty"`
	FilesScanned      int                             `json:"files_scanned,omitempty"`
	SearchScope       *agenttools.SearchScopeMetadata `json:"search_scope,omitempty"`
	Error             string                          `json:"error,omitempty"`
	Disposition       ToolCallDisposition             `json:"disposition"`
	LatencyMillis     int64                           `json:"latency_ms"`
}

// VerificationTelemetry accumulates one candidate's agentic model and tool
// accounting. Callers may append standard fallback and location calls later.
type VerificationTelemetry struct {
	ModelCalls                 []ModelCallTelemetry `json:"model_calls"`
	ToolCalls                  []ToolCallTelemetry  `json:"tool_calls"`
	StopReason                 LoopStopReason       `json:"stop_reason"`
	AttemptStopReasons         []LoopStopReason     `json:"attempt_stop_reasons,omitempty"`
	SummaryRequested           bool                 `json:"summary_requested"`
	FallbackReason             string               `json:"fallback_reason,omitempty"`
	ProviderFallbackReason     string               `json:"provider_fallback_reason,omitempty"`
	InvestigationIterations    int                  `json:"investigation_iterations"`
	RequestedToolCalls         int                  `json:"requested_tool_calls"`
	ExecutedToolCalls          int                  `json:"executed_tool_calls"`
	InputTokens                int32                `json:"input_tokens"`
	OutputTokens               int32                `json:"output_tokens"`
	TotalRecordedLatencyMillis int64                `json:"total_recorded_latency_ms"`
	activeModel                string
}

func prepareVerificationTelemetry(telemetry *VerificationTelemetry) *VerificationTelemetry {
	if telemetry == nil {
		telemetry = &VerificationTelemetry{}
	}
	if telemetry.ModelCalls == nil {
		telemetry.ModelCalls = make([]ModelCallTelemetry, 0)
	}
	if telemetry.ToolCalls == nil {
		telemetry.ToolCalls = make([]ToolCallTelemetry, 0)
	}
	return telemetry
}

func (telemetry *VerificationTelemetry) nextAttempt() int {
	maxAttempt := 0
	for _, call := range telemetry.ModelCalls {
		if call.Attempt > maxAttempt {
			maxAttempt = call.Attempt
		}
	}
	return maxAttempt + 1
}

func (telemetry *VerificationTelemetry) addModelCall(call ModelCallTelemetry) int {
	call.Sequence = len(telemetry.ModelCalls) + 1
	telemetry.ModelCalls = append(telemetry.ModelCalls, call)
	telemetry.InputTokens += call.InputTokens
	telemetry.OutputTokens += call.OutputTokens
	telemetry.TotalRecordedLatencyMillis += call.LatencyMillis
	return call.Sequence
}

func (telemetry *VerificationTelemetry) addToolCall(call ToolCallTelemetry) {
	call.Sequence = len(telemetry.ToolCalls) + 1
	telemetry.ToolCalls = append(telemetry.ToolCalls, call)
	telemetry.RequestedToolCalls++
	if call.Disposition == ToolCallDispositionExecuted {
		telemetry.ExecutedToolCalls++
	}
	telemetry.TotalRecordedLatencyMillis += call.LatencyMillis
}

func (telemetry *VerificationTelemetry) markLastModelCallError(err error) {
	if telemetry == nil || err == nil || len(telemetry.ModelCalls) == 0 {
		return
	}
	telemetry.ModelCalls[len(telemetry.ModelCalls)-1].Error = err.Error()
}
