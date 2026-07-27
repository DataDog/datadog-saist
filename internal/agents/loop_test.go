package agents

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/stretchr/testify/assert"
)

// fakeToolClient implements both clients.LLMClient and clients.ToolCallingClient
// so it can drive the tool loop deterministically. fn decides each turn's
// response from the call index, incoming messages, and the tools offered.
type fakeToolClient struct {
	fn       func(call int, msgs []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse
	errFn    func(call int) error
	calls    int
	gotTools [][]clients.ToolDefinition
	gotMsgs  [][]clients.Message
}

func TestWithOptionalTimeoutZeroLeavesDeadlineUnset(t *testing.T) {
	ctx, cancel := withOptionalTimeout(context.Background(), 0)
	defer cancel()

	_, hasDeadline := ctx.Deadline()
	assert.False(t, hasDeadline)
}

func TestStructuredVerdictRequestPinsEvidenceToCandidate(t *testing.T) {
	assert.Contains(t, structuredVerdictRequest,
		"The sink citation must remain in the flagged file and within the candidate line window.")
	assert.Contains(t, structuredVerdictRequest,
		"Record deeper downstream operations as flow citations, not as the sink.")
	assert.Contains(t, structuredVerdictRequest,
		"For each read_file citation, copy the line number and complete snippet from the same output row.")
	assert.Contains(t, structuredVerdictRequest,
		"Never pair one row's line number with an adjacent row's snippet.")
}

func (f *fakeToolClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return &clients.GenerateResponse{Content: "single-shot"}, nil
}

func (f *fakeToolClient) GenerateWithTools(_ context.Context, msgs []clients.Message,
	tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	f.gotMsgs = append(f.gotMsgs, msgs)
	f.gotTools = append(f.gotTools, tools)
	var resp *clients.ToolGenerateResponse
	if f.fn != nil {
		resp = f.fn(f.calls, msgs, tools)
	}
	var err error
	if f.errFn != nil {
		err = f.errFn(f.calls)
	}
	f.calls++
	return resp, err
}

// basicOnlyClient implements only clients.LLMClient, so the loop must fall back
// to a single-shot call.
type basicOnlyClient struct{ content string }

func (b *basicOnlyClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return &clients.GenerateResponse{Content: b.content}, nil
}

type returnedModelClient struct{}

func (returnedModelClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return &clients.GenerateResponse{Content: "direct", ReturnedModel: "model-revision-one"}, nil
}

func (returnedModelClient) GenerateWithTools(_ context.Context, _ []clients.Message,
	_ []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	return &clients.ToolGenerateResponse{Content: "tools", ReturnedModel: "model-revision-one"}, nil
}

func TestGenerationTelemetryRecordsReturnedModel(t *testing.T) {
	agent := &DetectionAgent{}
	telemetry := prepareVerificationTelemetry(&VerificationTelemetry{})
	telemetry.activeModel = "openai/gpt-5.2"
	client := returnedModelClient{}

	_, _, directErr := agent.generateContentWithTelemetry(context.Background(), client,
		"system", "user", &clients.GenerateOptions{}, telemetry, 1, ModelCallKindStandardVerification)
	assert.NoError(t, directErr)
	_, _, toolErr := agent.generateWithToolsTelemetry(context.Background(), client,
		nil, nil, &clients.GenerateOptions{}, telemetry, 1, ModelCallKindAgenticVerdict)
	assert.NoError(t, toolErr)

	if assert.Len(t, telemetry.ModelCalls, 2) {
		assert.Equal(t, "model-revision-one", telemetry.ModelCalls[0].ReturnedModel)
		assert.Equal(t, "model-revision-one", telemetry.ModelCalls[1].ReturnedModel)
	}
}

func tempSandbox(t *testing.T) *agenttools.Sandbox {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("hello\nworld\n"), 0o600); err != nil {
		t.Fatalf("write inside.txt: %v", err)
	}
	sb, err := agenttools.NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	return sb
}

func agenticAgent(sb *agenttools.Sandbox) *DetectionAgent {
	return &DetectionAgent{
		agentOption: &AgentOption{
			AgenticDetection:     true,
			AgenticVerification:  true,
			AgenticMaxIterations: 6,
			AgenticMaxToolCalls:  16,
			RequestTimeoutSec:    30,
		},
		sandbox: sb,
	}
}

func TestRunToolLoopExecutesToolThenAnswers(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				// The tools-off verdict call produces the disciplined final answer.
				return &clients.ToolGenerateResponse{Content: `{"violations":[]}`}
			}
			if call == 0 {
				return &clients.ToolGenerateResponse{
					ToolCalls: []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
				}
			}
			return &clients.ToolGenerateResponse{} // ready to answer -> loop breaks to verdict
		},
	}
	agent := agenticAgent(sb)

	content, _, _, err := agent.runToolLoop(context.Background(), fake, "sys", "user", &clients.GenerateOptions{}, 30,
		"detection", "test-unit", "test-rule")
	if err != nil {
		t.Fatalf("runToolLoop: %v", err)
	}
	if content != `{"violations":[]}` {
		t.Fatalf("content = %q, want the verdict answer", content)
	}
	// Two investigation turns (tool call, then ready) plus the verdict call.
	if fake.calls != 3 {
		t.Fatalf("model called %d times, want 3", fake.calls)
	}

	// The verdict (final) call must have received the tool result with the file content.
	last := fake.gotMsgs[len(fake.gotMsgs)-1]
	var sawToolResult bool
	for _, m := range last {
		if m.Role == "tool" && m.ToolCallID == "c1" && strings.Contains(m.Content, "hello") {
			sawToolResult = true
		}
	}
	if !sawToolResult {
		t.Fatalf("verdict call did not include the read_file tool result, msgs=%+v", last)
	}
}

func TestRunToolLoopFallsBackToSingleShot(t *testing.T) {
	sb := tempSandbox(t)
	agent := agenticAgent(sb)
	client := &basicOnlyClient{content: "NO VIOLATION AMIGO"}

	content, _, _, err := agent.runToolLoop(context.Background(), client, "sys", "user", &clients.GenerateOptions{}, 30,
		"detection", "test-unit", "test-rule")
	if err != nil {
		t.Fatalf("runToolLoop: %v", err)
	}
	if content != "NO VIOLATION AMIGO" {
		t.Fatalf("content = %q, want single-shot result", content)
	}
}

func TestRunToolLoopPassesInvestigationSynthesisToVerdict(t *testing.T) {
	sb := tempSandbox(t)
	synthesis := "Observed inside.txt line 1 and confirmed the helper returns a constant."
	fake := &fakeToolClient{
		fn: func(call int, msgs []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			switch call {
			case 0:
				return &clients.ToolGenerateResponse{
					ToolCalls: []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
				}
			case 1:
				return &clients.ToolGenerateResponse{Content: synthesis}
			default:
				if len(tools) != 0 {
					t.Fatalf("verdict call offered %d tools, want 0", len(tools))
				}
				var sawSynthesis bool
				var sawVerdictRequest bool
				for _, message := range msgs {
					if message.Role == "assistant" && message.Content == synthesis {
						sawSynthesis = true
					}
					if message.Role == "user" && message.Content == structuredVerdictRequest {
						sawVerdictRequest = true
					}
				}
				if !sawSynthesis {
					t.Fatal("verdict call did not receive the investigation synthesis")
				}
				if !sawVerdictRequest {
					t.Fatal("verdict call did not receive the structured verdict request")
				}
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
		},
	}
	agent := agenticAgent(sb)

	content, _, _, err := agent.runToolLoop(context.Background(), fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule")

	if err != nil {
		t.Fatalf("runToolLoop() error = %v", err)
	}
	if content != "FINAL" {
		t.Fatalf("content = %q, want FINAL", content)
	}
	if fake.calls != 3 {
		t.Fatalf("model called %d times, want 3", fake.calls)
	}
}

func TestRunToolLoopPromptsForMissingInvestigationSynthesis(t *testing.T) {
	sb := tempSandbox(t)
	synthesis := "Requested evidence summary."
	fake := &fakeToolClient{
		fn: func(call int, msgs []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			switch call {
			case 0:
				return &clients.ToolGenerateResponse{Content: "   ", InputTokens: 1, OutputTokens: 2}
			case 1:
				if len(tools) != 0 {
					t.Fatalf("summary call offered %d tools, want 0", len(tools))
				}
				last := msgs[len(msgs)-1]
				if last.Role != "user" || last.Content != investigationSummaryRequest {
					t.Fatalf("summary request = %+v, want dedicated request", last)
				}
				return &clients.ToolGenerateResponse{Content: synthesis, InputTokens: 1, OutputTokens: 2}
			default:
				var sawSynthesis bool
				for _, message := range msgs {
					if message.Role == "assistant" && message.Content == synthesis {
						sawSynthesis = true
					}
				}
				if !sawSynthesis {
					t.Fatal("verdict call did not receive the requested synthesis")
				}
				return &clients.ToolGenerateResponse{Content: "FINAL", InputTokens: 1, OutputTokens: 2}
			}
		},
	}
	agent := agenticAgent(sb)
	telemetry := &VerificationTelemetry{}

	content, inputTokens, outputTokens, err := agent.runToolLoopWithTelemetry(context.Background(), fake,
		"sys", "user", &clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	if err != nil {
		t.Fatalf("runToolLoop() error = %v", err)
	}
	if content != "FINAL" {
		t.Fatalf("content = %q, want FINAL", content)
	}
	if fake.calls != 3 {
		t.Fatalf("model called %d times, want 3", fake.calls)
	}
	if inputTokens != 3 || outputTokens != 6 {
		t.Fatalf("tokens = (%d, %d), want (3, 6)", inputTokens, outputTokens)
	}
	assert.True(t, telemetry.SummaryRequested)
	assert.Equal(t, LoopStopReasonReadyToAnswer, telemetry.StopReason)
	assert.Equal(t, int32(3), telemetry.InputTokens)
	assert.Equal(t, int32(6), telemetry.OutputTokens)
	if assert.Len(t, telemetry.ModelCalls, 3) {
		assert.Equal(t, ModelCallKindAgenticInvestigation, telemetry.ModelCalls[0].Kind)
		assert.Equal(t, ModelCallKindAgenticSummary, telemetry.ModelCalls[1].Kind)
		assert.Equal(t, ModelCallKindAgenticVerdict, telemetry.ModelCalls[2].Kind)
		assert.True(t, telemetry.ModelCalls[0].UsageKnown)
		assert.True(t, telemetry.ModelCalls[1].UsageKnown)
		assert.True(t, telemetry.ModelCalls[2].UsageKnown)
	}
}

func TestRunToolLoopTelemetryOmitsRawToolOutput(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				return &clients.ToolGenerateResponse{Content: "FINAL", InputTokens: 3, OutputTokens: 4}
			}
			if call == 0 {
				return &clients.ToolGenerateResponse{
					ToolCalls:   []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
					InputTokens: 1, OutputTokens: 2,
				}
			}
			return &clients.ToolGenerateResponse{Content: "Evidence summary", InputTokens: 1, OutputTokens: 1}
		},
	}
	agent := agenticAgent(sb)
	telemetry := &VerificationTelemetry{}

	content, _, _, err := agent.runToolLoopWithTelemetry(context.Background(), fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.NoError(t, err)
	assert.Equal(t, "FINAL", content)
	if assert.Len(t, telemetry.ToolCalls, 1) {
		call := telemetry.ToolCalls[0]
		assert.Equal(t, "c1", call.ToolCallID)
		assert.Equal(t, "read_file", call.Name)
		assert.Equal(t, `{"path":"inside.txt"}`, call.Arguments)
		assert.Equal(t, ToolCallDispositionExecuted, call.Disposition)
		assert.Positive(t, call.ResultBytes)
		assert.False(t, call.Truncated)
		assert.Empty(t, call.Error)
		assert.Equal(t, 1, call.ModelCallSequence)
	}
	encoded, marshalErr := json.Marshal(telemetry)
	assert.NoError(t, marshalErr)
	assert.NotContains(t, string(encoded), "hello")
	assert.NotContains(t, string(encoded), "world")
}

func TestRunToolLoopTelemetryRecordsDuplicateAndBudgetRefusal(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
			if call == 0 {
				return &clients.ToolGenerateResponse{ToolCalls: []clients.ToolCall{
					{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`},
					{ID: "c2", Name: "read_file", Arguments: `{"path":"inside.txt"}`},
					{ID: "c3", Name: "list_directory", Arguments: `{"path":"."}`},
				}}
			}
			return &clients.ToolGenerateResponse{Content: "Evidence summary"}
		},
	}
	agent := agenticAgent(sb)
	agent.agentOption.AgenticMaxToolCalls = 2
	telemetry := &VerificationTelemetry{}

	content, _, _, err := agent.runToolLoopWithTelemetry(context.Background(), fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.NoError(t, err)
	assert.Equal(t, "FINAL", content)
	assert.Equal(t, LoopStopReasonToolCallBudgetExhausted, telemetry.StopReason)
	assert.Equal(t, 3, telemetry.RequestedToolCalls)
	assert.Equal(t, 1, telemetry.ExecutedToolCalls)
	if assert.Len(t, telemetry.ToolCalls, 3) {
		assert.Equal(t, ToolCallDispositionExecuted, telemetry.ToolCalls[0].Disposition)
		assert.Equal(t, ToolCallDispositionDuplicate, telemetry.ToolCalls[1].Disposition)
		assert.Equal(t, ToolCallDispositionBudgetRefused, telemetry.ToolCalls[2].Disposition)
	}
}

func TestRunToolLoopTelemetryRecordsToolErrorsAndTruncation(t *testing.T) {
	sb := tempSandbox(t)
	longContent := strings.Repeat("observed evidence line\n", 500)
	longPath := filepath.Join(sb.Root(), "long.txt")
	assert.NoError(t, os.WriteFile(longPath, []byte(longContent), 0o600))
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
			if call == 0 {
				return &clients.ToolGenerateResponse{ToolCalls: []clients.ToolCall{
					{ID: "missing", Name: "read_file", Arguments: `{"path":"missing.txt"}`},
					{ID: "long", Name: "read_file", Arguments: `{"path":"long.txt"}`},
				}}
			}
			return &clients.ToolGenerateResponse{Content: "Evidence summary"}
		},
	}
	agent := agenticAgent(sb)
	telemetry := &VerificationTelemetry{}

	_, _, _, err := agent.runToolLoopWithTelemetry(context.Background(), fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.NoError(t, err)
	if assert.Len(t, telemetry.ToolCalls, 2) {
		assert.Contains(t, telemetry.ToolCalls[0].Error, "missing.txt")
		assert.False(t, telemetry.ToolCalls[0].Truncated)
		assert.Empty(t, telemetry.ToolCalls[1].Error)
		assert.True(t, telemetry.ToolCalls[1].Truncated)
	}
	encoded, marshalErr := json.Marshal(telemetry)
	assert.NoError(t, marshalErr)
	assert.NotContains(t, string(encoded), "observed evidence line")
}

func TestRunToolLoopTelemetryRecordsSafeSearchCoverage(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
			if call == 0 {
				return &clients.ToolGenerateResponse{ToolCalls: []clients.ToolCall{{
					ID:        "search",
					Name:      "search_code",
					Arguments: `{"query":"missing","path_glob":"*.txt"}`,
				}}}
			}
			return &clients.ToolGenerateResponse{Content: "Evidence summary"}
		},
	}
	agent := agenticAgent(sb)
	telemetry := &VerificationTelemetry{}

	_, _, _, err := agent.runToolLoopWithTelemetry(context.Background(), fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.NoError(t, err)
	if assert.Len(t, telemetry.ToolCalls, 1) {
		call := telemetry.ToolCalls[0]
		assert.False(t, call.Incomplete)
		assert.Empty(t, call.StopReason)
		assert.Equal(t, 1, call.FilesScanned)
		if assert.NotNil(t, call.SearchScope) {
			assert.Equal(t, ".", call.SearchScope.Root)
			assert.Equal(t, "*.txt", call.SearchScope.PathGlob)
			assert.Equal(t, "text", call.SearchScope.Strategy)
			assert.True(t, call.SearchScope.HiddenPathsExcluded)
			assert.True(t, call.SearchScope.TextSymlinksExcluded)
			assert.True(t, call.SearchScope.BinaryFilesExcluded)
		}
	}
	encoded, marshalErr := json.Marshal(telemetry)
	assert.NoError(t, marshalErr)
	assert.NotContains(t, string(encoded), "hello")
	assert.NotContains(t, string(encoded), "world")
}

func TestRunToolLoopTelemetryRecordsCanceledSearch(t *testing.T) {
	sb := tempSandbox(t)
	ctx, cancel := context.WithCancel(context.Background())
	sb.SetSymbolIndex(&cancelingLoopSymbolIndex{cancel: cancel})
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
			if call == 0 {
				return &clients.ToolGenerateResponse{ToolCalls: []clients.ToolCall{{
					ID:        "search",
					Name:      "search_code",
					Arguments: `{"query":"hello","path_glob":"*.txt","search_kind":"definition"}`,
				}}}
			}
			return &clients.ToolGenerateResponse{Content: "Evidence summary"}
		},
	}
	agent := agenticAgent(sb)
	telemetry := &VerificationTelemetry{}

	content, _, _, err := agent.runToolLoopWithTelemetry(ctx, fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, content)
	assert.Equal(t, LoopStopReasonInvestigationCallFailed, telemetry.StopReason)
	assert.Equal(t, 1, fake.calls)
	if assert.Len(t, telemetry.ToolCalls, 1) {
		call := telemetry.ToolCalls[0]
		assert.Equal(t, ToolCallDispositionExecuted, call.Disposition)
		assert.True(t, call.Incomplete)
		assert.Equal(t, agenttools.StopReasonCanceled, call.StopReason)
		assert.Equal(t, context.Canceled.Error(), call.Error)
		assert.Zero(t, call.FilesScanned)
		assert.NotNil(t, call.SearchScope)
	}
}

type cancelingLoopSymbolIndex struct {
	cancel context.CancelFunc
}

func (index *cancelingLoopSymbolIndex) LookupSymbol(_ string, _ agenttools.SymbolSearchKind) []string {
	return nil
}

func (index *cancelingLoopSymbolIndex) LookupSymbolContext(ctx context.Context, _ string,
	_ agenttools.SymbolSearchKind) []string {
	index.cancel()
	<-ctx.Done()
	return nil
}

func TestRunToolLoopPropagatesCancellationWithoutToolCalls(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fake := &fakeToolClient{
		fn: func(_ int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			cancel()
			return &clients.ToolGenerateResponse{Content: "Evidence summary"}
		},
	}
	agent := agenticAgent(tempSandbox(t))
	telemetry := &VerificationTelemetry{}

	content, _, _, err := agent.runToolLoopWithTelemetry(ctx, fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, content)
	assert.Equal(t, LoopStopReasonInvestigationCallFailed, telemetry.StopReason)
	assert.Equal(t, 1, fake.calls)
	assert.Empty(t, telemetry.ToolCalls)
}

type blockingLoopSymbolIndex struct{}

func (index *blockingLoopSymbolIndex) LookupSymbol(_ string, _ agenttools.SymbolSearchKind) []string {
	return nil
}

func (index *blockingLoopSymbolIndex) LookupSymbolContext(ctx context.Context, _ string,
	_ agenttools.SymbolSearchKind) []string {
	<-ctx.Done()
	return nil
}

func TestExecToolUsesPassedRequestTimeout(t *testing.T) {
	sb := tempSandbox(t)
	sb.SetSymbolIndex(&blockingLoopSymbolIndex{})
	agent := agenticAgent(sb)
	testCtx, testCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer testCancel()

	output, disposition := agent.execToolWithDisposition(testCtx, clients.ToolCall{
		ID:        "search",
		Name:      agenttools.ToolSearchCode,
		Arguments: `{"query":"hello","path_glob":"*.txt","search_kind":"definition"}`,
	}, map[string]bool{}, 1)
	metadata := agenttools.InspectResult(output)

	assert.NoError(t, testCtx.Err())
	assert.Equal(t, ToolCallDispositionExecuted, disposition)
	assert.True(t, metadata.Incomplete)
	assert.Equal(t, agenttools.StopReasonTimeout, metadata.StopReason)
	assert.Equal(t, context.DeadlineExceeded.Error(), metadata.Error)
}

func TestRunToolLoopTelemetryRecordsIterationBudgetStop(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				if call == 1 {
					return &clients.ToolGenerateResponse{Content: "Evidence summary"}
				}
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
			return &clients.ToolGenerateResponse{
				ToolCalls: []clients.ToolCall{{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
			}
		},
	}
	agent := agenticAgent(sb)
	agent.agentOption.AgenticMaxIterations = 1
	telemetry := &VerificationTelemetry{}

	content, _, _, err := agent.runToolLoopWithTelemetry(context.Background(), fake, "sys", "user",
		&clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.NoError(t, err)
	assert.Equal(t, "FINAL", content)
	assert.Equal(t, LoopStopReasonIterationBudgetExhausted, telemetry.StopReason)
	assert.True(t, telemetry.SummaryRequested)
	if assert.Len(t, telemetry.ModelCalls, 3) {
		assert.Equal(t, ModelCallKindAgenticInvestigation, telemetry.ModelCalls[0].Kind)
		assert.Equal(t, ModelCallKindAgenticSummary, telemetry.ModelCalls[1].Kind)
		assert.Equal(t, ModelCallKindAgenticVerdict, telemetry.ModelCalls[2].Kind)
	}
}

func TestRunToolLoopTelemetryCapturesFailedModelUsage(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(_ int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			return &clients.ToolGenerateResponse{InputTokens: 7, OutputTokens: 8}
		},
		errFn: func(_ int) error {
			return errors.New("provider unavailable")
		},
	}
	agent := agenticAgent(sb)
	telemetry := &VerificationTelemetry{}

	_, inputTokens, outputTokens, err := agent.runToolLoopWithTelemetry(context.Background(), fake,
		"sys", "user", &clients.GenerateOptions{}, 30, "verification", "test-unit", "test-rule", telemetry)

	assert.EqualError(t, err, "provider unavailable")
	assert.Equal(t, int32(7), inputTokens)
	assert.Equal(t, int32(8), outputTokens)
	assert.Equal(t, LoopStopReasonInvestigationCallFailed, telemetry.StopReason)
	if assert.Len(t, telemetry.ModelCalls, 1) {
		assert.True(t, telemetry.ModelCalls[0].UsageKnown)
		assert.Equal(t, int32(7), telemetry.ModelCalls[0].InputTokens)
		assert.Equal(t, int32(8), telemetry.ModelCalls[0].OutputTokens)
		assert.Equal(t, "provider unavailable", telemetry.ModelCalls[0].Error)
	}
}

func TestRunToolLoopForcesFinalAnswerAtToolCallBudget(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(_ int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			// Keep requesting tools as long as any are offered. Answer only when
			// the loop forces a tools-off final call.
			if len(tools) == 0 {
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
			return &clients.ToolGenerateResponse{
				ToolCalls: []clients.ToolCall{{ID: "c", Name: "read_file", Arguments: `{"path":"inside.txt"}`}},
			}
		},
	}
	agent := agenticAgent(sb)
	agent.agentOption.AgenticMaxToolCalls = 2

	content, _, _, err := agent.runToolLoop(context.Background(), fake, "sys", "user", &clients.GenerateOptions{}, 30,
		"detection", "test-unit", "test-rule")
	if err != nil {
		t.Fatalf("runToolLoop: %v", err)
	}
	if content != "FINAL" {
		t.Fatalf("content = %q, want forced final answer", content)
	}
	// The last model call must have been made with no tools offered.
	lastTools := fake.gotTools[len(fake.gotTools)-1]
	if len(lastTools) != 0 {
		t.Fatalf("final call offered %d tools, want 0", len(lastTools))
	}
}

func TestRunToolLoopDoesNotForceToolsFromRuleID(t *testing.T) {
	sb := tempSandbox(t)
	fake := &fakeToolClient{
		fn: func(_ int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if len(tools) == 0 {
				return &clients.ToolGenerateResponse{Content: "FINAL"}
			}
			return &clients.ToolGenerateResponse{Content: "the flagged file contains sufficient evidence"}
		},
	}
	agent := agenticAgent(sb)

	content, _, _, err := agent.runToolLoop(context.Background(), fake, "sys", "user", &clients.GenerateOptions{}, 30,
		"detection", "test-unit", "datadog/go-sqli")
	if err != nil {
		t.Fatalf("runToolLoop: %v", err)
	}
	if content != "FINAL" {
		t.Fatalf("content = %q, want the verdict answer", content)
	}
	if fake.calls != 2 {
		t.Fatalf("model called %d times, want 2", fake.calls)
	}
}

func TestRunToolLoopEnumerateSitesNudgeOnlyOnDetection(t *testing.T) {
	sb := tempSandbox(t)
	readyToAnswer := func(_ int, _ []clients.Message, tools []clients.ToolDefinition) *clients.ToolGenerateResponse {
		if len(tools) == 0 {
			return &clients.ToolGenerateResponse{Content: `{"violations":[]}`}
		}
		return &clients.ToolGenerateResponse{} // ready to answer immediately, no tool calls
	}

	assertEnumerateSitesNudge(t, sb, readyToAnswer, "detection", true)
	assertEnumerateSitesNudge(t, sb, readyToAnswer, "verification", false)
}

func TestAgenticToolNudgeRequiresNonemptySearchScope(t *testing.T) {
	assert.Contains(t, agenticToolNudge,
		"Every search_code call must include path_glob as a non-empty repository-relative glob")
}

func assertEnumerateSitesNudge(t *testing.T, sb *agenttools.Sandbox,
	readyToAnswer func(int, []clients.Message, []clients.ToolDefinition) *clients.ToolGenerateResponse,
	phase string, wantNudged bool) {
	t.Helper()
	fake := &fakeToolClient{fn: readyToAnswer}
	agent := agenticAgent(sb)

	_, _, _, err := agent.runToolLoop(context.Background(), fake, "sys", "user", &clients.GenerateOptions{}, 30,
		phase, "test-unit", "test-rule")
	if err != nil {
		t.Fatalf("phase=%s runToolLoop failed with %v", phase, err)
	}

	var systemContent string
	for _, message := range fake.gotMsgs[0] {
		if message.Role == "system" {
			systemContent = message.Content
		}
	}
	gotNudged := strings.Contains(systemContent, agenticEnumerateSitesNudge)
	if gotNudged != wantNudged {
		t.Fatalf("phase=%s system prompt contains enumerate-sites nudge %v, want %v",
			phase, gotNudged, wantNudged)
	}
}

func TestExecToolDeduplicates(t *testing.T) {
	sb := tempSandbox(t)
	agent := agenticAgent(sb)
	seen := map[string]bool{}
	call := clients.ToolCall{ID: "c1", Name: "read_file", Arguments: `{"path":"inside.txt"}`}

	first := agent.execTool(context.Background(), call, seen, 0)
	if !strings.Contains(first, "hello") {
		t.Fatalf("first exec did not read the file: %q", first)
	}
	second := agent.execTool(context.Background(), call, seen, 0)
	if second != toolDuplicateNote {
		t.Fatalf("second exec = %q, want duplicate note", second)
	}
}

func TestValidateVerificationModeRejectsMissingSandbox(t *testing.T) {
	agent := agenticAgent(nil)

	err := agent.ValidateVerificationMode()

	if err == nil || !strings.Contains(err.Error(), "repository sandbox") {
		t.Fatalf("ValidateVerificationMode() error = %v, want repository sandbox error", err)
	}
}

func TestValidateVerificationModeRejectsBasicClient(t *testing.T) {
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = &basicOnlyClient{content: "unused"}

	err := agent.ValidateVerificationMode()

	if err == nil || !strings.Contains(err.Error(), "tool-calling client") {
		t.Fatalf("ValidateVerificationMode() error = %v, want tool-calling client error", err)
	}
}

func TestValidateVerificationModeAcceptsToolClient(t *testing.T) {
	agent := agenticAgent(tempSandbox(t))
	agent.verificationLLMClient = &fakeToolClient{
		fn: func(_ int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			return &clients.ToolGenerateResponse{}
		},
	}

	if err := agent.ValidateVerificationMode(); err != nil {
		t.Fatalf("ValidateVerificationMode() error = %v, want nil", err)
	}
}
