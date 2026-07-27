package agents

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/candidates"
	"github.com/DataDog/datadog-saist/internal/clients"
	internallog "github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

type phaseSpyClient struct {
	content                string
	standardContent        string
	generateCalls          int
	generateWithToolsCalls int
	gotMessages            [][]clients.Message
}

type failingVerificationClient struct{}

type fallbackSpyClient struct {
	agenticContent         string
	standardContent        string
	agenticErr             error
	standardErr            error
	onAgenticCall          func()
	generateCalls          int
	generateWithToolsCalls int
	standardSystemPrompt   string
	standardUserPrompt     string
}

type sequenceDetectionClient struct {
	responses []*clients.GenerateResponse
	next      int
}

type toolFailureFallbackClient struct {
	toolCalls      int
	standardCalls  int
	agenticContent string
}

type incompleteSearchFallbackClient struct {
	offeredToolCalls int
	standardCalls    int
}

type invalidSearchRecoveryClient struct {
	offeredToolCalls int
	standardCalls    int
	agenticContent   string
	standardContent  string
}

type generateContentFunc func(context.Context, string, string,
	*clients.GenerateOptions) (*clients.GenerateResponse, error)

func (generate generateContentFunc) GenerateContent(ctx context.Context, systemPrompt, userPrompt string,
	options *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return generate(ctx, systemPrompt, userPrompt, options)
}

type capturedInfo struct {
	message string
	fields  []internallog.Field
}

type captureLogger struct {
	infos []capturedInfo
}

func (logger *captureLogger) With(_ ...internallog.Field) internallog.DDSourceLogger { return logger }
func (logger *captureLogger) Debug(_ string, _ ...internallog.Field)                 {}
func (logger *captureLogger) Info(message string, fields ...internallog.Field) {
	logger.infos = append(logger.infos, capturedInfo{message: message, fields: fields})
}
func (logger *captureLogger) Warn(_ string, _ ...internallog.Field)  {}
func (logger *captureLogger) Error(_ string, _ ...internallog.Field) {}
func (logger *captureLogger) Panic(_ string, _ ...internallog.Field) {}
func (logger *captureLogger) Fatal(_ string, _ ...internallog.Field) {}
func (logger *captureLogger) Debugf(_ string, _ ...any)              {}
func (logger *captureLogger) Infof(_ string, _ ...any)               {}
func (logger *captureLogger) Warnf(_ string, _ ...any)               {}
func (logger *captureLogger) Errorf(_ string, _ ...any)              {}
func (logger *captureLogger) Panicf(_ string, _ ...any)              {}
func (logger *captureLogger) Fatalf(_ string, _ ...any)              {}

func findCapturedInfo(logger *captureLogger, message string) *capturedInfo {
	for index := range logger.infos {
		if logger.infos[index].message == message {
			return &logger.infos[index]
		}
	}
	return nil
}

func capturedString(fields []internallog.Field, key string) string {
	for _, field := range fields {
		if field.Key == key {
			return field.String
		}
	}
	return ""
}

func capturedInteger(fields []internallog.Field, key string) int64 {
	for _, field := range fields {
		if field.Key == key {
			return field.Integer
		}
	}
	return 0
}

func hasCapturedField(fields []internallog.Field, key string) bool {
	for _, field := range fields {
		if field.Key == key {
			return true
		}
	}
	return false
}

func (client *toolFailureFallbackClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	client.standardCalls++
	return &clients.GenerateResponse{
		Content:      `{"confirmed":false,"confidence":"high","reason":"standard rejected"}`,
		InputTokens:  11,
		OutputTokens: 13,
	}, nil
}

func (client *incompleteSearchFallbackClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	client.standardCalls++
	return &clients.GenerateResponse{
		Content:      `{"confirmed":true,"confidence":"high","reason":"standard confirmed"}`,
		InputTokens:  11,
		OutputTokens: 13,
	}, nil
}

func (client *invalidSearchRecoveryClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	client.standardCalls++
	return &clients.GenerateResponse{
		Content:      client.standardContent,
		InputTokens:  11,
		OutputTokens: 13,
	}, nil
}

func (client *invalidSearchRecoveryClient) GenerateWithTools(_ context.Context, _ []clients.Message,
	tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	if len(tools) == 0 {
		return &clients.ToolGenerateResponse{
			Content: client.agenticContent, InputTokens: 5, OutputTokens: 7,
		}, nil
	}
	client.offeredToolCalls++
	if client.offeredToolCalls == 1 {
		return &clients.ToolGenerateResponse{
			InputTokens: 2, OutputTokens: 3,
			ToolCalls: []clients.ToolCall{{
				ID: "empty-scope", Name: "search_code",
				Arguments: `{"query":"danger","path_glob":""}`,
			}},
		}, nil
	}
	if client.offeredToolCalls == 2 {
		return &clients.ToolGenerateResponse{
			InputTokens: 2, OutputTokens: 3,
			ToolCalls: []clients.ToolCall{{
				ID: "bounded-scope", Name: "search_code",
				Arguments: `{"query":"danger","path_glob":"*.go"}`,
			}},
		}, nil
	}
	return &clients.ToolGenerateResponse{
		Content: "Investigation complete.", InputTokens: 2, OutputTokens: 3,
	}, nil
}

func (client *incompleteSearchFallbackClient) GenerateWithTools(_ context.Context, _ []clients.Message,
	tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	if len(tools) == 0 {
		return &clients.ToolGenerateResponse{Content: validAgenticRejectJSON(), InputTokens: 5, OutputTokens: 7}, nil
	}
	client.offeredToolCalls++
	if client.offeredToolCalls == 1 {
		return &clients.ToolGenerateResponse{
			InputTokens:  2,
			OutputTokens: 3,
			ToolCalls: []clients.ToolCall{{
				ID: "truncated-search", Name: "search_code",
				Arguments: `{"query":"danger","path_glob":"*.go","max_results":1}`,
			}},
		}, nil
	}
	return &clients.ToolGenerateResponse{
		Content: "The incomplete search did not find another operation.", InputTokens: 2, OutputTokens: 3,
	}, nil
}

func (client *toolFailureFallbackClient) GenerateWithTools(_ context.Context, _ []clients.Message,
	tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	client.toolCalls++
	if len(tools) == 0 {
		content := client.agenticContent
		if content == "" {
			content = validAgenticRejectJSON()
		}
		return &clients.ToolGenerateResponse{Content: content, InputTokens: 5, OutputTokens: 7}, nil
	}
	if client.toolCalls == 1 {
		return &clients.ToolGenerateResponse{
			InputTokens:  2,
			OutputTokens: 3,
			ToolCalls: []clients.ToolCall{{
				ID: "missing", Name: "read_file", Arguments: `{"path":"missing.go"}`,
			}},
		}, nil
	}
	return &clients.ToolGenerateResponse{Content: "Investigation complete.", InputTokens: 2, OutputTokens: 3}, nil
}

func (client *sequenceDetectionClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	if client.next >= len(client.responses) {
		return nil, fmt.Errorf("unexpected detection call %d", client.next+1)
	}
	response := client.responses[client.next]
	client.next++
	return response, nil
}

func (c *failingVerificationClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return nil, errors.New("verification unavailable")
}

func (c *failingVerificationClient) GenerateWithTools(_ context.Context, _ []clients.Message,
	_ []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	return nil, errors.New("verification unavailable")
}

func (c *fallbackSpyClient) GenerateContent(_ context.Context, systemPrompt, userPrompt string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	c.generateCalls++
	c.standardSystemPrompt = systemPrompt
	c.standardUserPrompt = userPrompt
	if c.standardErr != nil {
		return nil, c.standardErr
	}
	return &clients.GenerateResponse{
		Content:      c.standardContent,
		InputTokens:  11,
		OutputTokens: 13,
	}, nil
}

func (c *fallbackSpyClient) GenerateWithTools(_ context.Context, _ []clients.Message,
	tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	c.generateWithToolsCalls++
	if c.onAgenticCall != nil {
		c.onAgenticCall()
	}
	if c.agenticErr != nil {
		return nil, c.agenticErr
	}
	if len(tools) > 0 {
		return &clients.ToolGenerateResponse{
			Content:      "Investigation complete.",
			InputTokens:  2,
			OutputTokens: 3,
		}, nil
	}
	return &clients.ToolGenerateResponse{
		Content:      c.agenticContent,
		InputTokens:  5,
		OutputTokens: 7,
	}, nil
}

func (c *phaseSpyClient) GenerateContent(_ context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	c.generateCalls++
	content := c.content
	if c.standardContent != "" {
		content = c.standardContent
	}
	return &clients.GenerateResponse{Content: content, InputTokens: 11, OutputTokens: 7}, nil
}

func (c *phaseSpyClient) GenerateWithTools(_ context.Context, messages []clients.Message,
	tools []clients.ToolDefinition, _ *clients.GenerateOptions) (*clients.ToolGenerateResponse, error) {
	c.gotMessages = append(c.gotMessages, messages)
	c.generateWithToolsCalls++
	if len(tools) > 0 {
		return &clients.ToolGenerateResponse{Content: "Investigation complete."}, nil
	}
	return &clients.ToolGenerateResponse{Content: c.content}, nil
}

func fallbackTestInputs(t *testing.T, client clients.LLMClient) (*DetectionAgent, *model.ScanData,
	model.LLMResultViolation) {
	t.Helper()
	sandbox := tempSandbox(t)
	assert.NoError(t, os.WriteFile(filepath.Join(sandbox.Root(), "file.go"), []byte("danger()"), 0o600))
	agent := &DetectionAgent{
		verificationLLMClient: client,
		agentOption: &AgentOption{
			AgenticVerification:  true,
			AgenticMaxIterations: 6,
			AgenticMaxToolCalls:  16,
			RequestTimeoutSec:    30,
		},
		sandbox: sandbox,
	}
	scanData := &model.ScanData{
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule:             &api.AiPrompt{ID: "test-rule", Content: "test rule"},
	}
	candidate := model.LLMResultViolation{
		StartLine:   1,
		StartColumn: 1,
		EndLine:     1,
		EndColumn:   8,
		Reason:      "candidate",
	}
	return agent, scanData, candidate
}

func validAgenticRejectJSON() string {
	return `{"verdict":"reject","confidence":"high","sink":{"path":"file.go","line":1,"snippet":"danger()","symbol":"danger","description":"The candidate operation."},"source":null,"flow":[],"guards":[],"counterevidence":[{"path":"file.go","line":1,"snippet":"danger()","symbol":"danger","description":"The operation is safe in this fixture."}],"reason":"The candidate is safe."}`
}

func validAgenticAbstainJSON() string {
	return `{"verdict":"abstain","confidence":"low","sink":{"path":"file.go","line":1,"snippet":"danger()","symbol":"danger","description":"The candidate operation."},"source":null,"flow":[],"guards":[],"counterevidence":[],"reason":"More context is required."}`
}

func validAgenticConfirmJSON() string {
	return `{"verdict":"confirm","confidence":"high","sink":{"path":"file.go","line":1,"snippet":"danger()","symbol":"danger","description":"The candidate operation."},"source":null,"flow":[],"guards":[],"counterevidence":[],"reason":"The candidate is exploitable."}`
}

func runDetectionModes(t *testing.T, agenticDetection, agenticVerification bool) (
	*phaseSpyClient, *phaseSpyClient,
) {
	t.Helper()

	detectionClient := &phaseSpyClient{
		content: `{"violations":[{"startLine":1,"startColumn":1,"endLine":1,"endColumn":8,"reason":"candidate"}]}`,
	}
	verificationClient := &phaseSpyClient{
		content: `{"confirmed":false,"confidence":"high","reason":"safe"}`,
	}
	if agenticVerification {
		verificationClient.content = `{"verdict":"reject","confidence":"high","sink":{"path":"file.go","line":1,"snippet":"danger()","symbol":"danger","description":"The candidate operation."},"source":null,"flow":[],"guards":[],"counterevidence":[{"path":"file.go","line":1,"snippet":"danger()","symbol":"danger","description":"The operation is safe in this test fixture."}],"reason":"The candidate is safe."}`
	}
	sandbox := tempSandbox(t)
	assert.NoError(t, os.WriteFile(filepath.Join(sandbox.Root(), "file.go"), []byte("danger()"), 0o600))
	agent := &DetectionAgent{
		llmClient:             detectionClient,
		verificationLLMClient: verificationClient,
		agentOption: &AgentOption{
			AgenticDetection:     agenticDetection,
			AgenticVerification:  agenticVerification,
			AgenticMaxIterations: 6,
			AgenticMaxToolCalls:  16,
			RequestTimeoutSec:    30,
		},
		sandbox: sandbox,
	}
	scanData := &model.ScanData{
		SystemPrompt:     "system prompt",
		UserPrompt:       "user prompt",
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule: &api.AiPrompt{
			ID:      "test-rule",
			Content: "test rule",
		},
	}

	result, err := agent.basicDetection(context.Background(), scanData)
	assert.NoError(t, err)
	assert.Empty(t, result.Violations)

	return detectionClient, verificationClient
}

func TestDiscoverCandidatesPreservesStandardResponse(t *testing.T) {
	client := &phaseSpyClient{
		content: `{"violations":[{"startLine":3,"startColumn":2,"endLine":3,"endColumn":9,"reason":"candidate"}]}`,
	}
	agent := &DetectionAgent{
		llmClient: client,
		agentOption: &AgentOption{
			RequestTimeoutSec: 30,
		},
	}
	scanData := &model.ScanData{
		SystemPrompt:     "system prompt",
		UserPrompt:       "user prompt",
		RelativeFilePath: "file.go",
		Rule:             &api.AiPrompt{ID: "test-rule"},
	}

	candidates, inputTokens, outputTokens, modelCalls, err := agent.discoverCandidates(context.Background(), scanData)

	assert.NoError(t, err)
	assert.Equal(t, int32(11), inputTokens)
	assert.Equal(t, int32(7), outputTokens)
	assert.Equal(t, int32(1), modelCalls)
	if assert.Len(t, candidates, 1) {
		assert.Equal(t, uint(3), candidates[0].StartLine)
		assert.Equal(t, uint(2), candidates[0].StartColumn)
		assert.Equal(t, uint(3), candidates[0].EndLine)
		assert.Equal(t, uint(9), candidates[0].EndColumn)
		assert.Equal(t, "candidate", candidates[0].Reason)
	}
}

func TestBasicDetectionUsesStandardDetectionAndStandardVerification(t *testing.T) {
	detectionClient, verificationClient := runDetectionModes(t, false, false)

	assert.Equal(t, 1, detectionClient.generateCalls)
	assert.Equal(t, 0, detectionClient.generateWithToolsCalls)
	assert.Equal(t, 1, verificationClient.generateCalls)
	assert.Equal(t, 0, verificationClient.generateWithToolsCalls)
}

func TestBasicDetectionUsesAgenticDetectionAndStandardVerification(t *testing.T) {
	detectionClient, verificationClient := runDetectionModes(t, true, false)

	assert.Equal(t, 0, detectionClient.generateCalls)
	assert.Equal(t, 2, detectionClient.generateWithToolsCalls)
	assert.Equal(t, 1, verificationClient.generateCalls)
	assert.Equal(t, 0, verificationClient.generateWithToolsCalls)
}

func TestBasicDetectionRetainsCandidateWhenAgenticVerificationFails(t *testing.T) {
	detectionClient := &phaseSpyClient{
		content: `{"violations":[{"startLine":1,"startColumn":1,"endLine":1,"endColumn":8,"reason":"candidate"}]}`,
	}
	agent := &DetectionAgent{
		llmClient:             detectionClient,
		verificationLLMClient: &failingVerificationClient{},
		agentOption: &AgentOption{
			AgenticVerification:  true,
			AgenticMaxIterations: 6,
			AgenticMaxToolCalls:  16,
			RequestTimeoutSec:    30,
		},
		sandbox: tempSandbox(t),
	}
	scanData := &model.ScanData{
		SystemPrompt:     "system prompt",
		UserPrompt:       "user prompt",
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule:             &api.AiPrompt{ID: "test-rule", Content: "test rule"},
	}

	result, err := agent.basicDetection(context.Background(), scanData)

	assert.NoError(t, err)
	if assert.Len(t, result.Violations, 1) {
		assert.Equal(t, "candidate", result.Violations[0].Message)
	}
}

func TestAgenticVerificationRetainsCandidateWhenContextIsCanceled(t *testing.T) {
	agent := &DetectionAgent{agentOption: &AgentOption{AgenticVerification: true}}
	scanData := &model.ScanData{
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule:             &api.AiPrompt{ID: "test-rule", Content: "test rule"},
	}
	candidate := model.LLMResultViolation{
		StartLine:   1,
		StartColumn: 1,
		EndLine:     1,
		EndColumn:   8,
		Reason:      "candidate",
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verification := agent.verifyCandidates(ctx, scanData, []model.LLMResultViolation{candidate})

	if assert.Len(t, verification.Violations, 1) {
		assert.Equal(t, "candidate", verification.Violations[0].Message)
	}
}

func assertInvalidSearchRecoveryTelemetry(t *testing.T, telemetry *VerificationTelemetry) {
	t.Helper()
	if !assert.NotNil(t, telemetry) {
		return
	}
	assert.Equal(t, 2, telemetry.RequestedToolCalls)
	assert.Equal(t, 1, telemetry.ExecutedToolCalls)
	if assert.Len(t, telemetry.ToolCalls, 2) {
		invalid := telemetry.ToolCalls[0]
		assert.Equal(t, `{"query":"danger","path_glob":""}`, invalid.Arguments)
		assert.Equal(t, ToolCallDispositionInvalidArgs, invalid.Disposition)
		assert.True(t, invalid.Incomplete)
		assert.Equal(t, agenttools.StopReasonPathGlobRequired, invalid.StopReason)
		assert.Contains(t, invalid.Error, "path_glob")
		assert.Equal(t, ToolCallDispositionExecuted, telemetry.ToolCalls[1].Disposition)
		assert.Empty(t, telemetry.ToolCalls[1].Error)
	}
}

func TestVerificationProviderFallbackGetsFreshPerCallContext(t *testing.T) {
	type contextKey struct{}
	parent := context.WithValue(context.Background(), contextKey{}, "parent-value")
	var agent *DetectionAgent
	var primaryContext context.Context
	var primaryDeadline time.Time
	var fallbackContext context.Context
	var fallbackDeadline time.Time
	fallback := generateContentFunc(func(ctx context.Context, _, _ string,
		_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
		fallbackContext = ctx
		fallbackDeadline, _ = ctx.Deadline()
		assert.Equal(t, "parent-value", ctx.Value(contextKey{}))
		select {
		case <-primaryContext.Done():
		default:
			t.Error("primary call context was not canceled before provider fallback")
		}
		return &clients.GenerateResponse{Content: "fallback response", InputTokens: 3, OutputTokens: 4}, nil
	})
	primary := generateContentFunc(func(ctx context.Context, _, _ string,
		_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
		primaryContext = ctx
		primaryDeadline, _ = ctx.Deadline()
		assert.Equal(t, "parent-value", ctx.Value(contextKey{}))
		agent.verificationFallbackMu.Lock()
		agent.verificationFallbackAttempted = true
		agent.verificationLLMClient = fallback
		agent.verificationActiveModel = aIGatewayFallbackModel
		agent.verificationFallbackMu.Unlock()
		return nil, clients.ErrRateLimited
	})
	agent = &DetectionAgent{
		verificationLLMClient: primary,
		agentOption: &AgentOption{
			IsAIGateway:       true,
			RequestTimeoutSec: 30,
		},
	}
	telemetry := &VerificationTelemetry{}
	scanData := &model.ScanData{
		RelativeFilePath: "file.go",
		Rule:             &api.AiPrompt{ID: "test-rule"},
	}

	response, err := agent.verificationGenerateContentWithTelemetry(parent, scanData, 1,
		"system", "user", &clients.GenerateOptions{}, telemetry, ModelCallKindStandardVerification)

	assert.NoError(t, err)
	if assert.NotNil(t, response) {
		assert.Equal(t, "fallback response", response.Content)
	}
	assert.NotNil(t, primaryContext)
	assert.NotNil(t, fallbackContext)
	assert.NotEqual(t, primaryContext, fallbackContext)
	assert.False(t, fallbackDeadline.Before(primaryDeadline))
	assert.Equal(t, "rate_limit", telemetry.ProviderFallbackReason)
	if assert.Len(t, telemetry.ModelCalls, 2) {
		assert.Equal(t, ModelCallKindStandardVerification, telemetry.ModelCalls[0].Kind)
		assert.Equal(t, ModelCallKindProviderFallback, telemetry.ModelCalls[1].Kind)
	}
}

func TestVerificationProviderFallbackDisabledReturnsRateLimit(t *testing.T) {
	calls := 0
	primary := generateContentFunc(func(_ context.Context, _, _ string,
		_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
		calls++
		return nil, clients.ErrRateLimited
	})
	agent := &DetectionAgent{
		verificationLLMClient: primary,
		agentOption: &AgentOption{
			IsAIGateway:             true,
			DisableProviderFallback: true,
			RequestTimeoutSec:       30,
		},
	}
	telemetry := &VerificationTelemetry{}
	scanData := &model.ScanData{
		RelativeFilePath: "file.go",
		Rule:             &api.AiPrompt{ID: "test-rule"},
	}

	response, err := agent.verificationGenerateContentWithTelemetry(context.Background(), scanData, 1,
		"system", "user", &clients.GenerateOptions{}, telemetry, ModelCallKindStandardVerification)

	assert.Nil(t, response)
	assert.ErrorIs(t, err, clients.ErrRateLimited)
	assert.Equal(t, 1, calls)
	assert.False(t, agent.verificationFallbackAttempted)
	assert.Empty(t, telemetry.ProviderFallbackReason)
	if assert.Len(t, telemetry.ModelCalls, 1) {
		assert.Equal(t, ModelCallKindStandardVerification, telemetry.ModelCalls[0].Kind)
	}
}

func TestDetectionProviderFallbackDisabledReturnsRateLimit(t *testing.T) {
	calls := 0
	client := generateContentFunc(func(_ context.Context, _, _ string,
		_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
		calls++
		return nil, clients.ErrRateLimited
	})
	agent := &DetectionAgent{
		llmClient: client,
		agentOption: &AgentOption{
			IsAIGateway:             true,
			DisableProviderFallback: true,
			RequestTimeoutSec:       30,
		},
	}
	scanData := &model.ScanData{
		SystemPrompt:     "system",
		UserPrompt:       "user",
		RelativeFilePath: "file.go",
		Rule:             &api.AiPrompt{ID: "test-rule"},
	}

	result, err := agent.Detect(context.Background(), scanData)

	assert.ErrorIs(t, err, clients.ErrRateLimited)
	assert.NotNil(t, result)
	assert.Equal(t, 1, calls)
}

func TestBasicDetectionIncludesRejectedVerificationUsage(t *testing.T) {
	detectionClient := &phaseSpyClient{
		content: `{"violations":[{"startLine":1,"startColumn":1,"endLine":1,"endColumn":8,"reason":"candidate"}]}`,
	}
	verificationClient := &phaseSpyClient{
		content: `{"confirmed":false,"confidence":"high","reason":"safe"}`,
	}
	agent := &DetectionAgent{
		llmClient:             detectionClient,
		verificationLLMClient: verificationClient,
		agentOption:           &AgentOption{RequestTimeoutSec: 30},
	}
	scanData := &model.ScanData{
		SystemPrompt:     "system prompt",
		UserPrompt:       "user prompt",
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule:             &api.AiPrompt{ID: "test-rule", Content: "test rule"},
	}

	result, err := agent.basicDetection(context.Background(), scanData)

	assert.NoError(t, err)
	assert.Empty(t, result.Violations)
	assert.Equal(t, int32(22), result.InputTokens)
	assert.Equal(t, int32(14), result.OutputTokens)
	assert.Equal(t, int32(2), result.ModelCalls)
}

func TestDetectPreservesFailedAttemptAccountingBeforeRetry(t *testing.T) {
	client := &sequenceDetectionClient{responses: []*clients.GenerateResponse{
		{Content: `{invalid`, InputTokens: 2, OutputTokens: 3},
		{Content: `{"violations":[]}`, InputTokens: 5, OutputTokens: 7},
	}}
	agent := &DetectionAgent{
		llmClient:   client,
		agentOption: &AgentOption{RequestTimeoutSec: 30},
	}
	scanData := &model.ScanData{
		SystemPrompt:     "system prompt",
		UserPrompt:       "user prompt",
		RelativeFilePath: "file.go",
		FileText:         "safe()",
		Rule:             &api.AiPrompt{ID: "test-rule", Content: "test rule"},
	}

	result, err := agent.Detect(context.Background(), scanData)

	assert.NoError(t, err)
	assert.Empty(t, result.Violations)
	assert.Equal(t, int32(7), result.InputTokens)
	assert.Equal(t, int32(10), result.OutputTokens)
	assert.Equal(t, int32(2), result.ModelCalls)
	assert.Equal(t, 2, client.next)
}

func TestBasicDetectionExportsCandidateBeforeVerification(t *testing.T) {
	exportPath := filepath.Join(t.TempDir(), "candidates.jsonl")
	exporter, err := candidates.NewExporter(exportPath)
	assert.NoError(t, err)
	detectionClient := &phaseSpyClient{
		content: `{"violations":[{"startLine":1,"startColumn":1,"endLine":1,"endColumn":8,"reason":"candidate"}]}`,
	}
	verificationClient := &phaseSpyClient{
		content: `{"confirmed":false,"confidence":"high","reason":"safe"}`,
	}
	agent := &DetectionAgent{
		llmClient:             detectionClient,
		verificationLLMClient: verificationClient,
		agentOption: &AgentOption{
			RequestTimeoutSec: 30,
			RepositoryID:      "repository",
			RepositorySHA:     strings.Repeat("a", 40),
			CandidateExporter: exporter,
		},
	}
	scanData := &model.ScanData{
		SystemPrompt:     "system prompt",
		UserPrompt:       "user prompt",
		RelativeFilePath: "file.go",
		FileText:         "danger()",
		Rule: &api.AiPrompt{
			ID:      "test-rule",
			Content: "test rule",
		},
	}

	result, err := agent.basicDetection(context.Background(), scanData)
	assert.NoError(t, err)
	assert.Empty(t, result.Violations)
	assert.NoError(t, agent.Close())
	file, err := os.Open(exportPath)
	assert.NoError(t, err)
	exported, err := candidates.ReadJSONL(file)
	assert.NoError(t, err)
	assert.NoError(t, file.Close())
	if assert.Len(t, exported, 1) {
		assert.Equal(t, "file.go", exported[0].RelativeFilePath)
		assert.Equal(t, "test-rule", exported[0].Rule.ID)
		assert.Equal(t, candidates.DetectionModeStandard, exported[0].DetectionMode)
	}
}
