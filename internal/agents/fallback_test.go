package agents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

type fallbackTestClient func(context.Context) (*clients.GenerateResponse, error)

func (f fallbackTestClient) GenerateContent(ctx context.Context, _, _ string,
	_ *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	return f(ctx)
}

func TestFallbackExhaustionDoesNotRestart(t *testing.T) {
	rateLimited := fallbackTestClient(func(context.Context) (*clients.GenerateResponse, error) {
		return nil, clients.ErrRateLimited
	})
	client := newRateLimitFallbackClient(rateLimited, "primary", "verification",
		&AgentOption{IsAIGateway: true}).(*rateLimitFallbackClient)
	var models []string
	client.newClient = func(_ context.Context, name string) (clients.LLMClient, error) {
		models = append(models, name)
		return rateLimited, nil
	}
	_, err := client.GenerateContent(context.Background(), "", "", nil)
	assert.ErrorIs(t, err, clients.ErrRateLimited)
	_, err = client.GenerateContent(context.Background(), "", "", nil)
	assert.ErrorIs(t, err, clients.ErrRateLimited)
	assert.Equal(t, []string{aIGatewayFallbackModel, aIGatewaySecondFallbackModel}, models)
}

func TestFallbackDoesNotRunOnOtherErrors(t *testing.T) {
	want := errors.New("provider unavailable")
	client := newRateLimitFallbackClient(fallbackTestClient(func(context.Context) (*clients.GenerateResponse, error) {
		return nil, want
	}), "primary", "verification", &AgentOption{IsAIGateway: true}).(*rateLimitFallbackClient)
	client.newClient = func(context.Context, string) (clients.LLMClient, error) {
		t.Fatal("unexpected fallback for a non-rate-limit error")
		return nil, nil
	}
	_, err := client.GenerateContent(context.Background(), "", "", nil)
	assert.ErrorIs(t, err, want)
}

func TestFallbackDisabledOutsideGateway(t *testing.T) {
	want := errors.New("primary failed")
	client := newRateLimitFallbackClient(fallbackTestClient(func(context.Context) (*clients.GenerateResponse, error) {
		return nil, want
	}), "primary", "verification", &AgentOption{})
	_, wrapped := client.(*rateLimitFallbackClient)
	assert.False(t, wrapped)
	_, err := client.GenerateContent(context.Background(), "", "", nil)
	assert.ErrorIs(t, err, want)
}

func TestConcurrentFallbackAdvancesOnce(t *testing.T) {
	const callers = 8
	var entered sync.WaitGroup
	entered.Add(callers)
	client := newRateLimitFallbackClient(fallbackTestClient(func(context.Context) (*clients.GenerateResponse, error) {
		entered.Done()
		entered.Wait()
		return nil, clients.ErrRateLimited
	}), "primary", "verification", &AgentOption{IsAIGateway: true}).(*rateLimitFallbackClient)
	var models []string
	client.newClient = func(_ context.Context, name string) (clients.LLMClient, error) {
		models = append(models, name)
		return fallbackTestClient(func(context.Context) (*clients.GenerateResponse, error) {
			if name == aIGatewayFallbackModel {
				return nil, clients.ErrRateLimited
			}
			return &clients.GenerateResponse{Content: "success"}, nil
		}), nil
	}
	var finished sync.WaitGroup
	finished.Add(callers)
	for range callers {
		go func() {
			defer finished.Done()
			got, err := client.GenerateContent(context.Background(), "", "", nil)
			assert.NoError(t, err)
			assert.Equal(t, "success", got.Content)
		}()
	}
	finished.Wait()
	assert.Equal(t, []string{aIGatewayFallbackModel, aIGatewaySecondFallbackModel}, models)
}

func TestDetectionAndVerificationUseSecondFallback(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-key")
	var mu sync.Mutex
	var models []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Model string `json:"model"`
		}
		if !assert.NoError(t, json.NewDecoder(r.Body).Decode(&request)) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		models = append(models, request.Model)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-should-retry", "false")
		if request.Model != aIGatewaySecondFallbackModel {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{
				"content": `{"violations":[],"confirmed":true,"confidence":"high","reason":"confirmed"}`,
			}}},
		}))
	}))
	defer server.Close()
	agent, err := NewDetectionAgent(context.Background(), &AgentOption{
		DetectionModel: model.OpenAIGPT56Luna, ValidationModel: model.OpenAIGPT56Luna,
		OpenAiBaseUrl: server.URL, IsAIGateway: true, RequestTimeoutSec: 10,
	})
	if !assert.NoError(t, err) {
		return
	}
	_, err = agent.Detect(context.Background(), &model.ScanData{})
	assert.NoError(t, err)
	result, err := agent.VerifyViolation(context.Background(), &model.ScanData{
		FileContent: &model.FileContent{},
		Rule:        &api.AiPrompt{},
	}, model.LLMResultViolation{})
	if assert.NoError(t, err) {
		assert.True(t, result.Confirmed)
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{
		"openai/gpt-5.6-luna", aIGatewayFallbackModel, aIGatewaySecondFallbackModel,
		"openai/gpt-5.6-luna", aIGatewayFallbackModel, aIGatewaySecondFallbackModel,
	}, models)
}

func TestDetectionPreservesRetryBudgetAndTimeouts(t *testing.T) {
	opts := &AgentOption{IsAIGateway: true, RequestTimeoutSec: 10}
	var models []string
	var deadlines []time.Time
	clientForModel := func(name string) clients.LLMClient {
		return fallbackTestClient(func(ctx context.Context) (*clients.GenerateResponse, error) {
			models = append(models, name)
			deadline, ok := ctx.Deadline()
			assert.True(t, ok)
			deadlines = append(deadlines, deadline)
			if name == "primary" {
				return nil, clients.ErrRateLimited
			}
			return &clients.GenerateResponse{Content: "invalid JSON"}, nil
		})
	}
	client := newRateLimitFallbackClient(clientForModel("primary"), "primary", "detection", opts).(*rateLimitFallbackClient)
	client.newClient = func(_ context.Context, name string) (clients.LLMClient, error) {
		return clientForModel(name), nil
	}
	agent := &DetectionAgent{llmClient: client, agentOption: opts}
	_, err := agent.Detect(context.Background(), &model.ScanData{})
	assert.ErrorContains(t, err, "max analysis attempts exceeded")
	assert.Equal(t, []string{"primary", aIGatewayFallbackModel, aIGatewayFallbackModel}, models)
	if assert.Len(t, deadlines, 3) {
		assert.True(t, deadlines[1].After(deadlines[0]))
		assert.True(t, deadlines[2].After(deadlines[1]))
	}
}

func TestDetectionFallsBackWhenRateLimitArrivesAtAttemptDeadline(t *testing.T) {
	opts := &AgentOption{IsAIGateway: true, RequestTimeoutSec: 1}
	primaryCalls, fallbackCalls := 0, 0
	client := newRateLimitFallbackClient(fallbackTestClient(func(ctx context.Context) (*clients.GenerateResponse, error) {
		primaryCalls++
		<-ctx.Done()
		return nil, clients.ErrRateLimited
	}), "primary", "detection", opts).(*rateLimitFallbackClient)
	client.newClient = func(ctx context.Context, name string) (clients.LLMClient, error) {
		assert.NoError(t, ctx.Err())
		assert.Equal(t, aIGatewayFallbackModel, name)
		return fallbackTestClient(func(ctx context.Context) (*clients.GenerateResponse, error) {
			fallbackCalls++
			assert.NoError(t, ctx.Err())
			return &clients.GenerateResponse{Content: `{"violations":[]}`}, nil
		}), nil
	}
	agent := &DetectionAgent{llmClient: client, agentOption: opts}
	_, err := agent.Detect(context.Background(), &model.ScanData{})
	assert.NoError(t, err)
	assert.Equal(t, 1, primaryCalls)
	assert.Equal(t, 1, fallbackCalls)
}

func TestDetectionDoesNotFallBackAfterScanCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts := &AgentOption{IsAIGateway: true, RequestTimeoutSec: 10}
	primaryCalls := 0
	client := newRateLimitFallbackClient(fallbackTestClient(func(context.Context) (*clients.GenerateResponse, error) {
		primaryCalls++
		cancel()
		return nil, clients.ErrRateLimited
	}), "primary", "detection", opts).(*rateLimitFallbackClient)
	client.newClient = func(context.Context, string) (clients.LLMClient, error) {
		t.Fatal("unexpected fallback after scan cancellation")
		return nil, nil
	}
	agent := &DetectionAgent{llmClient: client, agentOption: opts}
	_, err := agent.Detect(ctx, &model.ScanData{})
	assert.ErrorIs(t, err, context.Canceled)
	assert.ErrorIs(t, err, clients.ErrRateLimited)
	assert.Equal(t, 1, primaryCalls)
}
