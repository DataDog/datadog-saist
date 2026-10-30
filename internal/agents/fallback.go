package agents

import (
	"context"
	"errors"
	"sync"

	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
)

type rateLimitFallbackError struct {
	err    error
	client *rateLimitFallbackClient
	next   int
}

func (e *rateLimitFallbackError) Error() string { return e.err.Error() }
func (e *rateLimitFallbackError) Unwrap() error { return e.err }

type rateLimitFallbackClient struct {
	mu        sync.Mutex
	client    clients.LLMClient
	model     string
	models    []string
	next      int
	callType  string
	newClient func(context.Context, string) (clients.LLMClient, error)
}

func newRateLimitFallbackClient(client clients.LLMClient, primaryModel, callType string, opts *AgentOption) clients.LLMClient {
	if !opts.IsAIGateway {
		return client
	}

	fallback := &rateLimitFallbackClient{
		client:   client,
		model:    primaryModel,
		callType: callType,
		newClient: func(ctx context.Context, name string) (clients.LLMClient, error) {
			return clients.NewOpenAIClient(ctx, name, opts.OpenAiBaseUrl, opts.IsAIGateway, opts.AIGuardEnabled, opts.OrgID, false)
		},
	}
	for _, name := range []string{aIGatewayFallbackModel, aIGatewaySecondFallbackModel} {
		if name != primaryModel {
			fallback.models = append(fallback.models, name)
		}
	}
	return fallback
}

func (c *rateLimitFallbackClient) GenerateContent(ctx context.Context, systemPrompt, userPrompt string,
	options *clients.GenerateOptions) (*clients.GenerateResponse, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		client, next := c.client, c.next
		c.mu.Unlock()

		response, err := client.GenerateContent(ctx, systemPrompt, userPrompt, options)
		if !clients.IsRateLimitError(err) {
			return response, err
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = errors.Join(err, ctxErr)
		}

		if c.callType == "detection" {
			// Detect owns the attempt budget and starts a fresh timeout for each attempt.
			return nil, &rateLimitFallbackError{err: err, client: c, next: next}
		}
		if !c.advance(ctx, next) {
			return nil, err
		}
	}
}

func (c *rateLimitFallbackClient) advance(ctx context.Context, next int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return false
	}
	// Another call may already have advanced the shared client.
	if c.next != next {
		return true
	}
	if c.next == len(c.models) {
		return false
	}
	name := c.models[c.next]
	fallback, err := c.newClient(ctx, name)
	if err != nil {
		log.FromContext(ctx).Warnf("Failed to create %s fallback client for %s: %s", c.callType, name, err)
		return false
	}
	log.FromContext(ctx).Warnf("%s model %s rate limited, switching to fallback model: %s", c.callType, c.model, name)
	c.client, c.model = fallback, name
	c.next++
	return true
}
