package clients

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type stagingTransportKey struct{}

type stagingAuthTransport struct {
	mu        sync.Mutex
	token     string
	refreshed time.Time
	getToken  func(context.Context) (string, error)
	base      http.RoundTripper
}

func WithStagingTokenRefresh(ctx context.Context) context.Context {
	return context.WithValue(ctx, stagingTransportKey{}, &stagingAuthTransport{
		base: http.DefaultTransport,
		getToken: func(ctx context.Context) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, "ddtool", "auth", "token", "rapid-ai-platform", "--datacenter", "us1.staging.dog").Output()
			if err != nil || strings.TrimSpace(string(output)) == "" {
				return "", fmt.Errorf("staging gateway token renewal failed; check ddtool login")
			}
			return strings.TrimSpace(string(output)), nil
		},
	})
}

func (t *stagingAuthTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "ai-gateway.us1.staging.dog" {
		return nil, fmt.Errorf("experimental token renewal only allows the staging AI gateway")
	}
	t.mu.Lock()
	if t.token == "" || time.Since(t.refreshed) >= 5*time.Minute {
		token, err := t.getToken(request.Context())
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
		t.token, t.refreshed = token, time.Now()
	}
	token := t.token
	t.mu.Unlock()
	copy := request.Clone(request.Context())
	copy.Header.Set("Authorization", "Bearer "+token)
	response, err := t.base.RoundTrip(copy)
	if response != nil && response.StatusCode == http.StatusUnauthorized {
		t.mu.Lock()
		if t.token == token {
			t.refreshed = time.Time{}
		}
		t.mu.Unlock()
	}
	return response, err
}
