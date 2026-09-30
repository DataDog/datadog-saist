package clients

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type stagingTestTransport struct {
	requests []*http.Request
}

func (t *stagingTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests = append(t.requests, req)
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
}

func TestStagingAuthRefreshesWithoutMutatingOriginalRequest(t *testing.T) {
	base := &stagingTestTransport{}
	refreshes := 0
	transport := &stagingAuthTransport{base: base, getToken: func(context.Context) (string, error) {
		refreshes++
		return "fresh-token", nil
	}}
	req, err := http.NewRequest("POST", "https://ai-gateway.us1.staging.dog/v1/chat/completions", nil)
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer old-token")
	response, err := transport.RoundTrip(req)
	assert.NoError(t, err)
	assert.NoError(t, response.Body.Close())
	response, err = transport.RoundTrip(req)
	assert.NoError(t, err)
	assert.NoError(t, response.Body.Close())
	assert.Equal(t, 1, refreshes)
	assert.Len(t, base.requests, 2)
	assert.Equal(t, "Bearer fresh-token", base.requests[0].Header.Get("Authorization"))
	assert.Equal(t, "Bearer old-token", req.Header.Get("Authorization"))
	transport.refreshed = time.Now().Add(-6 * time.Minute)
	response, err = transport.RoundTrip(req)
	assert.NoError(t, err)
	assert.NoError(t, response.Body.Close())
	assert.Equal(t, 2, refreshes)
	assert.Len(t, base.requests, 3)
}

func TestStagingAuthRejectsOtherHostsBeforeFetchingCredentials(t *testing.T) {
	base := &stagingTestTransport{}
	refreshes := 0
	transport := &stagingAuthTransport{base: base, getToken: func(context.Context) (string, error) {
		refreshes++
		return "unused", nil
	}}
	req, err := http.NewRequest("POST", "https://example.com/v1/chat/completions", nil)
	assert.NoError(t, err)
	response, err := transport.RoundTrip(req)
	assert.ErrorContains(t, err, "only allows the staging AI gateway")
	assert.Nil(t, response)
	assert.Equal(t, 0, refreshes)
	assert.Len(t, base.requests, 0)
}
