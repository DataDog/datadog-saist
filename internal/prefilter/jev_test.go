package prefilter

import (
	"context"
	"encoding/json"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"strings"
	"testing"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestJevBatchesRulesAndUsesOnlyStrippedState(t *testing.T) {
	calls := 0
	j := &Jev{BearerToken: "test-key", Model: DefaultJevModel, Threshold: 0.1,
		Questions: map[string]string{"sql": "SQL operations?", "xss": "HTML output?"}}
	j.Client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		assert.Equal(t, JevEndpoint, r.URL.String())
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))
		assert.Equal(t, "https://ai-gateway.us1.staging.dog/v1/systemone", r.URL.String())
		assert.Equal(t, "k9-saist-jev-prefilter", r.Header.Get("source"))
		assert.Equal(t, "2", r.Header.Get("org-id"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		var request struct {
			State     string
			Questions map[string]any
			Model     string
		}
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		assert.Equal(t, "Language: "+model.Go.String()+"\n\ndb.query(query)", request.State)
		assert.NotContains(t, request.State, "leaky_name.go")
		assert.NotContains(t, request.State, "VULNERABLE")
		assert.Len(t, request.Questions, 2)
		assert.Equal(t, DefaultJevModel, request.Model)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
			`{"model":"jev-1.13.0","answers":{"sql":{"type":"noul","noul":0.1},"xss":{"type":"noul","noul":0}},"usage":{"input_tokens":123,"output_tokens":4}}`))}, nil
	})}
	result, err := j.Select(context.Background(), File{Language: model.Go,
		Code: "// VULNERABLE\ndb.Query(query)", StrippedCode: "db.query(query)", Path: "leaky_name.go"},
		[]api.AiPrompt{{ID: "sql"}, {ID: "xss"}})
	assert.NoError(t, err)
	assert.Equal(t, 1, calls)
	assert.Equal(t, "jev-1.13.0", result.Model)
	assert.Equal(t, int64(123), result.Usage.InputTokens)
	if !assert.Len(t, result.Decisions, 2) {
		return
	}
	assert.True(t, result.Decisions[0].Selected)
	assert.False(t, result.Decisions[1].Selected)
	assert.NotNil(t, result.Decisions[1].Score)
}

func TestJevMissingAndInvalidAnswersFailOpen(t *testing.T) {
	j := &Jev{BearerToken: "test", Threshold: 0.1, Questions: map[string]string{"sql": "SQL?", "xss": "HTML?"}}
	j.Client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(
			`{"answers":{"sql":{"type":"noul","noul":2}}}`))}, nil
	})}
	result, err := j.Select(context.Background(), File{}, []api.AiPrompt{{ID: "sql"}, {ID: "xss"}})
	assert.NoError(t, err)
	if !assert.Len(t, result.Decisions, 2) {
		return
	}
	assert.True(t, result.Decisions[0].Selected)
	assert.True(t, result.Decisions[1].Selected)
	assert.NotEmpty(t, result.Decisions[0].Error)
	assert.NotEmpty(t, result.Decisions[1].Error)
	assert.Nil(t, result.Decisions[0].Score)
}

func TestJevRejectsOversizedStateWithoutRequest(t *testing.T) {
	calls := 0
	j := &Jev{BearerToken: "test", Questions: map[string]string{"sql": "SQL?"}}
	j.Client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return nil, context.Canceled
	})}
	_, err := j.Select(context.Background(), File{StrippedCode: strings.Repeat("x", MaxJevRequestBytes)},
		[]api.AiPrompt{{ID: "sql"}})
	assert.ErrorContains(t, err, "exceeds")
	assert.Equal(t, 0, calls)
}

func TestJevHTTPErrorDoesNotExportResponseBody(t *testing.T) {
	j := &Jev{BearerToken: "test", Questions: map[string]string{"sql": "SQL?"}}
	j.Client = &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader("echoed secret source"))}, nil
	})}
	_, err := j.Select(context.Background(), File{}, []api.AiPrompt{{ID: "sql"}})
	assert.ErrorContains(t, err, "429")
	assert.NotContains(t, err.Error(), "echoed secret")
}
