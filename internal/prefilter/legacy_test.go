package prefilter

import (
	"context"
	"github.com/DataDog/datadog-saist/internal/filtering"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLegacyPreservesConfigKeywordGate(t *testing.T) {
	code := "package main\nfunc f() { db.Query(\"SELECT * FROM users\" + input) }"
	file := File{Language: model.Go, Code: code, StrippedCode: filtering.StripCodeForDetection(code, model.Go)}
	rule := api.AiPrompt{ID: "datadog/go-sqli", FileSearchKeywords: []string{"absent_keyword"}}
	result, err := (Legacy{}).Select(context.Background(), file, []api.AiPrompt{rule})
	assert.NoError(t, err)
	if !assert.Len(t, result.Decisions, 1) {
		return
	}
	assert.True(t, result.Decisions[0].Selected)
	file.RequireKeywords = true
	result, err = (Legacy{}).Select(context.Background(), file, []api.AiPrompt{rule})
	assert.NoError(t, err)
	if !assert.Len(t, result.Decisions, 1) {
		return
	}
	assert.False(t, result.Decisions[0].Selected)
	assert.Equal(t, "config_keywords", result.Decisions[0].Reason)
}

func TestLegacyIgnoresCommentKeywords(t *testing.T) {
	code := "package main\n// dangerous_call\nfunc f() {}"
	result, err := (Legacy{}).Select(context.Background(), File{
		Language: model.Go, Code: code, StrippedCode: filtering.StripCodeForDetection(code, model.Go),
	}, []api.AiPrompt{{ID: "custom", FileSearchKeywords: []string{"dangerous_call"}}, {ID: "unfiltered"}})
	assert.NoError(t, err)
	if !assert.Len(t, result.Decisions, 2) {
		return
	}
	assert.False(t, result.Decisions[0].Selected)
	assert.True(t, result.Decisions[1].Selected)
}
