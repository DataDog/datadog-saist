package filtering

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestAnalysisFilterUsesMetadata(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java,
		Code:     `String query = "SELECT * FROM users";`,
		Rule: api.AiPrompt{ID: "datadog/java-sqli", AnalysisFilter: &api.AnalysisFilter{
			Version: 1, Expression: api.FilterExpression{ContainsAny: []string{"select"}},
		}},
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.ID = "custom/rule"
	ctx.Rule.FileSearchKeywords = []string{"database"}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter.Expression.ContainsAny = []string{"missing"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestAnalysisFilterFallbackPreservesRejections(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java, Code: `String query = "SELECT * FROM users";`,
		Rule: api.AiPrompt{ID: "datadog/java-sqli", FileSearchKeywords: []string{"select"}},
	}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter = &api.AnalysisFilter{Version: api.AnalysisFilterVersion + 1,
		Expression: api.FilterExpression{ContainsAny: []string{"select"}},
	}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter.Version = api.AnalysisFilterVersion
	ctx.Rule.AnalysisFilter.Expression = api.FilterExpression{Any: []api.FilterExpression{
		{ContainsAny: []string{"select"}}, {},
	}}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx.Rule.ID = "custom/rule"
	ctx.Rule.FileSearchKeywords = []string{"database"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter = nil
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.FileSearchKeywords = []string{"select"}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestAnalysisFilterCompatibility(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java, Code: `statement.executeQuery("SELECT * FROM users");`,
		Rule: api.AiPrompt{ID: "datadog/java-sqli"},
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter = &api.AnalysisFilter{Version: 1, Expression: api.FilterExpression{ContainsAny: []string{"missing"}}}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter.Version = 2
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter.Version = 1
	ctx.Rule.AnalysisFilter.Expression = api.FilterExpression{All: []api.FilterExpression{
		{ContainsAny: []string{"missing"}}, {},
	}}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()), "invalid child must invalidate the entire filter")
}

func TestFilterExpressionOperators(t *testing.T) {
	expression := api.FilterExpression{All: []api.FilterExpression{
		{ContainsAny: []string{"STATEMENT"}},
		{Any: []api.FilterExpression{
			{WordsAny: []string{"SELECT"}},
			{WordsAny: []string{"UPDATE"}},
		}},
	}}
	matches, supported := matchFilterExpression("statement select", &expression)
	assert.True(t, supported)
	assert.True(t, matches)
	matches, supported = matchFilterExpression("statement update", &expression)
	assert.True(t, supported)
	assert.True(t, matches)
	matches, supported = matchFilterExpression("statement selected", &expression)
	assert.True(t, supported)
	assert.False(t, matches)
	expression = api.FilterExpression{ContainsAny: []string{"statement"}, WordsAny: []string{"select"}}
	_, supported = matchFilterExpression("statement select", &expression)
	assert.False(t, supported)
}

func TestFilterNegation(t *testing.T) {
	expression := api.FilterExpression{Not: &api.FilterExpression{ContainsAny: []string{"safe_load"}}}
	matches, supported := matchFilterExpression("yaml.load(data)", &expression)
	assert.True(t, supported)
	assert.True(t, matches)
	matches, supported = matchFilterExpression("yaml.safe_load(data)", &expression)
	assert.True(t, supported)
	assert.False(t, matches)

	ctx := model.DetectionContext{
		Language: model.Java, Code: `statement.executeQuery("SELECT * FROM users");`,
		Rule: api.AiPrompt{ID: "datadog/java-sqli", AnalysisFilter: &api.AnalysisFilter{
			Version: 1, Expression: api.FilterExpression{Not: &api.FilterExpression{RegexAny: []string{"["}}},
		}},
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()), "invalid negated conditions must retain legacy behavior")
}

func TestFilterRegexps(t *testing.T) {
	expression := api.FilterExpression{RegexAny: []string{`\S+`}}
	matches, supported := matchFilterExpression("value", &expression)
	assert.True(t, supported)
	assert.True(t, matches)
	matches, supported = matchFilterExpression(" \n", &expression)
	assert.True(t, supported)
	assert.False(t, matches)

	expression.RegexAny = []string{`\S+`, "["}
	_, supported = matchFilterExpression("value", &expression)
	assert.False(t, supported, "a matching pattern must not hide an invalid pattern")
	_, supported = matchFilterExpression("value", &expression)
	assert.False(t, supported, "cached invalid patterns must remain unsupported")
}

func TestFilterOccurrenceCounts(t *testing.T) {
	expression := api.FilterExpression{CountEquals: &api.FilterCount{Substrings: []string{"LOAD(", "decode("}, Count: 2}}
	matches, supported := matchFilterExpression("load(a); decode(b)", &expression)
	assert.True(t, supported)
	assert.True(t, matches)
	matches, supported = matchFilterExpression("load(a); load(b)", &expression)
	assert.True(t, supported)
	assert.True(t, matches)
	matches, supported = matchFilterExpression("load(a)", &expression)
	assert.True(t, supported)
	assert.False(t, matches)

	expression.CountEquals = &api.FilterCount{Substrings: []string{"aa"}, Count: 2}
	matches, supported = matchFilterExpression("aaaa", &expression)
	assert.True(t, supported)
	assert.True(t, matches, "count matches strings.Count's non-overlapping semantics")
	expression.CountEquals.Count = 0
	matches, supported = matchFilterExpression("bbb", &expression)
	assert.True(t, supported)
	assert.True(t, matches)
	expression.CountEquals.Count = -1
	_, supported = matchFilterExpression("bbb", &expression)
	assert.False(t, supported)
	expression.CountEquals = &api.FilterCount{Substrings: []string{""}, Count: 0}
	_, supported = matchFilterExpression("bbb", &expression)
	assert.False(t, supported)
}

func FuzzElixirRequestInputFilterParity(f *testing.F) {
	expression := api.FilterExpression{Any: []api.FilterExpression{
		{ContainsAny: []string{"conn.params", "params[", "body_params", "query_params", "get_req_header("}},
		{RegexAny: []string{reElixirPhoenixActionParameters.String(), reElixirLiveViewEventParameters.String()}},
	}}
	f.Add(`def show(conn, %{"id" => id}), do: id`)
	f.Add(`def handle_event("search", params, socket), do: params`)
	f.Add(`def unrelated(socket, state), do: state`)
	f.Add("# def show(conn, params)\nvalue = 1")
	f.Fuzz(func(t *testing.T, code string) {
		stripped := StripCodeForDetection(code, model.Elixir)
		matches, supported := matchFilterExpression(stripped, &expression)
		assert.True(t, supported)
		assert.Equal(t, hasElixirRequestInput(stripped), matches)
	})
}

func FuzzElixirDeserializationFilterParity(f *testing.F) {
	expression := api.FilterExpression{All: []api.FilterExpression{
		{ContainsAny: []string{":erlang.binary_to_term", "binary_to_term("}},
		{Not: &api.FilterExpression{All: []api.FilterExpression{
			{CountEquals: &api.FilterCount{Substrings: []string{"binary_to_term("}, Count: 1}},
			{RegexAny: []string{reElixirSingleSafeDeserialization.String()}},
		}}},
	}}
	f.Add(`:erlang.binary_to_term(data, [:safe])`)
	f.Add(`:erlang.binary_to_term(data)`)
	f.Add(`:erlang.binary_to_term(a, [:safe]); :erlang.binary_to_term(b)`)
	f.Add(`:erlang.binary_to_term(decode(data), [:safe])`)
	f.Add(`:erlang.binary_to_term (data, [:safe])`)
	f.Fuzz(func(t *testing.T, code string) {
		ctx := model.DetectionContext{Code: code, Language: model.Elixir}
		matches, supported := matchFilterExpression(getStrippedCode(&ctx), &expression)
		assert.True(t, supported)
		assert.Equal(t, shouldAnalyzeElixirDeserializationCtx(&ctx), matches)
	})
}

func FuzzElixirSupplychainFilterParity(f *testing.F) {
	downloads := api.FilterExpression{ContainsAny: []string{
		"req.get(", "req.request(", "finch.request(", "httpoison.get(", ":httpc.request(", "download(",
	}}
	loaders := []string{"bumblebee.load_model(", "bumblebee.load_featurizer(", "axon.deserialize(", "nx.deserialize("}
	ortex := api.FilterExpression{ContainsAny: []string{"ortex"}}
	singleLoader := api.FilterExpression{Any: []api.FilterExpression{
		{All: []api.FilterExpression{
			{CountEquals: &api.FilterCount{Substrings: loaders, Count: 1}}, {Not: &ortex},
		}},
		{All: []api.FilterExpression{
			{CountEquals: &api.FilterCount{Substrings: loaders, Count: 0}}, ortex,
		}},
	}}
	expression := api.FilterExpression{All: []api.FilterExpression{
		{Any: []api.FilterExpression{{ContainsAny: loaders}, ortex}},
		{Any: []api.FilterExpression{downloads, {ContainsAny: []string{"{:hf,"}}}},
		{Not: &api.FilterExpression{All: []api.FilterExpression{
			{Not: &downloads}, singleLoader, {RegexAny: []string{reElixirPinnedHuggingFaceLoad.String()}},
		}}},
	}}
	pinned := `Bumblebee.load_model({:hf, "model", revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})`
	f.Add(pinned)
	f.Add(`Bumblebee.load_model({:hf, "model"})`)
	f.Add(pinned + `; Bumblebee.load_featurizer({:hf, "other"})`)
	f.Add(pinned + `; Ortex.load(path)`)
	f.Add(pinned + `; Req.get(url)`)
	f.Add(`Bumblebee.load_model ({:hf, "model", revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); Ortex; Ortex`)
	f.Fuzz(func(t *testing.T, code string) {
		ctx := model.DetectionContext{Code: code, Language: model.Elixir}
		matches, supported := matchFilterExpression(getStrippedCode(&ctx), &expression)
		assert.True(t, supported)
		assert.Equal(t, shouldAnalyzeElixirSupplychainCtx(&ctx), matches)
	})
}
