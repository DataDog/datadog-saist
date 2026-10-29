package filtering

import (
	"encoding/json"
	"os"
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

func TestAnalysisFilterMatchesPreMigrationDecisions(t *testing.T) {
	analyze := func(language model.Language, ruleID, code string) bool {
		t.Helper()
		ctx := model.DetectionContext{Language: language, Code: code,
			Rule: api.AiPrompt{ID: ruleID, AnalysisFilter: analysisFilterForTest(t, ruleID)}}
		return ShouldAnalyze(&ctx, log.NoopLogger())
	}
	pinned := `Bumblebee.load_model({:hf, "model", revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})`
	after := []bool{
		analyze(model.Java, "datadog/java-sqli", `statement.executeQuery("SELECT * FROM users")`),
		analyze(model.Java, "datadog/java-sqli", `statement.selected()`),
		analyze(model.Elixir, "datadog/elixir-xss", `Phoenix.HTML.raw(conn.params["html"])`),
		analyze(model.Elixir, "datadog/elixir-xss", `Phoenix.HTML.raw(value)`),
		analyze(model.Elixir, "datadog/elixir-deserialization", `:erlang.binary_to_term(data)`),
		analyze(model.Elixir, "datadog/elixir-deserialization", `:erlang.binary_to_term(data, [:safe])`),
		analyze(model.Elixir, "datadog/elixir-supplychain", pinned+`; Req.get(url)`),
		analyze(model.Elixir, "datadog/elixir-supplychain", pinned),
	}
	// Recorded with the pre-migration implementation at 4af751d.
	before := []bool{true, false, true, false, true, false, true, false}
	assert.Equal(t, before, after)
}

func TestAnalysisFilterFallsBackToKeywords(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java, Code: `String query = "SELECT * FROM users";`,
		Rule: api.AiPrompt{ID: "datadog/java-sqli", FileSearchKeywords: []string{"missing", "SELECT"}},
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter = &api.AnalysisFilter{Version: api.AnalysisFilterVersion + 1,
		Expression: api.FilterExpression{ContainsAny: []string{"missing"}},
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter.Version = api.AnalysisFilterVersion
	ctx.Rule.AnalysisFilter.Expression = api.FilterExpression{All: []api.FilterExpression{
		{ContainsAny: []string{"missing"}}, {},
	}}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.FileSearchKeywords = []string{"database"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter.Version++
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.AnalysisFilter = nil
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.FileSearchKeywords = []string{"SELECT"}
	ctx.Code = "// SELECT" // Comments do not satisfy keyword filtering.
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Rule.FileSearchKeywords = nil
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
	ctx.Code = ""
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
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

func TestJavaSQLAnalysisFilter(t *testing.T) {
	filter := analysisFilterForTest(t, "datadog/java-sqli")
	assertDecision := func(code string, want bool) {
		t.Helper()
		ctx := model.DetectionContext{Language: model.Java, Code: code,
			Rule: api.AiPrompt{ID: "datadog/java-sqli", AnalysisFilter: filter}}
		assert.Equal(t, want, ShouldAnalyze(&ctx, log.NoopLogger()), code)
	}
	assertDecision(`statement.executeQuery("SELECT * FROM users WHERE name='" + name + "'");`, true)
	assertDecision("// statement SELECT\nclass Example {}", false)
	assertDecision(`String value = "select";`, false)
	assertDecision(`statement.selected()`, false)
	assertDecision(`statement.prepare("count")`, false)
	assertDecision("", false)

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
		Rule: api.AiPrompt{ID: "datadog/java-sqli", FileSearchKeywords: []string{"statement"}, AnalysisFilter: &api.AnalysisFilter{
			Version: 1, Expression: api.FilterExpression{Not: &api.FilterExpression{RegexAny: []string{"["}}},
		}},
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()), "invalid negated conditions must use keyword filtering")
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

func TestElixirRequestInputAnalysisFilter(t *testing.T) {
	filter := analysisFilterForTest(t, "datadog/elixir-xss")
	assertDecision := func(code string, want bool) {
		t.Helper()
		ctx := model.DetectionContext{Language: model.Elixir, Code: "Phoenix.HTML.raw(value)\n" + code,
			Rule: api.AiPrompt{ID: "datadog/elixir-xss", AnalysisFilter: filter}}
		assert.Equal(t, want, ShouldAnalyze(&ctx, log.NoopLogger()), code)
	}
	assertDecision(`def show(conn, %{"id" => id}), do: id`, true)
	assertDecision(`def handle_event("search", params, socket), do: params`, true)
	assertDecision(`def unrelated(socket, state), do: state`, false)
	assertDecision("# def show(conn, params)\nvalue = 1", false)
}

func TestElixirDeserializationAnalysisFilter(t *testing.T) {
	filter := analysisFilterForTest(t, "datadog/elixir-deserialization")
	assertDecision := func(code string, want bool) {
		t.Helper()
		ctx := model.DetectionContext{Language: model.Elixir, Code: code,
			Rule: api.AiPrompt{ID: "datadog/elixir-deserialization", AnalysisFilter: filter}}
		assert.Equal(t, want, ShouldAnalyze(&ctx, log.NoopLogger()), code)
	}
	assertDecision(`:erlang.binary_to_term(data, [:safe])`, false)
	assertDecision(`:erlang.binary_to_term(data)`, true)
	assertDecision(`:erlang.binary_to_term(a, [:safe]); :erlang.binary_to_term(b)`, true)
	assertDecision(`:erlang.binary_to_term(decode(data), [:safe])`, true)
	assertDecision(`:erlang.binary_to_term (data, [:safe])`, true)
}

func TestElixirSupplychainAnalysisFilter(t *testing.T) {
	filter := analysisFilterForTest(t, "datadog/elixir-supplychain")
	assertDecision := func(code string, want bool) {
		t.Helper()
		ctx := model.DetectionContext{Language: model.Elixir, Code: code,
			Rule: api.AiPrompt{ID: "datadog/elixir-supplychain", AnalysisFilter: filter}}
		assert.Equal(t, want, ShouldAnalyze(&ctx, log.NoopLogger()), code)
	}
	pinned := `Bumblebee.load_model({:hf, "model", revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})`
	assertDecision(pinned, false)
	assertDecision(`Bumblebee.load_model({:hf, "model"})`, true)
	assertDecision(pinned+`; Bumblebee.load_featurizer({:hf, "other"})`, true)
	assertDecision(pinned+`; Ortex.load(path)`, true)
	assertDecision(pinned+`; Req.get(url)`, true)
	assertDecision(`Bumblebee.load_model ({:hf, "model", revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); Ortex; Ortex`, false)
}

func analysisFilterForTest(t *testing.T, ruleID string) *api.AnalysisFilter {
	t.Helper()
	data, err := os.ReadFile("testdata/analysis_filters.json")
	if err != nil {
		t.Fatal(err)
	}
	var filters map[string]*api.AnalysisFilter
	if err := json.Unmarshal(data, &filters); err != nil {
		t.Fatal(err)
	}
	filter := filters[ruleID]
	if filter == nil {
		t.Fatalf("missing filter fixture for %s", ruleID)
	}
	if _, supported := matchFilterExpression("", &filter.Expression); !supported || filter.Version != api.AnalysisFilterVersion {
		t.Fatalf("unsupported filter fixture for %s", ruleID)
	}
	return filter
}
