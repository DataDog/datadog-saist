package filtering

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func FuzzAnalysisFilterParity(f *testing.F) {
	// Snapshot of analysis_filter metadata from dd-source's prompts API.
	data, err := os.ReadFile("testdata/analysis_filters.json")
	if err != nil {
		f.Fatal(err)
	}
	var filters map[string]*api.AnalysisFilter
	if err := json.Unmarshal(data, &filters); err != nil {
		f.Fatal(err)
	}
	if !assert.Len(f, filters, len(ruleFilters)) {
		return
	}
	ids := make([]string, 0, len(filters))
	for id := range filters {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	languages := make([]model.Language, len(ids))
	for i, id := range ids {
		languageName := strings.Split(strings.TrimPrefix(id, "datadog/"), "-")[0]
		for _, language := range model.GetAllLanguages() {
			if strings.EqualFold(language.String(), languageName) {
				languages[i] = language
				break
			}
		}
		if languages[i] == model.LanguageUnknown || ruleFilters[id] == nil || filters[id] == nil {
			f.Fatalf("missing language, legacy filter, or metadata for %s", id)
		}
		if !assert.Equal(f, api.AnalysisFilterVersion, filters[id].Version, id) {
			return
		}
		terms := analysisFilterTerms(&filters[id].Expression)
		combined := strings.Join(terms, " ")
		assert.True(f, ruleFilters[id](&model.DetectionContext{Language: languages[i], Code: combined}),
			"%s must have a positive seed", id)
		f.Add(uint16(i), "")
		f.Add(uint16(i), "unrelated value")
		f.Add(uint16(i), combined)
		excluded := analysisFilterExclusions(&filters[id].Expression)
		f.Add(uint16(i), combined+" "+strings.Join(excluded, " "))
		for _, exclusion := range excluded {
			f.Add(uint16(i), combined+" "+exclusion)
		}
		if strings.HasPrefix(id, "datadog/elixir-") {
			addElixirFilterSeeds(f, uint16(i))
		}
		f.Add(uint16(i), strings.ToUpper(combined))
		f.Add(uint16(i), "// "+combined)
		f.Add(uint16(i), "/* "+combined+" */")
		f.Add(uint16(i), "# "+combined)
		f.Add(uint16(i), `def show(conn, params), do: `+combined)
		f.Add(uint16(i), `def handle_event("search", params, socket), do: `+combined)
		for _, term := range terms {
			f.Add(uint16(i), term)
			f.Add(uint16(i), "prefix_"+term+"_suffix")
		}
	}
	f.Fuzz(func(t *testing.T, index uint16, code string) {
		i := int(index) % len(ids)
		id := ids[i]
		ctx := model.DetectionContext{
			Language: languages[i], Code: code,
			Rule: api.AiPrompt{ID: id, AnalysisFilter: filters[id]},
		}
		want := ruleFilters[id](&ctx)
		matches, supported := matchFilterExpression(getStrippedCode(&ctx), &filters[id].Expression)
		assert.True(t, supported, id)
		assert.Equal(t, want, matches, id)
		assert.Equal(t, want, ShouldAnalyze(&ctx, log.NoopLogger()), id)
	})
}

func analysisFilterTerms(expression *api.FilterExpression) []string {
	terms := append([]string{}, expression.ContainsAny...)
	terms = append(terms, expression.WordsAny...)
	for i := range expression.All {
		terms = append(terms, analysisFilterTerms(&expression.All[i])...)
	}
	for i := range expression.Any {
		terms = append(terms, analysisFilterTerms(&expression.Any[i])...)
	}
	return terms
}

func analysisFilterExclusions(expression *api.FilterExpression) []string {
	var terms []string
	if expression.Not != nil {
		terms = append(terms, analysisFilterTerms(expression.Not)...)
		terms = append(terms, analysisFilterExclusions(expression.Not)...)
	}
	for i := range expression.All {
		terms = append(terms, analysisFilterExclusions(&expression.All[i])...)
	}
	for i := range expression.Any {
		terms = append(terms, analysisFilterExclusions(&expression.Any[i])...)
	}
	return terms
}

func addElixirFilterSeeds(f *testing.F, index uint16) {
	f.Add(index, `:erlang.binary_to_term(data, [:safe])`)
	f.Add(index, `:erlang.binary_to_term(data)`)
	f.Add(index, `:erlang.binary_to_term(a, [:safe]); :erlang.binary_to_term(b)`)
	f.Add(index, `:erlang.binary_to_term(decode(data), [:safe])`)
	f.Add(index, `:erlang.binary_to_term (data, [:safe])`)
	pinned := `Bumblebee.load_model({:hf, "model", revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})`
	f.Add(index, pinned)
	f.Add(index, `Bumblebee.load_model({:hf, "model"})`)
	f.Add(index, pinned+`; Bumblebee.load_featurizer({:hf, "other"})`)
	f.Add(index, pinned+`; Ortex.load(path)`)
	f.Add(index, pinned+`; Req.get(url)`)
	f.Add(index, `Bumblebee.load_model ({:hf, "model", revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}); Ortex; Ortex`)
}
