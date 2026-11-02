# Rule filtering

[ShouldAnalyze](pre_processing.go) is called by `RuleProcessor.BuildScanDataForResult` before prompt construction and LLM execution. It evaluates the same format for every language; language-specific preprocessing remains in `StripCodeForDetection`.

## Conditional metadata

The prompts API carries an optional `analysis_filter` with `version` and `expression`. Its wire types and tolerant decoder are in [internal/model/api/analysis_filter.go](../model/api/analysis_filter.go). The supported version is defined in [constants.go](../model/api/constants.go).

Exactly one nonempty operator is allowed per expression:

| Operator | Meaning |
|---|---|
| `all` | Every child matches |
| `any` | At least one child matches |
| `not` | Negates one child |
| `contains_any` | Any listed substring occurs |
| `words_any` | Any listed whole token occurs; tokens split on `[^a-z0-9_]+` |
| `regex_any` | Any Go regular expression matches |
| `count_equals` | Sum of non-overlapping occurrences of each listed substring equals `count` |

Evaluation uses lowercased, comment-stripped code. Substring/word/count operands are lowercased too; regex patterns are compiled as supplied and must account for the lowercased input. String-literal handling matters: framework names, SQL, and model endpoints often occur inside strings.

For example, a database indicator AND a SQL token:

```json
{"version":1,"expression":{"all":[
  {"contains_any":["connection","statement","executequery("]},
  {"words_any":["select","update","insert","delete"]}
]}}
```

This illustrates the format, not the complete definition of any shipped rule.

## Fallback and scope

- Empty source code is rejected first.
- A supported, valid conditional expression determines the result directly. `FileSearchKeywords` is not an additional AND inside `ShouldAnalyze`.
- Missing/unsupported versions, invalid expressions, invalid regexes, or invalid children cause fallback for the whole expression. Group evaluation checks every child, even if an earlier child already determines the Boolean result.
- Fallback is a case-insensitive substring OR over `FileSearchKeywords` using stripped code. With no keywords, nonempty source is accepted.
- The decoder tolerates malformed optional filter metadata without rejecting the rest of an otherwise valid rule response. It rejects unknown expression fields. Invalid-filter fallback currently has no dedicated warning log; passing a logger to `ShouldAnalyze` does not make fallback observable.

Hosted execution has an additional keyword gate in dd-source before cache lookup. Local Code Security YAML selection also has an outer keyword match in [internal/codesecurity/match.go](../codesecurity/match.go). Check both stages when adding indicators: a conditional match cannot recover a pair already removed upstream.

## Changing filters

Ordinary per-rule expressions are authored in dd-source's `domains/static-analysis/shared/libs/go/saist/rules.go`, not a language-specific Go dispatch map here. New operators require both wire schemas, decoder/evaluator support, and tests. Keep keyword fallback available for older or invalid metadata.

[analysis_filter_test.go](analysis_filter_test.go) covers operators, fallback, and selected pre-migration decisions; [API tests](../api/datadog_api_test.go) cover decoding. `testdata/analysis_filters.json` is test data, not a runtime rule source. Use focused positive/negative cases and a fixed-corpus decision comparison when changing selection; a passing filter is permission to analyze, not a prediction of a vulnerability.
