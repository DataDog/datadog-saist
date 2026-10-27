package filtering

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestShouldAnalyze_CaseInsensitive(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-xpathi", FileSearchKeywords: []string{"XPATH"}},
		Code:     "func main() { xpath.Compile() }", // lowercase required after codeUsedForDetection
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to match xpath keyword")
}

func TestStripCodeForDetectionCppComments(t *testing.T) {
	code := `// system(comment)
auto literal = R"tag(system(raw text) // still a string)tag";
std::system(command.c_str()); /* hidden_system */`

	stripped := StripCodeForDetection(code, model.Cpp)
	assert.NotContains(t, stripped, "system(comment)")
	assert.Contains(t, stripped, "system(raw text) // still a string")
	assert.Contains(t, stripped, "std::system(command.c_str())")
	assert.NotContains(t, stripped, "hidden_system")
}

func TestStripDartComments(t *testing.T) {
	code := `final route = r'/api/*'; // Process.run(request.query)
final template = """/* still a string */""";
/* outer /* nested */ comment */
Process.run('tool', [request.url.queryParameters['arg']!]);`
	stripped := StripCodeForDetection(code, model.Dart)
	assert.Contains(t, stripped, `r'/api/*'`)
	assert.Contains(t, stripped, `"""/* still a string */"""`)
	assert.NotContains(t, stripped, "outer")
	assert.Contains(t, stripped, "process.run")
	assert.Equal(t, strings.ToLower(`final value = "unterminated /* process.run"`), StripCodeForDetection(`final value = "unterminated /* Process.run"`, model.Dart))
}

func TestShouldAnalyze_EmptyCode(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-xpathi"},
		Code:     "",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result, "Expected ShouldAnalyze to return false for empty code")
}

func TestShouldAnalyze_KeywordAsPartOfLargerWord(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-sqli", FileSearchKeywords: []string{"select"}},
		Code:     "selectAll()",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Keyword fallback matches substrings")
}

func TestShouldAnalyze_WithFileSearchKeywordsFromRule(t *testing.T) {
	// Test that FileSearchKeywords from rule definition are used for filtering
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule: api.AiPrompt{
			ID:                 "datadog/custom-rule",
			FileSearchKeywords: []string{"customkeyword", "anotherkeyword"},
		},
		Code: "func main() { customkeyword() }",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true when FileSearchKeywords from rule matches")
}

func TestShouldAnalyze_WithFileSearchKeywordsNotMatching(t *testing.T) {
	// Test that files without matching keywords are filtered out
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule: api.AiPrompt{
			ID:                 "datadog/custom-rule",
			FileSearchKeywords: []string{"customkeyword", "anotherkeyword"},
		},
		Code: "func main() { fmt.Println(\"hello\") }",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result, "Expected ShouldAnalyze to return false when FileSearchKeywords from rule don't match")
}

func TestShouldAnalyze_NoKeywordsAnalyzesEverything(t *testing.T) {
	// Test that rules without FileSearchKeywords analyze everything
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule: api.AiPrompt{
			ID: "datadog/unknown-rule-no-filter",
		},
		Code: "func main() { fmt.Println(\"hello\") }",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true when no keywords are defined (analyze everything)")
}

func TestStripElixirCommentsPreservesInterpolation(t *testing.T) {
	code := "value = \"token ##{id}\" # token in a comment\nRepo.query(\"select * from users\")"
	stripped := StripCodeForDetection(code, model.Elixir)
	assert.Contains(t, stripped, "\"token ##{id}\"")
	assert.NotContains(t, stripped, "token in a comment")
	assert.Contains(t, stripped, "repo.query")
}

func TestStripElixirCommentsPreservesSigilsAndHeredocs(t *testing.T) {
	code := "pattern = ~r/#admin/; Code.eval_string(conn.params[\"code\"])\ntext = \"\"\"\n# content\n\"\"\"\n# Code.eval_string(comment)"
	stripped := StripCodeForDetection(code, model.Elixir)

	assert.Contains(t, stripped, "~r/#admin/")
	assert.Contains(t, stripped, "code.eval_string(conn.params")
	assert.Contains(t, stripped, "# content")
	assert.NotContains(t, stripped, "code.eval_string(comment)")
}

func assertDangerousCallRemainsVisible(t *testing.T, language model.Language, code string) {
	t.Helper()
	stripped := StripCodeForDetection(code, language)
	assert.Contains(t, stripped, "dangerous_call", "language %s", language)
}

func TestStripCStyleCommentsPreservesBlockOpenersInStrings(t *testing.T) {
	assertDangerousCallRemainsVisible(t, model.Go, "marker := `/*`\ndangerous_call()")
	assertDangerousCallRemainsVisible(t, model.Java, "String marker = \"\"\"\n/*\n\"\"\";\ndangerous_call();")
	assertDangerousCallRemainsVisible(t, model.Kotlin, "val marker = \"\"\"/*\"\"\"\ndangerous_call()")
	assertDangerousCallRemainsVisible(t, model.JavaScript, "const marker = `/*`;\ndangerous_call();")
	assertDangerousCallRemainsVisible(t, model.TypeScript, "const marker: string = '/*';\ndangerous_call();")
	assertDangerousCallRemainsVisible(t, model.PHP, "<?php $marker = '/*';\ndangerous_call();")
	assertDangerousCallRemainsVisible(t, model.CSharp, "var marker = \"/*\";\ndangerous_call();")
	assertDangerousCallRemainsVisible(t, model.Rust, "let marker = \"escaped quote: \\\" and /*\";\ndangerous_call();")
}

func TestStripCStyleCommentsPreservesCodeAfterLineCommentOpeners(t *testing.T) {
	assertDangerousCallRemainsVisible(t, model.Go, "// Route wildcard: /api/*\ndangerous_call()")
	assertDangerousCallRemainsVisible(t, model.Rust, "// Route wildcard: /api/*\ndangerous_call();")
	assertDangerousCallRemainsVisible(t, model.PHP, "# Route wildcard: /api/*\ndangerous_call();")
}

func TestStripCStyleCommentsRemovesRealComments(t *testing.T) {
	stripped := StripCodeForDetection("/* hidden_block */\ndangerous_call() // hidden_line", model.Go)
	assert.Contains(t, stripped, "dangerous_call")
	assert.NotContains(t, stripped, "hidden_block")
	assert.NotContains(t, stripped, "hidden_line")

	nested := StripCodeForDetection("/* hidden_outer /* hidden_inner */ hidden_outer */\ndangerous_call();", model.Rust)
	assert.Contains(t, nested, "dangerous_call")
	assert.NotContains(t, nested, "hidden_outer")
	assert.NotContains(t, nested, "hidden_inner")
}

func TestStripCStyleCommentsFailsOpenForUnterminatedBlockComment(t *testing.T) {
	assertDangerousCallRemainsVisible(t, model.Go, "/* ambiguous content\ndangerous_call()")
}

func TestStripPHPCommentsPreservesAttributes(t *testing.T) {
	assertDangerousCallRemainsVisible(t, model.PHP, "#[Route('/*')]\nfunction dangerous_call() {}")
}

func TestStripSwiftCommentsPreservesStringLiteralsAndHandlesNesting(t *testing.T) {
	stripped := stripSwiftComments(`let endpoint = "https://example.com/*not-a-comment*/"
/* outer comment
   /* nested comment */
*/
let task = Process()`)

	assert.Contains(t, stripped, `https://example.com/*not-a-comment*/`)
	assert.Contains(t, stripped, "let task = Process()")
	assert.NotContains(t, stripped, "outer comment")
	assert.NotContains(t, stripped, "nested comment")
}
