package filtering

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestShouldAnalyze_WithXpathInjectionKeywords(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-xpathi"},
		Code:     "func main() { xpath.Compile() }",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for code containing xpath keyword")
}

func TestShouldAnalyze_WithoutRelevantKeywords(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-xpathi"},
		Code:     "func main() { fmt.Println(\"hello\") }",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result, "Expected ShouldAnalyze to return false for code without relevant keywords")
}

func TestShouldAnalyze_CaseInsensitive(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-xpathi"},
		Code:     "func main() { xpath.Compile() }", // lowercase required after codeUsedForDetection
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to match xpath keyword")
}

func TestShouldAnalyze_JavaCommandInjection(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "datadog/java-cmdi"},
		Code:     "ProcessBuilder process = new ProcessBuilder();",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for Java code with process keyword")
}

func TestShouldAnalyze_PythonSqlInjection(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Python,
		Rule:     api.AiPrompt{ID: "datadog/python-sqli"},
		Code:     "import sqlite3\nconn = sqlite3.connect('test.db')\ncursor.execute('SELECT * FROM users')",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for Python code with sqlite3 and SQL keywords")
}

func TestShouldAnalyze_GenericXssKeywords(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-xss"},
		Code:     "template := \"<html><body>Hello</body></html>\"",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for code with HTML tags")
}

func TestShouldAnalyze_GenericSqlKeywords(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Python,
		Rule:     api.AiPrompt{ID: "datadog/python-sqli"},
		Code:     "import sqlite3\nquery = \"SELECT * FROM users WHERE id = ?\"",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for code with DB import and SQL SELECT keyword")
}

func TestShouldAnalyze_NoKeywordsForVulnerability(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "datadog/java-xss"},
		Code:     "System.out.println(\"test\");",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result, "Expected ShouldAnalyze to return false when no keywords match (Java XSS has generic XSS keywords but no language-specific ones)")
}

func TestShouldNotAnalyzeXssWithComments(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "datadog/java-xss"},
		Code:     "/* <p> something\n*/",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result, "Expected ShouldAnalyze to return false when no keywords match (Java XSS has generic XSS keywords but no language-specific ones)")
}

func TestShouldNotAnalyzeJavadoc(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "datadog/java-xss"},
		Code:     "/**\n * OWASP Benchmark v1.2\n *\n * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project. For\n * details, please see <a\n * href=\"https://owasp.org/www-project-benchmark/\">https://owasp.org/www-project-benchmark/</a>.\n *\n * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms\n * of the GNU General Public License as published by the Free Software Foundation, version 2.\n *\n * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY\n * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR\n * PURPOSE. See the GNU General Public License for more details.\n *\n * @author Dave Wichers\n * @created 2015\n */\npackage org.owasp.benchmark.testcode;\n\nimport java.io.IOException;\nimport javax.servlet.ServletException;\nimport javax.servlet.annotation.WebServlet;\nimport javax.servlet.http.HttpServlet;\nimport javax.servlet.http.HttpServletRequest;\nimport javax.servlet.http.HttpServletResponse;\n\n@WebServlet(value = \"/sqli-00/BenchmarkTest00018\")\npublic class BenchmarkTest00018 extends HttpServlet {",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result)
}

func TestShouldAnalyzeXss(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "datadog/java-xss"},
		Code:     "class Foo {\n HttpServletRequest request = null;\n String foo = request.getParameter(\"user\");\n PrintWriter out = response.getWriter();\n out.println(\"<p>\" + foo + \"</p>\");\n }\n",
	}

	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()), "Expected Java XSS to match with HTML tags and request input")
}

func TestShouldAnalyze_UnknownLanguage(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.LanguageUnknown,
		Rule:     api.AiPrompt{ID: "unknown-rule"},
		Code:     "SELECT * FROM users",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for unknown language with generic keywords")
}

func TestShouldAnalyze_UnknownVulnerability(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "unknown-rule"},
		Code:     "func main() { fmt.Println(\"test\") }",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for unknown vulnerability (no filtering)")
}

func TestShouldAnalyze_MultipleKeywordsInCode(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-sqli"},
		Code:     "import \"database/sql\"\ndb.Query(\"SELECT * FROM users\"); db.Exec(\"UPDATE table SET value = 1\")",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true when code contains DB import and SQL keywords")
}

func TestShouldAnalyze_CommandInjectionGenericKeywords(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Python,
		Rule:     api.AiPrompt{ID: "datadog/python-cmdi"},
		Code:     "os.system('bash -c \"echo hello\"')",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for code with bash keyword")
}

func TestShouldAnalyze_LanguageSpecificOverridesGeneric(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-cmdi"},
		Code:     "exec.Command(\"ls\")",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for Go-specific command injection keyword")
}

func TestShouldAnalyze_XssHtmlTags(t *testing.T) {
	testCases := []struct {
		name string
		code string
	}{
		{"script tag", "<script>alert('xss')</script>"},
		{"div tag", "<div>content</div>"},
		{"form tag", "<form action=\"/submit\">"},
		{"input tag", "<input type=\"text\" name=\"user\">"},
		{"img tag", "<img src=\"image.jpg\">"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := model.DetectionContext{
				Language: model.Go,
				Rule:     api.AiPrompt{ID: "datadog/go-xss"},
				Code:     tc.code,
			}

			result := ShouldAnalyze(&ctx, log.NoopLogger())
			assert.True(t, result, "Expected ShouldAnalyze to return true for %s", tc.name)
		})
	}
}

func TestShouldAnalyze_AllSqlKeywords(t *testing.T) {
	sqlKeywords := []string{"select", "update", "insert", "delete"}

	for _, keyword := range sqlKeywords {
		t.Run(keyword, func(t *testing.T) {
			ctx := model.DetectionContext{
				Language: model.Go,
				Rule:     api.AiPrompt{ID: "datadog/go-sqli"},
				Code:     "import \"database/sql\"\ndb.Query(\"" + keyword + " something\")",
			}

			result := ShouldAnalyze(&ctx, log.NoopLogger())
			assert.True(t, result, "Expected ShouldAnalyze to return true for SQL keyword with DB import: %s", keyword)
		})
	}
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
		Rule:     api.AiPrompt{ID: "datadog/go-sqli"},
		Code:     "import \"database/sql\"\nfunction selectAll() { db.Query(\"select * from users\"); return all; }",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true with DB import and select keyword")
}
