package filtering

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

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
		Rule: api.AiPrompt{
			ID:                 "datadog/java-cmdi",
			FileSearchKeywords: []string{"runtime", "exec", "processbuilder", "process", "shell", "bash", "cmd"},
		},
		Code: "ProcessBuilder process = new ProcessBuilder();",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for Java code with process keyword")
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
		Rule: api.AiPrompt{ID: "datadog/go-sqli",
			FileSearchKeywords: []string{"select", "query"}},
		Code: "import \"database/sql\"\ndb.Query(\"SELECT * FROM users\"); db.Exec(\"UPDATE table SET value = 1\")",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true when code contains DB import and SQL keywords")
}

func TestShouldAnalyze_CommandInjectionKeywords(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Python,
		Rule:     api.AiPrompt{ID: "datadog/python-cmdi", FileSearchKeywords: []string{"system"}},
		Code:     "os.system('bash -c \"echo hello\"')",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for code with bash keyword")
}

func TestShouldAnalyze_CommandInjectionNoKeywordMatch(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Python,
		Rule:     api.AiPrompt{ID: "datadog/python-cmdi", FileSearchKeywords: []string{"foobar"}},
		Code:     "os.system('bash -c \"echo hello\"')",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result, "No keyword match")
}

func TestShouldAnalyze_LanguageSpecificOverridesGeneric(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule: api.AiPrompt{
			ID:                 "datadog/go-cmdi",
			FileSearchKeywords: []string{"exec", "command", "shell", "bash", "os/exec"},
		},
		Code: "exec.Command(\"ls\")",
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
	// Test that rules without FileSearchKeywords (and no specialized filter) analyze everything
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

// ============================================================
// C# Tests
// ============================================================

func TestShouldAnalyze_CSharpSqlInjection(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-sqli"},
		Code:     "var cmd = new SqlCommand(\"SELECT * FROM users WHERE id = \" + userId, connection);",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# code with SqlCommand and SQL keywords")
}

func TestShouldAnalyze_CSharpSqlInjection_NoMatch(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-sqli"},
		Code:     "Console.WriteLine(\"Hello World\");",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.False(t, result, "Expected ShouldAnalyze to return false for C# code without SQL keywords")
}

func TestShouldAnalyze_CSharpXss(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-xss"},
		Code:     "Response.Write(\"<div>\" + Request.QueryString[\"name\"] + \"</div>\");",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# XSS pattern")
}

func TestShouldAnalyze_CSharpDeserialization(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-deserialization"},
		Code:     "BinaryFormatter formatter = new BinaryFormatter();\nobject obj = formatter.Deserialize(stream);",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# BinaryFormatter deserialization")
}

func TestShouldAnalyze_CSharpPathTraversal(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-pathtraversal"},
		Code:     "string path = Path.Combine(basePath, Request.QueryString[\"file\"]);\nFile.ReadAllText(path);",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# path traversal pattern")
}

func TestShouldAnalyze_CSharpWeakHash(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-weakhash"},
		Code:     "var md5 = MD5.Create();\nvar hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# weak hash with password")
}

func TestShouldAnalyze_CSharpInsecureCookie(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-insecurecookie"},
		Code:     "Response.Cookies.Append(\"session\", sessionId, new CookieOptions { });",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# cookie operations")
}

func TestShouldAnalyze_CSharpWeakRandomness(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-weakrandomness"},
		Code:     "var random = new Random();\nvar token = random.Next().ToString();",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# weak randomness with token")
}

func TestShouldAnalyze_CSharpLdapInjection(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-ldapi"},
		Code:     "var searcher = new DirectorySearcher(entry);\nsearcher.Filter = \"(cn=\" + userName + \")\";",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# LDAP injection pattern")
}

func TestShouldAnalyze_CSharpXPathInjection(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-xpathi"},
		Code:     "XmlDocument doc = new XmlDocument();\nvar nodes = doc.SelectNodes(\"/users/user[@id='\" + userId + \"']\");",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# XPath injection pattern")
}

func TestShouldAnalyze_CSharpAccessControl(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-accesscontrol"},
		Code:     "[HttpGet]\npublic IActionResult GetUser([FromRoute] int id)\n{\n    return Ok(db.Users.FindById(id));\n}",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# access control pattern")
}

func TestShouldAnalyze_CSharpTrustBoundary(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-trustboundary"},
		Code:     "HttpContext.Session.SetString(\"user\", Request.Form[\"username\"]);",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# trust boundary pattern")
}

func TestShouldAnalyze_CSharpCodeInjection(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-codei"},
		Code:     "var provider = new CSharpCodeProvider();\nvar results = provider.CompileAssemblyFromSource(parameters, Request.Form[\"code\"]);",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# code injection pattern")
}

func TestShouldAnalyze_CSharpBrokenCrypto(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.CSharp,
		Rule:     api.AiPrompt{ID: "datadog/csharp-brokencrypto"},
		Code:     "var des = DESCryptoServiceProvider.Create();\nvar aes = Aes.Create();\naes.Mode = CipherMode.ECB;",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for C# broken crypto pattern")
}
