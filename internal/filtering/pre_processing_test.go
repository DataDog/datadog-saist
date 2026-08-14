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

func TestShouldAnalyze_GoSqliPgx(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "datadog/go-sqli"},
		Code: "import \"github.com/jackc/pgx/v5\"\n" +
			"func f(orgStore Store, ctx context.Context) {\n" +
			"\tqueryString := `\n\tSELECT sa.org_id FROM supportadmin_approvals sa`\n" +
			"\trows, err := orgStore.PostgresClient.Query(ctx, queryString)\n" +
			"\t_ = pgx.CollectRows(rows, pgx.RowToStructByName[Approval])\n" +
			"}",
	}

	result := ShouldAnalyze(&ctx, log.NoopLogger())
	assert.True(t, result, "Expected ShouldAnalyze to return true for pgx driver with non-db handle and raw-string SQL")
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

func TestShouldAnalyze_ElixirCriticalFilterRegressions(t *testing.T) {
	tests := []struct {
		name string
		rule string
		code string
		want bool
	}{
		{
			name: "multiline pattern-matched Phoenix parameters",
			rule: "datadog/elixir-codei",
			code: "def run(\n  conn,\n  %{\"code\" => code}\n), do: Code.eval_string(code)",
			want: true,
		},
		{
			name: "nested struct-matched Phoenix connection",
			rule: "datadog/elixir-codei",
			code: `def run(%Plug.Conn{assigns: %{current_user: user}} = conn, %{"code" => code}), do: Code.eval_string(code)`,
			want: true,
		},
		{
			name: "unrelated map is not a Phoenix parameter source",
			rule: "datadog/elixir-codei",
			code: `def run(payload), do: Code.eval_string(payload || %{"code" => "default"})`,
			want: false,
		},
		{
			name: "LiveView event parameters",
			rule: "datadog/elixir-codei",
			code: `def handle_event("run", %{"code" => code}, socket), do: {:noreply, Code.eval_string(code)}`,
			want: true,
		},
		{
			name: "unrelated three-argument function is not a LiveView source",
			rule: "datadog/elixir-codei",
			code: `def process("run", %{"code" => code}, state), do: Code.eval_string(code)`,
			want: false,
		},
		{
			name: "sensitive data sent to AI provider",
			rule: "datadog/elixir-sensitiveinfodisclosure",
			code: `ReqLLM.generate_text(model: model, prompt: "Summarize #{user.api_key}")`,
			want: true,
		},
		{
			name: "sensitive data sent in HTTP response",
			rule: "datadog/elixir-sensitiveinfodisclosure",
			code: `json(conn, %{token: user.token})`,
			want: true,
		},
		{
			name: "local sensitive variable sent in HTTP response",
			rule: "datadog/elixir-sensitiveinfodisclosure",
			code: `send_resp(conn, 200, password)`,
			want: true,
		},
		{
			name: "local sensitive variable written to log",
			rule: "datadog/elixir-sensitiveinfodisclosure",
			code: `Logger.info("password=#{password}")`,
			want: true,
		},
		{
			name: "Phoenix raw HTML response",
			rule: "datadog/elixir-xss",
			code: `def show(conn, params), do: html(conn, params["body"])`,
			want: true,
		},
		{
			name: "Ecto vector distance helper",
			rule: "datadog/elixir-vectorembeddingweaknesses",
			code: `Repo.all(from d in Document, order_by: l2_distance(d.embedding, ^query_vector))`,
			want: true,
		},
		{
			name: "bang filesystem read",
			rule: "datadog/elixir-pathtraversal",
			code: `def read(conn, params), do: File.read!(params["path"])`,
			want: true,
		},
		{
			name: "filesystem copy",
			rule: "datadog/elixir-pathtraversal",
			code: `def copy(conn, params), do: File.cp(params["source"], @destination)`,
			want: true,
		},
		{
			name: "system prompt returned in response",
			rule: "datadog/elixir-systempromptleakage",
			code: `json(conn, %{debug_prompt: system_prompt})`,
			want: true,
		},
		{
			name: "remote Bumblebee repository",
			rule: "datadog/elixir-supplychain",
			code: `Bumblebee.load_model({:hf, "owner/model"})`,
			want: true,
		},
		{
			name: "single pinned Bumblebee repository",
			rule: "datadog/elixir-supplychain",
			code: `Bumblebee.load_model({:hf, "owner/model", revision: "0123456789abcdef0123456789abcdef01234567"})`,
			want: false,
		},
		{
			name: "integrity marker does not suppress another model path",
			rule: "datadog/elixir-supplychain",
			code: "verified = Crypto.hash(:sha256, bytes)\nBumblebee.load_model({:hf, \"owner/other-model\", revision: revision})",
			want: true,
		},
		{
			name: "safe term conversion does not suppress unsafe conversion",
			rule: "datadog/elixir-deserialization",
			code: ":erlang.binary_to_term(trusted, [:safe])\n:erlang.binary_to_term(untrusted)",
			want: true,
		},
		{
			name: "single safe term conversion",
			rule: "datadog/elixir-deserialization",
			code: `:erlang.binary_to_term(trusted, [:safe])`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := model.DetectionContext{
				Language: model.Elixir,
				Rule:     api.AiPrompt{ID: tt.rule},
				Code:     tt.code,
			}
			assert.Equal(t, tt.want, ShouldAnalyze(&ctx, log.NoopLogger()))
		})
	}
}

func TestShouldAnalyze_ElixirSqlInjection(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Elixir,
		Rule:     api.AiPrompt{ID: "datadog/elixir-sqli"},
		Code:     "Repo.query(\"SELECT * FROM users WHERE id = #{id}\")",
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestShouldAnalyze_ElixirSqlInjectionRequiresSql(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Elixir,
		Rule:     api.AiPrompt{ID: "datadog/elixir-sqli"},
		Code:     "Repo.query(query, [id])",
	}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestShouldAnalyze_ElixirSqlInjectionWithRequestQuery(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Elixir,
		Rule:     api.AiPrompt{ID: "datadog/elixir-sqli"},
		Code:     `def run(conn, params), do: Repo.query(params["query"])`,
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestShouldAnalyze_ElixirPromptInjectionRequiresInput(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Elixir,
		Rule:     api.AiPrompt{ID: "datadog/elixir-promptinjection"},
		Code:     "ReqLLM.generate_text(model: model, prompt: system_prompt)",
	}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
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

func TestShouldAnalyzeSwiftSqli(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Swift,
		Rule:     api.AiPrompt{ID: "datadog/swift-sqli"},
		Code:     "let query = \"SELECT * FROM users WHERE id = \\(id)\"\ntry database.execute(sql: query)",
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestShouldAnalyzeSwiftCmdi(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Swift,
		Rule:     api.AiPrompt{ID: "datadog/swift-cmdi"},
		Code:     "let task = Process()\ntask.launchPath = \"/bin/sh\"\ntask.launch()",
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestShouldAnalyzeSwiftXss(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Swift,
		Rule:     api.AiPrompt{ID: "datadog/swift-xss"},
		Code:     "let name = try req.query.get(String.self, at: \"name\")\nreturn Response(body: .init(string: \"<p>\\(name)</p>\"))",
	}
	assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestShouldNotAnalyzeSwiftCommentOnly(t *testing.T) {
	ctx := model.DetectionContext{
		Language: model.Swift,
		Rule:     api.AiPrompt{ID: "datadog/swift-cmdi"},
		Code:     "// Process().launch()",
	}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
}

func TestShouldAnalyzeSwiftExtendedRules(t *testing.T) {
	assertSwiftRuleMatches := func(ruleID, code string) {
		t.Helper()
		ctx := model.DetectionContext{
			Language: model.Swift,
			Rule:     api.AiPrompt{ID: ruleID},
			Code:     code,
		}
		assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()), ruleID)
	}

	assertSwiftRuleMatches("datadog/swift-pathtraversal", "let path = req.parameters.get(String.self, at: \"file\")\ntry FileManager.default.removeItem(at: URL(fileURLWithPath: path))")
	assertSwiftRuleMatches("datadog/swift-zipslip", "let archive = try Archive(url: fileURL, accessMode: .read)\ntry archive.extract(entry, to: destinationURL)")
	assertSwiftRuleMatches("datadog/swift-ldapi", "let request = LDAPSearchRequest(base: dn, filter: filter)\nconnection.search(request)")
	assertSwiftRuleMatches("datadog/swift-codei", "let source = try req.content.decode(String.self)\ncontext.evaluateScript(source)")
	assertSwiftRuleMatches("datadog/swift-loginjection", "let message = try req.query.get(String.self, at: \"message\")\nlogger.info(\"\\(message)\")")
	assertSwiftRuleMatches("datadog/swift-integeroverflow", "let count = try req.query.get(Int.self, at: \"count\")\nlet small = Int8(count)")
	assertSwiftRuleMatches("datadog/swift-sensitiveinfodisclosure", "let token = config.apiKey\nreturn Response(body: .init(string: token))")
	assertSwiftRuleMatches("datadog/swift-errorinfoleak", "let message = error.localizedDescription\nreturn Response(body: .init(string: message))")
	assertSwiftRuleMatches("datadog/swift-accesscontrol", "let id = try req.parameters.get(String.self, at: \"id\")\nlet user = try User.find(id, on: req.db)")
	assertSwiftRuleMatches("datadog/swift-brokencrypto", "let cipher = kCCAlgorithmDES\nlet mode = CipherMode.ECB")
	assertSwiftRuleMatches("datadog/swift-weakhash", "let digest = Insecure.MD5.hash(data: data)")
	assertSwiftRuleMatches("datadog/swift-weakrandomness", "let token = Int.random(in: 0...1000)")
	assertSwiftRuleMatches("datadog/swift-deserialization", "let value = NSKeyedUnarchiver.unarchiveObject(with: data)")
	assertSwiftRuleMatches("datadog/swift-trustboundary", "let value = try req.content.decode(String.self)\nsession.setValue(value, forKey: \"role\")")
	assertSwiftRuleMatches("datadog/swift-openredirect", "let target = try req.query.get(String.self, at: \"next\")\nreturn redirect(to: target)")
	assertSwiftRuleMatches("datadog/swift-insecurecookie", "response.setCookie(HTTPCookie(properties: properties)!)")
	assertSwiftRuleMatches("datadog/swift-improperoutputhandling", "let answer = try openAI.chatCompletion(prompt)\ntry answer.write(to: fileURL)")
	assertSwiftRuleMatches("datadog/swift-excessiveagency", "let response = try OpenAI.chatCompletion(tools: tools)\ntry execute(response.functionCall)")
	assertSwiftRuleMatches("datadog/swift-systempromptleakage", "let systemPrompt = \"internal instructions\"\nreturn Response(body: .init(string: systemPrompt))")
	assertSwiftRuleMatches("datadog/swift-unboundedconsumption", "for await token in openAI.stream(prompt) { print(token) }")
	assertSwiftRuleMatches("datadog/swift-vectorembeddingweaknesses", "let embedding = try pinecone.query(vector: vector, topK: 10)")
	assertSwiftRuleMatches("datadog/swift-datamodelpoisoning", "let model = try MLModel.loadModel(at: url)\nlet dataset = trainingData")
	assertSwiftRuleMatches("datadog/swift-misinformation", "let answer = try OpenAI.chatCompletion(prompt)\nreturn medicalRecommendation(answer)")
	assertSwiftRuleMatches("datadog/swift-promptinjection", "let userInput = try req.content.decode(String.self)\nlet answer = try OpenAI.chatCompletion(prompt: userInput)")
	assertSwiftRuleMatches("datadog/swift-supplychain", "let model = try MLModel.loadModel(at: url)\nlet data = try await URLSession.shared.data(from: modelURL)")
}
