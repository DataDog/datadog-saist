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
		Rule:     api.AiPrompt{ID: "datadog/go-xpathi"},
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

func TestShouldAnalyzeDartRepresentativeRules(t *testing.T) {
	assertDartRuleMatches := func(ruleID, code string) {
		t.Helper()
		ctx := model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: ruleID}, Code: code}
		assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()), ruleID)
	}

	assertDartRuleMatches("datadog/dart-sqli", "import 'package:sqflite/sqflite.dart'; db.rawQuery('select $id')")
	assertDartRuleMatches("datadog/dart-cmdi", "Process.run(request.url.queryParameters['cmd']!, const [])")
	assertDartRuleMatches("datadog/dart-xss", "element.setInnerHtml(request.url.queryParameters['html']!)")
	assertDartRuleMatches("datadog/dart-pathtraversal", "File(request.url.queryParameters['path']!).readAsString()")
	assertDartRuleMatches("datadog/dart-zipslip", "ZipDecoder().decodeBytes(data); File(entry.name).writeAsBytesSync(bytes)")
	assertDartRuleMatches("datadog/dart-ldapi", "import 'package:dartdap/client.dart'; ldap.query(request.url.queryParameters['filter']!)")
	assertDartRuleMatches("datadog/dart-codei", "import 'package:dart_eval/dart_eval.dart'; eval(request.readAsString())")
	assertDartRuleMatches("datadog/dart-loginjection", "import 'package:logging/logging.dart'; Logger('app').info(request.headers['x'])")
	assertDartRuleMatches("datadog/dart-integeroverflow", "Int32List.fromList([int.parse(request.url.queryParameters['n']!)])")
	assertDartRuleMatches("datadog/dart-sensitiveinfodisclosure", "Response.json(body: {'token': Platform.environment['TOKEN']})")
	assertDartRuleMatches("datadog/dart-errorinfoleak", "Response.internalServerError(body: stackTrace.toString())")
	assertDartRuleMatches("datadog/dart-accesscontrol", "import 'package:shelf_router/shelf_router.dart'; db.findById(request.url.queryParameters['id'])")
	assertDartRuleMatches("datadog/dart-brokencrypto", "final cipher = ECBBlockCipher(DESEngine())")
	assertDartRuleMatches("datadog/dart-weakhash", "final digest = md5.convert(bytes)")
	assertDartRuleMatches("datadog/dart-weakrandomness", "final resetToken = Random().nextInt(999999)")
	assertDartRuleMatches("datadog/dart-trustboundary", "request.session['role'] = request.url.queryParameters['role']")
	assertDartRuleMatches("datadog/dart-openredirect", "Response.found(request.url.queryParameters['next']!)")
	assertDartRuleMatches("datadog/dart-insecurecookie", "response.cookies.add(Cookie('session', token))")
	assertDartRuleMatches("datadog/dart-xpathi", "import 'package:xml/xpath.dart'; doc.xpath(request.url.queryParameters['q']!)")
	assertDartRuleMatches("datadog/dart-improperoutputhandling", "import 'package:google_generative_ai/google_generative_ai.dart'; final answer = await model.generateContent(prompt); Process.run(answer.text!, [])")
	assertDartRuleMatches("datadog/dart-excessiveagency", "FunctionDeclaration('delete', () => File(path).delete())")
	assertDartRuleMatches("datadog/dart-systempromptleakage", "Response.ok(systemInstruction)")
	assertDartRuleMatches("datadog/dart-unboundedconsumption", "import 'package:google_generative_ai/google_generative_ai.dart'; GenerativeModel(model: 'x').generateContent(prompt)")
	assertDartRuleMatches("datadog/dart-vectorembeddingweaknesses", "pinecone.similaritySearch(request.url.queryParameters['q']!)")
	assertDartRuleMatches("datadog/dart-datamodelpoisoning", "client.files.upload(bytes: uploadedDataset, purpose: FilePurpose.fineTune)")
	assertDartRuleMatches("datadog/dart-misinformation", "import 'package:google_generative_ai/google_generative_ai.dart'; final answer = await model.generateContent(medicalPrompt); return Response.ok(answer.text)")
	assertDartRuleMatches("datadog/dart-promptinjection", "import 'package:google_generative_ai/google_generative_ai.dart'; model.generateContent(Content.text(request.readAsString()))")
	assertDartRuleMatches("datadog/dart-supplychain", "Interpreter.fromBuffer(await http.get(Uri.parse(url)))")
	assertDartRuleMatches("datadog/dart-pathtraversal", "File(context.request.uri.queryParameters['path']!).readAsString()")
	assertDartRuleMatches("datadog/dart-promptinjection", "model.generateContent(Content.text(await context.request.body()))")
	assertDartRuleMatches("datadog/dart-sensitiveinfodisclosure", "final apiToken = Platform.environment['TOKEN']; debugPrint(apiToken)")
	assertDartRuleMatches("datadog/dart-brokencrypto", "final key = Key.fromBase64('c2VjcmV0')")
	assertDartRuleMatches("datadog/dart-weakrandomness", "final secure = Random.secure(); final resetToken = Random().nextInt(1000000)")
	assertDartRuleMatches("datadog/dart-weakrandomness", "final rng = Random(42); final apiKey = rng.nextInt(1 << 32)")
	assertDartRuleMatches("datadog/dart-sqli", "db.rawQuery('select * from users where id = $id')")
	assertDartRuleMatches("datadog/dart-sqli", "connection.execute('select * from users where id = $id')")
	assertDartRuleMatches("datadog/dart-accesscontrol", "repository.findById(request.params['accountId'])")
	assertDartRuleMatches("datadog/dart-systempromptleakage", "debugPrint(systemPrompt)")
	assertDartRuleMatches("datadog/dart-systempromptleakage", "logger.info(systemPrompt)")
	assertDartRuleMatches("datadog/dart-promptinjection", "import 'package:openai_dart/openai_dart.dart'; client.responses.create(CreateResponseRequest(input: await request.body()))")
	assertDartRuleMatches("datadog/dart-unboundedconsumption", "import 'package:dart_openai/dart_openai.dart'; OpenAI.instance.chat.create(messages: messages)")
	assertDartRuleMatches("datadog/dart-excessiveagency", "final tool = Tool.function(name: 'deleteFile', description: 'Delete a file')")
	assertDartRuleMatches("datadog/dart-excessiveagency", "for (final toolCall in response.allToolCalls) { await File(toolCall.function.arguments['path']).delete(); }")

	ctx := model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-cmdi"}, Code: "final process = 'documentation only';"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-supplychain"}, Code: "Interpreter.fromBuffer(bundledModelBytes)"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-trustboundary"}, Code: "final user = request.context['user'];"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-systempromptleakage"}, Code: "final log = systemPrompt.length;"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-sensitiveinfodisclosure"}, Code: "import 'package:langchain/langchain.dart'; final token = loadToken();"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-improperoutputhandling"}, Code: "import 'package:langchain/langchain.dart'; Process.run(command, const []);"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-datamodelpoisoning"}, Code: "final dataset = await request.readAsString(); render(dataset);"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-codei"}, Code: "import 'package:dart_eval/dart_eval.dart'; render(await request.readAsString());"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))

	ctx = model.DetectionContext{Language: model.Dart, Rule: api.AiPrompt{ID: "datadog/dart-zipslip"}, Code: "await extractArchiveToDisk(archive, root);"}
	assert.False(t, ShouldAnalyze(&ctx, log.NoopLogger()))
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

func TestShouldAnalyzeSwiftAdditionalAPIs(t *testing.T) {
	tests := []struct {
		ruleID string
		code   string
	}{
		{
			ruleID: "datadog/swift-cmdi",
			code:   "try Process.run(URL(fileURLWithPath: command), arguments: [userInput])",
		},
		{
			ruleID: "datadog/swift-pathtraversal",
			code:   "let path = try req.query.get(String.self, at: \"path\")\nlet handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))",
		},
		{
			ruleID: "datadog/swift-codei",
			code:   "let library = try req.content.decode(String.self)\n_ = dlopen(library, RTLD_NOW)",
		},
		{
			ruleID: "datadog/swift-brokencrypto",
			code:   "let algorithm = kCCAlgorithmRC2",
		},
		{
			ruleID: "datadog/swift-weakhash",
			code:   "let algorithm = kCCAlgorithmSHA1",
		},
		{
			ruleID: "datadog/swift-deserialization",
			code:   "let unarchiver = try NSKeyedUnarchiver(forReadingFrom: data)\nlet object = unarchiver.decodeObject(forKey: \"value\")",
		},
		{
			ruleID: "datadog/swift-insecurecookie",
			code:   "response.cookies[\"session\"] = Cookie(value: token, isSecure: false)",
		},
		{
			ruleID: "datadog/swift-supplychain",
			code:   "let package = .package(url: \"https://example.com/package.git\", exact: \"1.0.0\")",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			ctx := model.DetectionContext{
				Language: model.Swift,
				Rule:     api.AiPrompt{ID: tt.ruleID},
				Code:     tt.code,
			}
			assert.True(t, ShouldAnalyze(&ctx, log.NoopLogger()))
		})
	}
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
	assertSwiftRuleMatches("datadog/swift-datamodelpoisoning", "try pinecone.upsert(vectors: embeddings)")
	assertSwiftRuleMatches("datadog/swift-misinformation", "let answer = try OpenAI.chatCompletion(prompt)\nreturn medicalRecommendation(answer)")
	assertSwiftRuleMatches("datadog/swift-promptinjection", "let userInput = try req.content.decode(String.self)\nlet answer = try OpenAI.chatCompletion(prompt: userInput)")
	assertSwiftRuleMatches("datadog/swift-supplychain", "let package = .package(url: \"https://example.com/package.git\", from: \"1.0.0\")")
}

// TestShouldAnalyzeKotlinOWASPAIRules exercises the ten Kotlin OWASP AI Top 10
// combined filters added in K9CODESEC-7609. Each case is a canonical positive
// pattern taken from the matching playground fixture; the companion negative
// case asserts the combined filter rejects nearby ambiguous code.
func TestShouldAnalyzeKotlinOWASPAIRules(t *testing.T) {
	assertKotlinMatches := func(ruleID, code string, want bool) {
		t.Helper()
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: ruleID},
			Code:     code,
		}
		assert.Equal(t, want, ShouldAnalyze(&ctx, log.NoopLogger()), ruleID)
	}

	// sensitiveinfodisclosure: AI context + sensitive data
	assertKotlinMatches("datadog/kotlin-sensitiveinfodisclosure",
		"val pwd = System.getenv(\"DB_PASSWORD\")\nchatClient.prompt().user(pwd).call()", true)
	assertKotlinMatches("datadog/kotlin-sensitiveinfodisclosure",
		"val name = request.getParameter(\"name\")\nreturn ResponseEntity.ok(name)", false)

	assertKotlinMatches("datadog/kotlin-sensitiveinfodisclosure",
		"val pwd = System.getenv(\"DB_PASSWORD\")\nlogger.info(\"loaded $pwd\")", false)
	assertKotlinMatches("datadog/kotlin-promptinjection",
		"fun summarize(chatModel: ChatModel, userTopic: String) = chatModel.generate(userTopic)", true)
	assertKotlinMatches("datadog/kotlin-promptinjection",
		"val userTopic = call.receiveText(); println(userTopic)", false)
	assertKotlinMatches("datadog/kotlin-improperoutputhandling",
		"val output = openAI.chatCompletion(request).choices.first().message.content; println(output)", true)
	assertKotlinMatches("datadog/kotlin-improperoutputhandling",
		"val output = openAI.chatCompletion(request).choices.first().message.content", false)
	assertKotlinMatches("datadog/kotlin-unboundedconsumption",
		"class OllamaClient { suspend fun generate(prompt: String) = http.post(\"http://ollama.internal:11434/api/generate\") { setBody(prompt) } }", true)
	assertKotlinMatches("datadog/kotlin-unboundedconsumption",
		"val response = http.post(\"https://api.example.com/orders\") { setBody(order) }", false)

	// excessiveagency: AI client + tool/function-call pattern
	assertKotlinMatches("datadog/kotlin-excessiveagency",
		"val tool = ToolCallback.builder().name(\"deleteFile\").function(::deleteFile).build()\nchatClient.prompt().toolCallbacks(tool).call()", true)
	assertKotlinMatches("datadog/kotlin-excessiveagency",
		"val answer = chatClient.prompt().user(q).call().content()\nreturn ResponseEntity.ok(answer)", false)

	// systempromptleakage: system-prompt indicator + response sink / log / throw
	assertKotlinMatches("datadog/kotlin-systempromptleakage",
		"val systemPrompt = \"You are a backend DB admin.\"\ncall.respond(mapOf(\"system\" to systemPrompt))", true)
	assertKotlinMatches("datadog/kotlin-systempromptleakage",
		"val systemPrompt = \"You are a helpful bot.\"\nchatClient.prompt().system(systemPrompt).call()", false)

	// unboundedconsumption: AI client + request/stream shape
	assertKotlinMatches("datadog/kotlin-unboundedconsumption",
		"val model = OpenAiChatModel.builder().apiKey(k).build()\nmodel.chat(prompt)", true)
	assertKotlinMatches("datadog/kotlin-unboundedconsumption",
		"val n = request.getParameter(\"n\").toInt()\nfor (i in 0..n) println(i)", false)

	// vectorembeddingweaknesses: vector store + ingest op
	assertKotlinMatches("datadog/kotlin-vectorembeddingweaknesses",
		"val store = QdrantEmbeddingStore.builder().build()\nstore.add(embedding, doc)", true)
	assertKotlinMatches("datadog/kotlin-vectorembeddingweaknesses",
		"val results = store.search(query, topK = 5)", false)

	// datamodelpoisoning: model-load API + user input / huggingface
	assertKotlinMatches("datadog/kotlin-datamodelpoisoning",
		"import ai.onnxruntime.OrtEnvironment\nval url = call.parameters[\"url\"]!!\nval session = env.createSession(fetch(url))", true)
	assertKotlinMatches("datadog/kotlin-datamodelpoisoning",
		"val model = Model.load(\"/opt/models/fixed.onnx\")", false)

	assertKotlinMatches("datadog/kotlin-datamodelpoisoning",
		"val id = call.parameters[\"id\"]; sessionManager.createSession(id)", false)
	assertKotlinMatches("datadog/kotlin-supplychain",
		"val session = sessionManager.createSession(user)", false)
	assertKotlinMatches("datadog/kotlin-supplychain",
		"import ai.onnxruntime.OrtSession; val modelName = \"classifier\"", false)

	// misinformation: AI client + response sink + high-impact domain word
	assertKotlinMatches("datadog/kotlin-misinformation",
		"val diagnosis = chatModel.chat(symptoms).aiMessage().text()\ncall.respond(mapOf(\"diagnosis\" to diagnosis))", true)
	assertKotlinMatches("datadog/kotlin-misinformation",
		"val summary = chatModel.chat(text).aiMessage().text()\ncall.respond(mapOf(\"summary\" to summary))", false)

	// supplychain: model library + fetch/load, or AI client + package install
	assertKotlinMatches("datadog/kotlin-supplychain",
		"val url = \"https://huggingface.co/$repo/resolve/main/model.onnx\"\nval bytes = httpClient.get(url).readBytes()\nenv.createSession(bytes)", true)
	assertKotlinMatches("datadog/kotlin-supplychain",
		"val n = request.getParameter(\"n\").toInt()\nprintln(n)", false)
	// Regression cases from the documented APIs, plus non-AI controls.
	t.Run("kotlin/improperoutputhandling#4", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-improperoutputhandling"},
			Code: `val filename = chatModel.chat("Return only the filename for: $desc").aiMessage().text().trim()
val bytes = Files.readAllBytes(Paths.get("/var/app/docs/$filename"))  // <-- SINK: LLM-controlled path
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/improperoutputhandling#5", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-improperoutputhandling"},
			Code: `val url = chatModel.chat("Return only the URL for: $desc").aiMessage().text().trim()
val body = restTemplate.getForObject(url, String::class.java)  // <-- SINK: LLM-controlled URL enables SSRF
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/improperoutputhandling#8", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-improperoutputhandling"},
			Code: `val expr = chatModel.generate("Return a SpEL expression for: $task")
val value = SpelExpressionParser().parseExpression(expr).getValue(context)  // <-- SINK: SpEL code execution
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/systempromptleakage#4", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-systempromptleakage"},
			Code: `private val SYSTEM_PROMPT =
    "Internal support agent. Employee salary data is available to you."

class PromptServlet : HttpServlet() {
    override fun doGet(req: HttpServletRequest, resp: HttpServletResponse) {
        resp.contentType = "text/plain"
        resp.writer.write(SYSTEM_PROMPT)  // <-- SINK: raw system prompt in HTTP response
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/unboundedconsumption#2", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-unboundedconsumption"},
			Code: `import org.springframework.ai.openai.OpenAiChatModel
import org.springframework.ai.openai.OpenAiChatOptions
import org.springframework.ai.openai.api.OpenAiApi

class SpringAiConfig {
    fun buildModel(): OpenAiChatModel {
        val api = OpenAiApi.builder()
            .apiKey(System.getenv("OPENAI_API_KEY"))
            .build()
        val options = OpenAiChatOptions.builder()
            .model("gpt-4o")
            .build()  // <-- SINK: no .maxTokens(N)
        return OpenAiChatModel(api, options)
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/unboundedconsumption#5", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-unboundedconsumption"},
			Code: `import dev.langchain4j.model.openai.OpenAiChatModel
import dev.langchain4j.service.AiServices

interface Assistant {
    fun chat(message: String): String
}

class AssistantFactory {
    fun build(): Assistant {
        val model = OpenAiChatModel.builder()
            .apiKey(System.getenv("OPENAI_API_KEY"))
            .modelName("gpt-4o-mini")
            .build()  // <-- SINK: no .maxTokens — every AiServices call is uncapped
        return AiServices.builder(Assistant::class.java)
            .chatLanguageModel(model)
            .build()
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/unboundedconsumption#6", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-unboundedconsumption"},
			Code: `import org.springframework.ai.chat.client.ChatClient
import org.springframework.ai.openai.OpenAiChatOptions
import org.springframework.stereotype.Service

@Service
class ChatService(builder: ChatClient.Builder) {
    private val chatClient: ChatClient = builder.build()

    fun answer(userMessage: String): String =
        chatClient.prompt(userMessage)
            .options(OpenAiChatOptions.builder()
                .model("gpt-4o")
                .build())  // <-- SINK: no .maxTokens on per-request options
            .call()
            .content()
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/unboundedconsumption#9", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-unboundedconsumption"},
			Code: `import org.springframework.ai.chat.client.ChatClient
import org.springframework.ai.openai.OpenAiChatOptions
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class AiConfig {
    @Bean
    fun chatClient(builder: ChatClient.Builder): ChatClient =
        builder
            .defaultOptions(OpenAiChatOptions.builder()
                .model("gpt-4o-mini")
                .build())  // <-- SINK: default options missing .maxTokens
            .build()
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/vectorembeddingweaknesses#2", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-vectorembeddingweaknesses"},
			Code: `@RestController
class BatchIngestController(
    private val embeddingModel: EmbeddingModel,
    private val embeddingStore: EmbeddingStore<TextSegment>,
) {
    data class BatchRequest(val documents: List<String>)

    @PostMapping("/api/batch-ingest")
    fun batchIngest(@RequestBody request: BatchRequest): String {
        val segments = request.documents.map { TextSegment.from(it) }
        val embeddings = embeddingModel.embedAll(segments).content()
        embeddingStore.addAll(embeddings, segments)  // <-- SINK: batch of user text stored
        return "batch stored"
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/vectorembeddingweaknesses#7", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-vectorembeddingweaknesses"},
			Code: `@RestController
class RagIngestController(
    private val ingestor: EmbeddingStoreIngestor,
) {
    data class IngestRequest(val content: String)

    @PostMapping("/api/rag/ingest")
    fun ingest(@RequestBody request: IngestRequest): String {
        val doc = Document.from(request.content)
        ingestor.ingest(doc)  // <-- SINK: EmbeddingStoreIngestor.ingest calls embeddingStore.add internally
        return "ingested"
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/datamodelpoisoning#5", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-datamodelpoisoning"},
			Code: `import org.tensorflow.SavedModelBundle
import javax.servlet.http.HttpServlet
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class ModelServlet : HttpServlet() {
    override fun doPost(req: HttpServletRequest, resp: HttpServletResponse) {
        val modelPath = req.getParameter("model_path") ?: ""
        SavedModelBundle.load(modelPath, "serve")  // <-- SINK: user path
        resp.writer.write("ok")
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/datamodelpoisoning#6", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-datamodelpoisoning"},
			Code: `import org.deeplearning4j.nn.multilayer.MultiLayerNetwork
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.io.File

@RestController
class Dl4jController {
    @PostMapping("/load")
    fun load(@RequestParam modelPath: String): String {
        MultiLayerNetwork.load(File(modelPath), true)
        //                       ^-- SINK: deserializes arbitrary Java object
        return "ok"
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/datamodelpoisoning#8", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-datamodelpoisoning"},
			Code: `import weka.core.SerializationHelper
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class WekaController {
    @PostMapping("/load")
    fun load(@RequestParam modelPath: String): String {
        SerializationHelper.read(modelPath)  // <-- SINK: Java object deserialization
        return "ok"
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("kotlin/datamodelpoisoning#9", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-datamodelpoisoning"},
			Code: `import org.nd4j.linalg.dataset.DataSet
import org.nd4j.linalg.factory.Nd4j
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

data class TrainRequest(val features: Array<FloatArray>, val labels: Array<FloatArray>)

@RestController
class TrainController(private val model: org.deeplearning4j.nn.multilayer.MultiLayerNetwork) {
    @PostMapping("/train")
    fun train(@RequestBody req: TrainRequest): String {
        val dataset = DataSet(Nd4j.create(req.features), Nd4j.create(req.labels))
        model.fit(dataset)  // <-- SINK: user-controlled training data modifies live weights
        return "ok"
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Koog Android intent", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-promptinjection"},
			Code: `import ai.koog.agents.core.agent.AIAgent
val prompt = intent.getStringExtra("prompt") ?: return
agent.run(prompt)`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Koog function input", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-promptinjection"},
			Code: `import ai.koog.agents.core.agent.AIAgent
suspend fun answer(agent: AIAgent<String, String>, prompt: String) = agent.run(prompt)`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Android without AI", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-promptinjection"},
			Code: `val prompt = intent.getStringExtra("prompt") ?: return
agent.run(prompt)`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("JDBC email", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-sensitiveinfodisclosure"},
			Code: `import dev.langchain4j.model.chat.ChatLanguageModel
val email = rs.getString("email")
chatModel.chat(email)`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Phone without AI", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-sensitiveinfodisclosure"},
			Code: `val phone = rs.getString("phone")
logger.info(phone)`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("PII phone", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-sensitiveinfodisclosure"},
			Code: `val phone = rs.getString("phone")
chatModel.chat(phone)`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Servlet without system prompt", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-systempromptleakage"},
			Code:     `resp.writer.write("hello")`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Generic model training", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-datamodelpoisoning"},
			Code:     `@PostMapping("/train") fun train(@RequestBody data: Data) { model.fit(data) }`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Read only embeddings", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-vectorembeddingweaknesses"},
			Code:     `embeddingStore.search(request)`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("File read without AI", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.Kotlin,
			Rule:     api.AiPrompt{ID: "datadog/kotlin-improperoutputhandling"},
			Code:     `Files.readAllBytes(Paths.get(filename))`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})

}

// TestShouldAnalyzePhpOWASPAIRules exercises the ten PHP OWASP AI Top 10
// combined filters added in K9CODESEC-7609. Each case is a canonical positive
// pattern taken from the matching playground fixture; the companion negative
// case asserts the combined filter rejects nearby ambiguous code.
func TestShouldAnalyzePhpOWASPAIRules(t *testing.T) {
	assertPhpMatches := func(ruleID, code string, want bool) {
		t.Helper()
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: ruleID},
			Code:     code,
		}
		assert.Equal(t, want, ShouldAnalyze(&ctx, log.NoopLogger()), ruleID)
	}

	// promptinjection: AI client + request input OR prompt-role signal
	assertPhpMatches("datadog/php-promptinjection",
		"$client = \\OpenAI::client($k);\n$q = $_POST['query'];\n$client->chat()->create(['messages' => [['role' => 'user', 'content' => $q]]]);", true)
	assertPhpMatches("datadog/php-promptinjection",
		"$name = $_POST['name'];\necho htmlspecialchars($name);", false)

	// sensitiveinfodisclosure: AI context + sensitive data
	assertPhpMatches("datadog/php-sensitiveinfodisclosure",
		"$key = getenv('OPENAI_API_KEY');\nerror_log(\"loaded key: $key\");", true)
	assertPhpMatches("datadog/php-sensitiveinfodisclosure",
		"$name = $_POST['name'];\necho \"hello $name\";", false)

	assertPhpMatches("datadog/php-sensitiveinfodisclosure",
		"$key = getenv('STRIPE_SECRET_KEY'); error_log($key);", false)
	assertPhpMatches("datadog/php-sensitiveinfodisclosure",
		"$secret = getenv('DB_PASSWORD'); return new JsonResponse(['secret' => $secret]);", false)
	assertPhpMatches("datadog/php-promptinjection", `
 use LLPhant\Chat\OpenAIChat;
 $stmt = $pdo->prepare("SELECT body FROM comments WHERE id = ?");
 $stmt->execute([$id]);
 $comment = (string) $stmt->fetchColumn();
 $chat = new OpenAIChat();
 return $chat->generateText("Summarize this comment: " . $comment);`, true)
	assertPhpMatches("datadog/php-promptinjection",
		"$messages = new MessageBag(); $message = new UserMessage($_POST['text']);", false)
	assertPhpMatches("datadog/php-excessiveagency", `
 $client = \OpenAI::client($key);
 $response = $client->chat()->create(['tools' => $tools, 'messages' => $messages]);
 foreach ($response->choices[0]->message->toolCalls as $call) {
  $args = json_decode($call->function->arguments, true, flags: JSON_THROW_ON_ERROR);
  $http->post($args['path'], ['json' => $args['payload']]);
 }`, true)
	assertPhpMatches("datadog/php-excessiveagency",
		"use NeuronAI\\Tools\\Tool; #[Tool(name: 'remove')] function remove($path) { unlink($path); }", true)
	assertPhpMatches("datadog/php-excessiveagency",
		"$http = new GuzzleHttp\\Client(); $http->post($args['path']); User::destroy($id);", false)
	assertPhpMatches("datadog/php-unboundedconsumption", `
 use GuzzleHttp\Client;
 $http = new Client();
 $response = $http->post('http://llm.internal:8080/v1/completions', [
  'json' => ['model' => 'llama-3-70b', 'prompt' => $prompt],
 ]);`, true)
	assertPhpMatches("datadog/php-unboundedconsumption",
		"$http = new GuzzleHttp\\Client(); $http->post('https://api.example.com/orders', ['json' => $order]);", false)
	assertPhpMatches("datadog/php-unboundedconsumption",
		"Prism::text()->using(Provider::OpenAI, 'gpt-4o')->withPrompt($prompt)->asText();", true)

	// supplychain: model library + fetch/load, or AI client + package install
	assertPhpMatches("datadog/php-supplychain",
		"$bytes = file_get_contents(\"https://huggingface.co/$repo/resolve/main/model.onnx\");\n$sess = new OnnxRuntime\\InferenceSession($bytes);", true)
	assertPhpMatches("datadog/php-supplychain",
		"$name = $_POST['name'];\necho $name;", false)

	assertPhpMatches("datadog/php-supplychain",
		"use Rubix\\ML\\PersistentModel; $modelName = 'classifier';", false)
	assertPhpMatches("datadog/php-supplychain",
		"$data = file_get_contents('https://example.com/resolve/main/orders.json');", false)

	// datamodelpoisoning: model-load API + user input / finetune
	assertPhpMatches("datadog/php-datamodelpoisoning",
		"$path = $_FILES['model']['tmp_name'];\n$model = Rubix\\ML\\PersistentModel::load(new Rubix\\ML\\Persisters\\Filesystem($path));", true)
	assertPhpMatches("datadog/php-datamodelpoisoning",
		"$model = Rubix\\ML\\PersistentModel::load(new Rubix\\ML\\Persisters\\Filesystem('/opt/models/vetted.rbx'));", false)

	// improperoutputhandling: AI client + dangerous output sink
	assertPhpMatches("datadog/php-improperoutputhandling",
		"$client = \\OpenAI::client($k);\n$sql = $client->chat()->create([...])->choices[0]->message->content;\n$pdo->query($sql);", true)
	assertPhpMatches("datadog/php-improperoutputhandling",
		"$client = \\OpenAI::client($k);\n$answer = $client->chat()->create([...])->choices[0]->message->content;\nreturn response()->json(['answer' => $answer]);", false)

	// excessiveagency: AI client + tool/mail/auth pattern
	assertPhpMatches("datadog/php-excessiveagency",
		"use Symfony\\AI\\Agent\\Agent;\n$agent = new Agent($platform, $model);\n#[Tool]\nfunction deleteUser($id) { User::destroy($id); }", true)
	assertPhpMatches("datadog/php-excessiveagency",
		"$client = \\OpenAI::client($k);\n$resp = $client->chat()->create([...]);\necho $resp->choices[0]->message->content;", false)

	// systempromptleakage: system-prompt indicator + response sink / log / throw
	assertPhpMatches("datadog/php-systempromptleakage",
		"$systemPrompt = 'You are a backend admin.';\nreturn response()->json(['system_prompt' => $systemPrompt]);", true)
	assertPhpMatches("datadog/php-systempromptleakage",
		"$systemPrompt = 'You are helpful.';\n$client = \\OpenAI::client($k);\n$client->chat()->create(['messages' => [['role' => 'system', 'content' => $systemPrompt]]]);", false)

	// vectorembeddingweaknesses: vector store + ingest op
	assertPhpMatches("datadog/php-vectorembeddingweaknesses",
		"$store = new LLPhant\\Embeddings\\VectorStores\\Qdrant\\QdrantVectorStore($client, 'docs');\n$store->addDocument($doc);", true)
	assertPhpMatches("datadog/php-vectorembeddingweaknesses",
		"$results = $qdrant->search('docs', $queryVector, 5);", false)

	// misinformation: AI client + response sink + high-impact word
	assertPhpMatches("datadog/php-misinformation",
		"$client = \\OpenAI::client($k);\n$diagnosis = $client->chat()->create([...])->choices[0]->message->content;\nreturn new JsonResponse(['medical_diagnosis' => $diagnosis]);", true)
	assertPhpMatches("datadog/php-misinformation",
		"$client = \\OpenAI::client($k);\n$summary = $client->chat()->create([...])->choices[0]->message->content;\nreturn response()->json(['summary' => $summary]);", false)

	// unboundedconsumption: AI client + request/stream shape
	assertPhpMatches("datadog/php-unboundedconsumption",
		"$client = \\OpenAI::client($k);\n$resp = $client->chat()->create(['model' => 'gpt-4o', 'messages' => $msgs]);", true)
	assertPhpMatches("datadog/php-unboundedconsumption",
		"$name = $_POST['name'];\necho htmlspecialchars($name);", false)
	// Regression cases from the documented APIs, plus non-AI controls.
	t.Run("php/datamodelpoisoning#2", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-datamodelpoisoning"},
			Code: `<?php
Route::post('/retrain', function () {
    $client = \OpenAI::client(getenv('OPENAI_API_KEY'));
    $tmp = tempnam(sys_get_temp_dir(), 'ft');
    $fh = fopen($tmp, 'w');
    foreach (UserSubmission::recent()->get() as $s) {
        fwrite($fh, json_encode(['prompt' => $s->prompt, 'completion' => $s->completion]) . "\n");
    }
    fclose($fh);

    $file = $client->files->upload([
        'file' => fopen($tmp, 'r'),
        'purpose' => 'fine-tune',
    ]);
    // <-- SINK: unreviewed user submissions become the training corpus
    $client->fineTuning->createJob([
        'training_file' => $file->id,
        'model' => 'gpt-4o-mini-2024-07-18',
    ]);
    return response()->json(['status' => 'queued']);
});
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("php/datamodelpoisoning#5", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-datamodelpoisoning"},
			Code: `<?php
use Phpml\Classification\KNearestNeighbors;

Route::post('/train', function (\Illuminate\Http\Request $request) {
    $classifier = new KNearestNeighbors();
    $samples = $request->input('samples');
    $labels  = $request->input('labels');
    $classifier->train($samples, $labels);  // <-- SINK: untrusted training data
    return response()->json(['status' => 'trained']);
});
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("php/improperoutputhandling#4", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-improperoutputhandling"},
			Code: `$filename = trim($client->chat()->create([
    'model' => 'gpt-4o-mini',
    'messages' => [
        ['role' => 'system', 'content' => 'Return only the filename.'],
        ['role' => 'user', 'content' => $desc],
    ],
])->choices[0]->message->content);
$contents = file_get_contents("/var/app/docs/$filename");  // <-- SINK: LLM-controlled path
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("php/improperoutputhandling#5", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-improperoutputhandling"},
			Code: `use GuzzleHttp\Client;

$url = trim($client->chat()->create([
    'model' => 'gpt-4o-mini',
    'messages' => [
        ['role' => 'system', 'content' => 'Return only the URL.'],
        ['role' => 'user', 'content' => $desc],
    ],
])->choices[0]->message->content);
$body = (string) (new Client())->get($url)->getBody();  // <-- SINK: LLM-controlled URL enables SSRF
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("php/improperoutputhandling#8", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-improperoutputhandling"},
			Code: `$plugin = $chat->generateText("Return the plugin filename to load for: $task");
require "/var/app/plugins/$plugin";  // <-- SINK: LLM-controlled include path
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("php/improperoutputhandling#9", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-improperoutputhandling"},
			Code: `$output = $client->chat()->create([
    'model' => 'gpt-4o',
    'messages' => [['role' => 'user', 'content' => $prompt]],
])->choices[0]->message->content;
error_log($output);  // <-- SINK: ANSI escape sequences reach the log/terminal — visual spoofing / clipboard hijack
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("php/excessiveagency#8", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-excessiveagency"},
			Code: `<?php
use Mcp\Server\Server;
use Mcp\Server\Tool\McpTool;

class OpsTools {
    #[McpTool(name: 'run', description: 'Run a shell command')]
    public function run(string $cmd): string {
        return (string) shell_exec($cmd);  // <-- SINK: any MCP caller runs any shell command
    }
}
`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("PHP database email", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-sensitiveinfodisclosure"},
			Code: `use LLPhant\Chat\OpenAIChat;
$email = $pdo->query('SELECT email FROM users LIMIT 1')->fetchColumn();
$chat = new OpenAIChat();
$chat->generateText($email);`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("PHP phone", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-sensitiveinfodisclosure"},
			Code: `use LLPhant\Chat\OpenAIChat;
$chat->generateText($user->phone);`,
		}
		assert.Equal(t, true, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("PHP phone without AI", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-sensitiveinfodisclosure"},
			Code:     `$phone = $user->phone; error_log($phone);`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("PHP training without model library", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-datamodelpoisoning"},
			Code:     `$trainer->train($request->input('training'));`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("MCP without tool", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-excessiveagency"},
			Code:     `use Mcp\Server\Server; $server = new Server();`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("Tool without MCP or AI", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-excessiveagency"},
			Code:     `#[McpTool] function run($cmd) { return shell_exec($cmd); }`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})
	t.Run("HTTP without AI", func(t *testing.T) {
		ctx := model.DetectionContext{
			Language: model.PHP,
			Rule:     api.AiPrompt{ID: "datadog/php-improperoutputhandling"},
			Code:     `use GuzzleHttp\Client; $http->get($url);`,
		}
		assert.Equal(t, false, ShouldAnalyze(&ctx, log.NoopLogger()))
	})

}
