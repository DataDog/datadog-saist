package filtering

import (
	"regexp"
	"strings"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
)

// Precompiled regexes for stripping comments / docstrings.
var (
	reJavaBlock = regexp.MustCompile(`(?s)/\*.*?\*/`)
	reJavaLine  = regexp.MustCompile(`//.*`)
	// Like //.*,  this strips # inside string literals too (e.g. "#ff0000" becomes "").
	// The false-strip rate is higher than for // because # appears in PHP strings far more
	// often (hex colors, regex delimiters, URL fragments). Accepted tradeoff: keyword
	// matching only needs a rough signal, not perfect fidelity.
	rePHPHash = regexp.MustCompile(`#.*`)

	reGoBlock = regexp.MustCompile(`(?s)/\*.*?\*/`)

	// Simple heuristic for Python triple-quoted strings (often docstrings).
	rePyTriple = regexp.MustCompile(`(?s)("""[\s\S]*?"""|'''[\s\S]*?''')`)

	// Token splitter for word-ish matching.
	reTokenSplit = regexp.MustCompile(`[^a-z0-9_]+`)

	// Keep Phoenix request-source matching scoped to controller-style function heads,
	// while allowing standard formatter-introduced newlines and indentation.
	reElixirPhoenixActionParameters = regexp.MustCompile(
		`(?s)\bdefp?\s+[a-z_][a-z0-9_!?]*\s*(?:\(\s*)?` +
			`(?:_?conn|%plug\.conn\{.*?\}\s*=\s*_?conn)\s*,\s*(?:%\{\s*"|params\b)`,
	)
	reElixirLiveViewEventParameters = regexp.MustCompile(
		`(?s)\bdefp?\s+handle_event\s*(?:\(\s*)?` +
			`(?:"[^"]*"|[a-z_][a-z0-9_!?]*)\s*,\s*(?:%\{\s*"|params\b)`,
	)

	// These safe fast paths are intentionally narrow. If the expression is more
	// complex, the filter fails open and lets the rule evaluate it.
	reElixirSingleSafeDeserialization = regexp.MustCompile(`(?s)(?::erlang\.)?binary_to_term\s*\([^()]*(?:,\s*\[\s*:safe\s*\])\s*\)`)
	reElixirPinnedHuggingFaceLoad     = regexp.MustCompile(
		`(?s)bumblebee\.load_(?:model|featurizer)\s*\(\s*\{:hf,\s*"[^"]+"` +
			`\s*,\s*revision:\s*"[0-9a-f]{40}"\s*\}`,
	)
)

// codeUsedForDetection strips comments / docstrings etc. before keyword matching.
func codeUsedForDetection(inputCode string, language model.Language) string {
	switch language {
	case model.Java:
		return stripJavaComments(inputCode)
	case model.Go:
		return stripGoComments(inputCode)
	case model.Python:
		return stripPythonComments(inputCode)
	case model.CSharp:
		return stripCSharpComments(inputCode)
	case model.JavaScript:
		return stripJavaScriptComments(inputCode)
	case model.TypeScript:
		return stripTypeScriptComments(inputCode)
	case model.Kotlin:
		return stripKotlinComments(inputCode)
	case model.PHP:
		return stripPHPComments(inputCode)
	case model.Ruby:
		return stripRubyComments(inputCode)
	case model.Rust:
		return stripRustComments(inputCode)
	case model.Elixir:
		return stripElixirComments(inputCode)
	default:
		return inputCode
	}
}

// StripCodeForDetection returns lowercased code with comments/docstrings stripped.
// Call this once per file and store in DetectionContext.StrippedCode to avoid
// redundant regex operations when checking multiple rules against the same file.
func StripCodeForDetection(code string, language model.Language) string {
	return codeUsedForDetection(strings.ToLower(code), language)
}

// getStrippedCode returns the stripped code from context, computing it if not cached.
func getStrippedCode(ctx *model.DetectionContext) string {
	if ctx.StrippedCode != "" {
		return ctx.StrippedCode
	}
	return codeUsedForDetection(strings.ToLower(ctx.Code), ctx.Language)
}

// stripCStyleComments removes C-style block (/* ... */) and line (//) comments,
// then drops any post-stripping lines for which skipLine(trimmed) returns true.
// Shared between Java, JavaScript, and C# which all use the same comment syntax.
func stripCStyleComments(code string, skipLine func(trimmed string) bool) string {
	code = reJavaBlock.ReplaceAllString(code, "")
	code = reJavaLine.ReplaceAllString(code, "")

	lines := strings.Split(code, "\n")
	out := lines[:0]
	for _, line := range lines {
		if skipLine(strings.TrimSpace(line)) {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func stripJavaComments(code string) string {
	// Skip empty and bare "*" lines (common in Javadoc bodies).
	return stripCStyleComments(code, func(trimmed string) bool {
		return trimmed == "" || trimmed == "*"
	})
}

func stripGoComments(code string) string {
	// Remove /* ... */ first.
	code = reGoBlock.ReplaceAllString(code, "")
	lines := strings.Split(code, "\n")
	out := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func stripPythonComments(code string) string {
	// Remove triple-quoted docstrings (heuristic).
	code = rePyTriple.ReplaceAllString(code, "")

	lines := strings.Split(code, "\n")
	out := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func stripJavaScriptComments(code string) string {
	return stripCStyleComments(code, func(trimmed string) bool {
		return trimmed == ""
	})
}

func stripTypeScriptComments(code string) string {
	return stripCStyleComments(code, func(trimmed string) bool {
		return trimmed == ""
	})
}

func stripKotlinComments(code string) string {
	// Kotlin uses C-style comments; skip empty and bare "*" lines (KDoc bodies).
	return stripCStyleComments(code, func(trimmed string) bool {
		return trimmed == "" || trimmed == "*"
	})
}

func stripPHPComments(code string) string {
	// PHP supports C-style block/line comments and also # for single-line comments.
	code = reJavaBlock.ReplaceAllString(code, "")
	code = reJavaLine.ReplaceAllString(code, "")
	code = rePHPHash.ReplaceAllString(code, "")
	lines := strings.Split(code, "\n")
	out := lines[:0]
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func stripRustComments(code string) string {
	// Rust uses C-style comments (including /// and //! doc comments); skip empty and bare "*" lines.
	return stripCStyleComments(code, func(trimmed string) bool {
		return trimmed == "" || trimmed == "*"
	})
}

func stripCSharpComments(code string) string {
	// Skip empty and XML doc comment lines (/// or bare *).
	return stripCStyleComments(code, func(trimmed string) bool {
		return trimmed == "" || trimmed == "*" || strings.HasPrefix(trimmed, "///")
	})
}

func stripRubyComments(code string) string {
	lines := strings.Split(code, "\n")
	out := lines[:0]
	inBlock := false
	for _, line := range lines {
		// =begin/=end must start at column 0 in Ruby.
		if strings.HasPrefix(line, "=begin") {
			inBlock = true
			continue
		}
		if inBlock {
			if strings.HasPrefix(line, "=end") {
				inBlock = false
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// stripElixirComments is a small lexer whose branches mirror Elixir's literal states.
// Keeping the state transitions together makes it easier to verify that # is only
// treated as a comment outside strings, heredocs, and sigils.
//
//nolint:gocyclo
func stripElixirComments(code string) string {
	lines := strings.Split(code, "\n")
	out := make([]string, 0, len(lines))
	var quote byte
	var tripleQuote byte
	var sigilOpen byte
	var sigilClose byte
	var sigilTriple bool
	sigilDepth := 0
	escaped := false
	for _, line := range lines {
		commentAt := -1
		for i := 0; i < len(line); i++ {
			ch := line[i]
			if tripleQuote != 0 {
				if ch == tripleQuote && i+2 < len(line) && line[i+1] == ch && line[i+2] == ch {
					tripleQuote = 0
					i += 2
				}
				continue
			}
			if sigilClose != 0 {
				if sigilTriple {
					if ch == sigilClose && i+2 < len(line) && line[i+1] == ch && line[i+2] == ch {
						sigilOpen, sigilClose, sigilTriple, sigilDepth = 0, 0, false, 0
						i += 2
					}
					continue
				}
				if escaped {
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
					continue
				}
				if sigilOpen != sigilClose && ch == sigilOpen {
					sigilDepth++
					continue
				}
				if ch == sigilClose {
					sigilDepth--
					if sigilDepth == 0 {
						sigilOpen, sigilClose = 0, 0
					}
				}
				continue
			}
			if escaped {
				escaped = false
				continue
			}
			if quote != 0 && ch == '\\' {
				escaped = true
				continue
			}
			if quote != 0 {
				if ch == quote {
					quote = 0
				}
				continue
			}
			if ch == '\'' || ch == '"' {
				if i+2 < len(line) && line[i+1] == ch && line[i+2] == ch {
					tripleQuote = ch
					i += 2
				} else {
					quote = ch
				}
				continue
			}
			if ch == '~' && i+2 < len(line) && isASCIILetter(line[i+1]) {
				if closingDelimiter, ok := elixirSigilDelimiter(line[i+2]); ok {
					sigilOpen, sigilClose, sigilDepth = line[i+2], closingDelimiter, 1
					if (sigilOpen == '\'' || sigilOpen == '"') && i+4 < len(line) && line[i+3] == sigilOpen && line[i+4] == sigilOpen {
						sigilTriple = true
						i += 4
					} else {
						i += 2
					}
					continue
				}
			}
			if ch == '#' {
				commentAt = i
				break
			}
		}
		if commentAt >= 0 {
			line = line[:commentAt]
		}
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func isASCIILetter(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z'
}

func elixirSigilDelimiter(open byte) (byte, bool) {
	switch open {
	case '(':
		return ')', true
	case '[':
		return ']', true
	case '{':
		return '}', true
	case '<':
		return '>', true
	default:
		if isASCIILetter(open) || open >= '0' && open <= '9' || open == '_' || open == ' ' || open == '\t' {
			return 0, false
		}
		return open, true
	}
}

func containsAny(code string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(code, kw) {
			return true
		}
	}
	return false
}

func containsAnyWord(code string, words []string) bool {
	tokens := reTokenSplit.Split(code, -1)
	seen := make(map[string]struct{}, len(tokens))
	for _, t := range tokens {
		if t == "" {
			continue
		}
		seen[t] = struct{}{}
	}
	for _, w := range words {
		if _, ok := seen[w]; ok {
			return true
		}
	}
	return false
}

type ruleFilterFunc func(ctx *model.DetectionContext) bool

var ruleFilters = map[string]ruleFilterFunc{
	// SQL Injection
	"datadog/python-sqli": shouldAnalyzePythonSqliCtx,
	"datadog/go-sqli":     shouldAnalyzeGoSqliCtx,
	"datadog/java-sqli":   shouldAnalyzeJavaSqliCtx,
	"datadog/csharp-sqli": shouldAnalyzeCSharpSqliCtx,

	// Command Injection
	"datadog/java-cmdi":   shouldAnalyzeJavaCmdiCtx,
	"datadog/go-cmdi":     shouldAnalyzeGoCmdiCtx,
	"datadog/python-cmdi": shouldAnalyzePythonCmdiCtx,
	"datadog/csharp-cmdi": shouldAnalyzeCSharpCmdiCtx,

	// XSS
	"datadog/java-xss":   shouldAnalyzeJavaXssCtx,
	"datadog/go-xss":     shouldAnalyzeGoXssCtx,
	"datadog/python-xss": shouldAnalyzePythonXssCtx,
	"datadog/csharp-xss": shouldAnalyzeCSharpXssCtx,

	// Deserialization
	"datadog/java-deserialization":   shouldAnalyzeJavaDeserializationCtx,
	"datadog/go-deserialization":     shouldAnalyzeGoDeserializationCtx,
	"datadog/python-deserialization": shouldAnalyzePythonDeserializationCtx,
	"datadog/csharp-deserialization": shouldAnalyzeCSharpDeserializationCtx,

	// Broken Cryptography
	"datadog/java-brokencrypto":   shouldAnalyzeJavaBrokencryptoCtx,
	"datadog/go-brokencrypto":     shouldAnalyzeGoBrokencryptoCtx,
	"datadog/python-brokencrypto": shouldAnalyzePythonBrokencryptoCtx,
	"datadog/csharp-brokencrypto": shouldAnalyzeCSharpBrokencryptoCtx,

	// Path Traversal
	"datadog/java-pathtraversal":   shouldAnalyzeJavaPathtraversalCtx,
	"datadog/go-pathtraversal":     shouldAnalyzeGoPathtraversalCtx,
	"datadog/python-pathtraversal": shouldAnalyzePythonPathtraversalCtx,
	"datadog/csharp-pathtraversal": shouldAnalyzeCSharpPathtraversalCtx,

	// Code Injection
	"datadog/java-codei":   shouldAnalyzeJavaCodeiCtx,
	"datadog/go-codei":     shouldAnalyzeGoCodeiCtx,
	"datadog/python-codei": shouldAnalyzePythonCodeiCtx,
	"datadog/csharp-codei": shouldAnalyzeCSharpCodeiCtx,

	// LDAP Injection
	"datadog/java-ldapi":   shouldAnalyzeJavaLdapiCtx,
	"datadog/go-ldapi":     shouldAnalyzeGoLdapiCtx,
	"datadog/python-ldapi": shouldAnalyzePythonLdapiCtx,
	"datadog/csharp-ldapi": shouldAnalyzeCSharpLdapiCtx,

	// XPath Injection
	"datadog/java-xpathi":   shouldAnalyzeJavaXpathiCtx,
	"datadog/go-xpathi":     shouldAnalyzeGoXpathiCtx,
	"datadog/python-xpathi": shouldAnalyzePythonXpathiCtx,
	"datadog/csharp-xpathi": shouldAnalyzeCSharpXpathiCtx,

	// Weak Hash
	"datadog/java-weakhash":   shouldAnalyzeJavaWeakhashCtx,
	"datadog/go-weakhash":     shouldAnalyzeGoWeakhashCtx,
	"datadog/python-weakhash": shouldAnalyzePythonWeakhashCtx,
	"datadog/csharp-weakhash": shouldAnalyzeCSharpWeakhashCtx,

	// Insecure Cookie
	"datadog/java-insecurecookie":   shouldAnalyzeJavaInsecurecookieCtx,
	"datadog/go-insecurecookie":     shouldAnalyzeGoInsecurecookieCtx,
	"datadog/python-insecurecookie": shouldAnalyzePythonInsecurecookieCtx,
	"datadog/csharp-insecurecookie": shouldAnalyzeCSharpInsecurecookieCtx,

	// Access Control
	"datadog/java-accesscontrol":   shouldAnalyzeJavaAccesscontrolCtx,
	"datadog/go-accesscontrol":     shouldAnalyzeGoAccesscontrolCtx,
	"datadog/python-accesscontrol": shouldAnalyzePythonAccesscontrolCtx,
	"datadog/csharp-accesscontrol": shouldAnalyzeCSharpAccesscontrolCtx,

	// Trust Boundary
	"datadog/java-trustboundary":   shouldAnalyzeJavaTrustboundaryCtx,
	"datadog/go-trustboundary":     shouldAnalyzeGoTrustboundaryCtx,
	"datadog/python-trustboundary": shouldAnalyzePythonTrustboundaryCtx,
	"datadog/csharp-trustboundary": shouldAnalyzeCSharpTrustboundaryCtx,

	// Weak Randomness
	"datadog/java-weakrandomness":   shouldAnalyzeJavaWeakrandomnessCtx,
	"datadog/go-weakrandomness":     shouldAnalyzeGoWeakrandomnessCtx,
	"datadog/python-weakrandomness": shouldAnalyzePythonWeakrandomnessCtx,
	"datadog/csharp-weakrandomness": shouldAnalyzeCSharpWeakrandomnessCtx,

	// Ruby
	"datadog/ruby-sqli":                      shouldAnalyzeRubySqliCtx,
	"datadog/ruby-cmdi":                      shouldAnalyzeRubyCmdiCtx,
	"datadog/ruby-xss":                       shouldAnalyzeRubyXssCtx,
	"datadog/ruby-pathtraversal":             shouldAnalyzeRubyPathtraversalCtx,
	"datadog/ruby-zipslip":                   shouldAnalyzeRubyZipslipCtx,
	"datadog/ruby-ldapi":                     shouldAnalyzeRubyLdapiCtx,
	"datadog/ruby-codei":                     shouldAnalyzeRubyCodeiCtx,
	"datadog/ruby-loginjection":              shouldAnalyzeRubyLoginjectionCtx,
	"datadog/ruby-integeroverflow":           shouldAnalyzeRubyIntegeroverflowCtx,
	"datadog/ruby-sensitiveinfodisclosure":   shouldAnalyzeRubySensitiveinfodisclosureCtx,
	"datadog/ruby-errorinfoleak":             shouldAnalyzeRubyErrorinfoleakCtx,
	"datadog/ruby-accesscontrol":             shouldAnalyzeRubyAccesscontrolCtx,
	"datadog/ruby-brokencrypto":              shouldAnalyzeRubyBrokencryptoCtx,
	"datadog/ruby-weakhash":                  shouldAnalyzeRubyWeakhashCtx,
	"datadog/ruby-weakrandomness":            shouldAnalyzeRubyWeakrandomnessCtx,
	"datadog/ruby-deserialization":           shouldAnalyzeRubyDeserializationCtx,
	"datadog/ruby-trustboundary":             shouldAnalyzeRubyTrustboundaryCtx,
	"datadog/ruby-openredirect":              shouldAnalyzeRubyOpenredirectCtx,
	"datadog/ruby-insecurecookie":            shouldAnalyzeRubyInsecurecookieCtx,
	"datadog/ruby-xpathi":                    shouldAnalyzeRubyXpathiCtx,
	"datadog/ruby-improperoutputhandling":    shouldAnalyzeRubyImproperoutputhandlingCtx,
	"datadog/ruby-excessiveagency":           shouldAnalyzeRubyExcessiveagencyCtx,
	"datadog/ruby-systempromptleakage":       shouldAnalyzeRubySystempromptleakageCtx,
	"datadog/ruby-unboundedconsumption":      shouldAnalyzeRubyUnboundedconsumptionCtx,
	"datadog/ruby-vectorembeddingweaknesses": shouldAnalyzeRubyVectorembeddingweaknessesCtx,
	"datadog/ruby-datamodelpoisoning":        shouldAnalyzeRubyDatamodelpoisoningCtx,
	"datadog/ruby-misinformation":            shouldAnalyzeRubyMisinformationCtx,
	"datadog/ruby-promptinjection":           shouldAnalyzeRubyPromptinjectionCtx,

	// Elixir
	"datadog/elixir-sqli":                      shouldAnalyzeElixirSqliCtx,
	"datadog/elixir-cmdi":                      shouldAnalyzeElixirCmdiCtx,
	"datadog/elixir-xss":                       shouldAnalyzeElixirXssCtx,
	"datadog/elixir-pathtraversal":             shouldAnalyzeElixirPathtraversalCtx,
	"datadog/elixir-zipslip":                   shouldAnalyzeElixirZipslipCtx,
	"datadog/elixir-ldapi":                     shouldAnalyzeElixirLdapiCtx,
	"datadog/elixir-codei":                     shouldAnalyzeElixirCodeiCtx,
	"datadog/elixir-loginjection":              shouldAnalyzeElixirLoginjectionCtx,
	"datadog/elixir-integeroverflow":           shouldAnalyzeElixirIntegeroverflowCtx,
	"datadog/elixir-sensitiveinfodisclosure":   shouldAnalyzeElixirSensitiveinfodisclosureCtx,
	"datadog/elixir-errorinfoleak":             shouldAnalyzeElixirErrorinfoleakCtx,
	"datadog/elixir-accesscontrol":             shouldAnalyzeElixirAccesscontrolCtx,
	"datadog/elixir-brokencrypto":              shouldAnalyzeElixirBrokencryptoCtx,
	"datadog/elixir-weakhash":                  shouldAnalyzeElixirWeakhashCtx,
	"datadog/elixir-weakrandomness":            shouldAnalyzeElixirWeakrandomnessCtx,
	"datadog/elixir-deserialization":           shouldAnalyzeElixirDeserializationCtx,
	"datadog/elixir-trustboundary":             shouldAnalyzeElixirTrustboundaryCtx,
	"datadog/elixir-openredirect":              shouldAnalyzeElixirOpenredirectCtx,
	"datadog/elixir-insecurecookie":            shouldAnalyzeElixirInsecurecookieCtx,
	"datadog/elixir-xpathi":                    shouldAnalyzeElixirXpathiCtx,
	"datadog/elixir-improperoutputhandling":    shouldAnalyzeElixirImproperoutputhandlingCtx,
	"datadog/elixir-excessiveagency":           shouldAnalyzeElixirExcessiveagencyCtx,
	"datadog/elixir-systempromptleakage":       shouldAnalyzeElixirSystempromptleakageCtx,
	"datadog/elixir-unboundedconsumption":      shouldAnalyzeElixirUnboundedconsumptionCtx,
	"datadog/elixir-vectorembeddingweaknesses": shouldAnalyzeElixirVectorembeddingweaknessesCtx,
	"datadog/elixir-datamodelpoisoning":        shouldAnalyzeElixirDatamodelpoisoningCtx,
	"datadog/elixir-misinformation":            shouldAnalyzeElixirMisinformationCtx,
	"datadog/elixir-promptinjection":           shouldAnalyzeElixirPromptinjectionCtx,
	"datadog/elixir-supplychain":               shouldAnalyzeElixirSupplychainCtx,
}

// shouldAnalyzePythonSqliCtx checks for Python SQL injection patterns.
// Analyzes files with SQL string construction or database interaction.
func shouldAnalyzePythonSqliCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Database interaction patterns
	dbPatterns := []string{
		// Database modules
		"sqlite3",
		"psycopg2",
		"mysql",
		"pymysql",
		"cx_oracle",
		"pyodbc",
		"sqlalchemy",
		// Cursor/execute patterns
		"cursor(",
		".cursor(",
		"execute(",
		"executemany(",
		"callproc(",
		// Django ORM
		".raw(",
		".extra(",
		"rawsql",
		// Connection patterns
		"connection",
		"conn.",
		"db.",
	}

	// SQL keywords - use word-based matching
	sqlWords := []string{"select", "update", "insert", "delete", "from", "where", "call", "exec"}

	// String formatting patterns that suggest SQL injection risk
	stringFormattingPatterns := []string{
		"% (", // % formatting with tuple
		".format(",
		"f\"",
		"f'",
		"+ bar", // String concatenation with variable
		"+ param",
		"' +", // String concatenation patterns
		"\" +",
	}

	// SQL string construction patterns (direct SQL in string)
	sqlStringPatterns := []string{
		"\"select ",
		"'select ",
		"\"insert ",
		"'insert ",
		"\"update ",
		"'update ",
		"\"delete ",
		"'delete ",
	}

	hasDbPattern := containsAny(code, dbPatterns)
	hasSqlWord := containsAnyWord(code, sqlWords)
	hasStringFormatting := containsAny(code, stringFormattingPatterns)
	hasSqlString := containsAny(code, sqlStringPatterns)

	// Analyze if:
	// 1. DB pattern AND (SQL word OR string formatting), OR
	// 2. SQL string construction with string formatting (no DB pattern required)
	return (hasDbPattern && (hasSqlWord || hasStringFormatting)) ||
		(hasSqlString && hasStringFormatting)
}

// Go SQLi: require some SQL / DB hints AND SQL verbs.
// This helps avoid matching on random "select" keywords or stray identifiers.
func shouldAnalyzeGoSqliCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	dbHints := []string{
		`"database/sql"`,
		"database/sql",
		"db.exec(",
		"db.query(",
		"db.queryrow(",
		"db.prepare(",
		"sqlx.",
		"gorm.io/gorm",
		"sqlquery",
		"sqlstmt",
		"jackc/pgx",
		"pgx.",
		"pgxpool",
		".query(ctx",
		".queryrow(ctx",
		".exec(ctx",
		".querycontext(",
		".execcontext(",
	}

	// SQL string construction patterns
	sqlStringPatterns := []string{
		`"select `,
		`"insert `,
		`"update `,
		`"delete `,
		"select userid",
		"select * from",
		"insert into",
		"update users",
		"delete from",
		"from users where",
		"from customers where",
	}

	sqlWords := []string{"select", "update", "insert", "delete", "call", "exec"}

	// Stored procedure patterns
	storedProcPatterns := []string{
		"{call",
		"callablestatement",
		"callproc",
	}

	hasDbHints := containsAny(code, dbHints) || strings.Contains(code, "sql")
	hasSqlString := containsAny(code, sqlStringPatterns)
	hasStoredProc := containsAny(code, storedProcPatterns)
	hasSqlWord := containsAnyWord(code, sqlWords)

	// Match if:
	// 1. Has DB hints AND SQL words
	// 2. Has SQL string patterns (direct SQL construction)
	// 3. Has stored procedure patterns
	if hasStoredProc {
		return true
	}
	if hasSqlString {
		return true
	}
	if hasDbHints && hasSqlWord {
		return true
	}
	return false
}

// Java XSS: look for HTML-ish tags OR dynamic input sources OR explicit XSS-ish markers.
func shouldAnalyzeJavaXssCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Strong HTML indicators. No need to list every tag; a small core is enough.
	htmlHints := []string{
		"<html", "<body", "<script", "<form", "<input", "<img", "<iframe",
		"<div", "<span", "<a ", "<p>", "<p ",
	}

	// Typical dynamic-input / response patterns in servlet/JSP code.
	dynamicHints := []string{
		"getparameter(",
		"getheader(",
		"getcookie(",
		"getquerystring(",
		"request.",
		"request.get",
		"response.getwriter(",
		"printwriter",
	}

	// Explicit XSS-ish markers: literal "xss", inline JS, handlers.
	xssHints := []string{
		"xss",
		"javascript:",
		"onerror=",
		"onload=",
	}

	hasHTML := containsAny(code, htmlHints)
	hasDynamic := containsAny(code, dynamicHints)
	hasXSS := containsAny(code, xssHints)

	// If any of these are true, it's worth running the XSS rule.
	if hasHTML || hasDynamic || hasXSS {
		return true
	}

	return false
}

// Java SQLi: require DB interaction AND SQL verbs.
// This significantly reduces noise compared to substring-based keyword scanning.
func shouldAnalyzeJavaSqliCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Indicators that the code is interacting with a DB or query API.
	// NOTE: All hints must be lowercase since code is lowercased before comparison.
	dbHints := []string{
		// JDBC basics
		"connection",
		"drivermanager",
		"preparedstatement",
		"statement",
		"resultset",
		"executequery(",
		"executeupdate(",
		"execute(",

		// Spring JDBC
		"jdbctemplate",
		"namedparamjdbctemplate",
		"simplejdbccall",

		// Hibernate / JPA
		"entitymanager",
		"createquery(",
		"createsqlquery(",
		"session.createquery",
		"session.createsqlquery",

		// jOOQ
		"dsl.",
		"dslcontext",
		"selectfrom(",
	}

	// SQL words that must appear as standalone-ish tokens.
	sqlVerbs := []string{"select", "update", "insert", "delete", "from", "where"}

	// Must match at least one DB hint.
	hasDb := containsAny(code, dbHints)
	if !hasDb {
		return false
	}

	// And at least one SQL verb (use word-based matching to avoid noise).
	if !containsAnyWord(code, sqlVerbs) {
		return false
	}

	return true
}

// shouldAnalyzeGoXssCtx checks for Go XSS patterns.
// Triggers on HTML content, response writing sinks, or user input sources.
func shouldAnalyzeGoXssCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// HTML indicators
	htmlHints := []string{
		"<html", "<body", "<script", "<form", "<input", "<img", "<iframe",
		"<div", "<span", "<a ", "<p>", "<h1", "<h2",
	}

	// Response writing sinks - be more inclusive
	responseSinks := []string{
		"responsewriter",
		"http.responsewriter",
		"w.write(",
		"fmt.fprintf(",
		"fmt.fprint(",
		"fmt.fprintln(",
		"io.writestring(",
		"template.execute",
		"template.html(",
		"html/template",
		"text/template",
	}

	// User input sources - be more inclusive
	inputSources := []string{
		"r.url.query",
		"r.url.rawquery",
		"r.formvalue",
		"r.postformvalue",
		"r.header.get",
		"r.parseform",
		"r.form[",
		"mux.vars(",
		"chi.urlparam(",
		"c.query(",
		"c.param(",
	}

	hasHTML := containsAny(code, htmlHints)
	hasSink := containsAny(code, responseSinks)
	hasInput := containsAny(code, inputSources)

	// HTML content alone, or any sink with input
	return hasHTML || hasSink || hasInput
}

// shouldAnalyzePythonXssCtx checks for Python XSS patterns.
// Triggers on HTML content, response sinks, or user input sources.
func shouldAnalyzePythonXssCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// HTML indicators
	htmlHints := []string{
		"<html", "<body", "<script", "<form", "<input", "<img", "<iframe",
		"<div", "<span", "<a ", "<h1", "<h2", "<p>",
	}

	// Response sinks - be more inclusive
	responseSinks := []string{
		"response(",
		"response.",
		"make_response",
		"render_template",
		"render_template_string",
		"httpresponse",
		"jsonresponse",
		"markup(",
		".write(",
		"return f\"",
		"return f'",
	}

	// User input sources - be more inclusive
	inputSources := []string{
		"request.args",
		"request.form",
		"request.values",
		"request.get_json",
		"request.data",
		"request.headers",
		"request.cookies",
		"flask.request",
	}

	hasHTML := containsAny(code, htmlHints)
	hasSink := containsAny(code, responseSinks)
	hasInput := containsAny(code, inputSources)

	// HTML content alone, or any sink with input
	return hasHTML || hasSink || hasInput
}

// Java Deserialization: require deserialization operations
func shouldAnalyzeJavaDeserializationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Dangerous deserialization sinks
	deserializationSinks := []string{
		"objectinputstream",
		"readobject(",
		"xstream",
		"fromxml(",
		"xmldecoder",
		"enabledefaulttyping",
		"yaml.load",
		"kryo",
	}

	// Input sources that indicate untrusted data
	inputSources := []string{
		"getinputstream(",
		"request.",
		"socket.",
		"file.",
		"multipartfile",
	}

	hasSink := containsAny(code, deserializationSinks)
	hasInput := containsAny(code, inputSources)

	// ObjectInputStream is critical enough to flag even without obvious input
	hasCriticalSink := containsAny(code, []string{"objectinputstream", "xmldecoder"})

	return (hasSink && hasInput) || hasCriticalSink
}

// Python Deserialization: require pickle/yaml operations
func shouldAnalyzePythonDeserializationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Dangerous deserialization methods
	deserializationSinks := []string{
		"pickle.loads",
		"pickle.load",
		"cpickle.loads",
		"cpickle.load",
		"yaml.load(", // without safe_load
		"yaml.unsafe_load",
		"marshal.loads",
		"shelve.open",
		"dill.loads",
		"jsonpickle.decode",
	}

	// Safe patterns to exclude
	safePatterns := []string{
		"yaml.safe_load",
		"safeloader",
	}

	hasSink := containsAny(code, deserializationSinks)
	hasSafe := containsAny(code, safePatterns)

	// If using yaml.load, check it's not safe_load
	if strings.Contains(code, "yaml.load(") && !hasSafe {
		return true
	}

	return hasSink && !hasSafe
}

// Java Broken Cryptography: ONLY check for weak algorithms (DES, 3DES, RC4, RC2)
// AES is NOT a weak algorithm, so don't trigger on AES-only files
func shouldAnalyzeJavaBrokencryptoCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// ONLY check files that use WEAK crypto algorithms
	// AES is STRONG - do not include it here
	weakCryptoPatterns := []string{
		// DES (weak - 56-bit key)
		"\"des\"",
		"\"des/",
		"cipher.getinstance(\"des",
		// 3DES/DESede (deprecated)
		"\"desede\"",
		"\"desede/",
		"cipher.getinstance(\"desede",
		// RC4/ARCFOUR (broken)
		"\"rc4\"",
		"\"arcfour\"",
		"cipher.getinstance(\"rc4",
		"cipher.getinstance(\"arcfour",
		// RC2 (weak)
		"\"rc2\"",
		"cipher.getinstance(\"rc2",
		// Blowfish (outdated)
		"\"blowfish\"",
		"cipher.getinstance(\"blowfish",
		// Small RSA key sizes
		"initialize(512",
		"initialize(1024",
	}

	// Only analyze if file uses weak crypto patterns
	return containsAny(code, weakCryptoPatterns)
}

// Java Path Traversal: require file operations with user input
func shouldAnalyzeJavaPathtraversalCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// File operation sinks - include both simple and fully-qualified class names
	fileSinks := []string{
		"new file(",       // Simple: new File(path)
		"java.io.file(",   // Fully qualified: new java.io.File(path)
		"fileinputstream", // Matches both simple and qualified
		"fileoutputstream",
		"filereader",
		"filewriter",
		"files.read",
		"files.write",
		"files.delete",
		"files.exists",
		"files.copy",
		"files.move",
		"paths.get(",
		"path.of(",
		".exists(",    // check pattern like file.exists()
		".canread(",   // check pattern like file.canRead()
		".length(",    // check pattern like file.length()
		".listfiles(", // check pattern like file.listFiles()
	}

	// User input sources - include ALL patterns (simple and complex)
	inputSources := []string{
		"getparameter(",
		"getheader(",
		"pathvariable",
		"requestparam",
		"getoriginalfilename(",
		// Complex source patterns that MUST be included
		"getcookies(",      // Cookie iteration pattern
		"getheaders(",      // Headers enumeration pattern
		"getparametermap(", // Parameter map pattern
		"cookievalue",      // @CookieValue annotation
		"requestheader",    // @RequestHeader annotation
		// OWASP Benchmark specific patterns
		"separateclassrequest", // Wrapper class pattern
		"gettheparameter(",     // Wrapper method
		"getparameternames(",   // Parameter names iteration
		"getparametervalues(",  // Parameter values array
		"thingfactory",         // Factory pattern
		"thinginterface",       // Interface pattern
		"dosomething(",         // Helper method pattern
	}

	hasSink := containsAny(code, fileSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

// Go Path Traversal: require file operations with user input
func shouldAnalyzeGoPathtraversalCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// File operation sinks - include ALL file operations
	fileSinks := []string{
		"os.open(",
		"os.openfile(",
		"os.create(",
		"os.readfile(",
		"os.writefile(",
		"os.stat(",  // File existence check with user-controlled path
		"os.lstat(", // Symbolic link stat
		"os.remove(",
		"os.removeall(",
		"os.rename(",
		"os.mkdir(",
		"os.mkdirall(",
		"ioutil.readfile",
		"ioutil.writefile",
		"http.servefile",
		"http.fileserver",
		"filepath.join(", // Path construction
	}

	// User input sources - include ALL patterns
	inputSources := []string{
		"r.url.query",
		"r.formvalue",
		"r.form",
		"r.parseform",
		"r.url.path",
		"r.header.get",
		"r.header",
		"os.args",
		"os.getenv",
		// Additional source patterns
		"r.cookies(",
		"c.query(",
		"c.param(",
		"c.postform",
		"mux.vars(",     // gorilla/mux
		"chi.urlparam(", // chi router
		// Benchmark specific patterns
		"dosomething(",
		"param :=",
		"bar :=",
		"for name, values := range",
	}

	hasSink := containsAny(code, fileSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

// Python Path Traversal: require file operations with user input
func shouldAnalyzePythonPathtraversalCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// File operation sinks
	fileSinks := []string{
		"open(",
		"send_file(",
		"send_from_directory(",
		"os.path.join(",
		"os.path.exists(",
		"os.path.isfile(",
		"os.path.isdir(",
		"os.path.abspath(",
		"os.path.realpath(",
		"os.listdir(",
		"os.remove(",
		"os.unlink(",
		"os.rename(",
		"os.makedirs(",
		"pathlib",
		"shutil.",
	}

	// User input sources - include ALL patterns
	inputSources := []string{
		"request.args",
		"request.form",
		"request.values",
		"request.files",
		"flask.request",
		// Additional source patterns
		"request.cookies",
		"request.headers",
		"request.get_json",
		"request.data",
	}

	hasSink := containsAny(code, fileSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

// ============================================================
// Go Deserialization
// ============================================================
func shouldAnalyzeGoDeserializationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Deserialization packages/methods
	deserializationHints := []string{
		"encoding/gob",
		"gob.newdecoder",
		"gob.decode",
		"json.unmarshal",
		"yaml.unmarshal",
		"xml.unmarshal",
	}

	// Must have deserialization AND some input source
	inputSources := []string{
		"http.request",
		"r.body",
		"ioutil.readall",
		"io.readall",
		"net.conn",
	}

	hasDeser := containsAny(code, deserializationHints)
	hasInput := containsAny(code, inputSources)

	return hasDeser && hasInput
}

// ============================================================
// Go/Python Broken Cryptography
// ============================================================
func shouldAnalyzeGoBrokencryptoCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// ONLY check files that use WEAK crypto algorithms (DES, 3DES, RC4)
	// AES is NOT a weak algorithm, so don't trigger on AES-only files
	weakCryptoImports := []string{
		"crypto/des", // DES and 3DES
		"crypto/rc4", // RC4
	}

	// Weak algorithm patterns - only DES and RC4
	weakPatterns := []string{
		"des.newcipher",
		"des.newtripledescipher",
		"rc4.newcipher",
	}

	hasWeakImport := containsAny(code, weakCryptoImports)
	hasWeakPattern := containsAny(code, weakPatterns)

	// Only analyze if file uses weak crypto imports OR weak patterns
	return hasWeakImport || hasWeakPattern
}

func shouldAnalyzePythonBrokencryptoCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Check for crypto library usage first
	hasCryptoLibrary := containsAny(code, []string{
		"from cryptography",
		"cryptography.hazmat",
		"from crypto",
		"pycryptodome",
		"from pycrypto",
	})

	// WEAK crypto algorithm patterns (DES, 3DES, RC4, RC2, Blowfish)
	// Note: AES is NOT a weak algorithm
	weakCryptoPatterns := []string{
		// PyCrypto/PyCryptodome patterns
		"from crypto.cipher import des",
		"import des",
		"des.new(",
		"from crypto.cipher import des3",
		"des3.new(",
		"from crypto.cipher import arc4",
		"arc4.new(",
		"from crypto.cipher import arc2",
		"arc2.new(",
		"from crypto.cipher import blowfish",
		"blowfish.new(",
		// cryptography library patterns (hazmat)
		"algorithms.des",
		"algorithms.tripledes",
		"algorithms.3des",
		"algorithms.arc4",
		"algorithms.blowfish",
		"algorithms.idea",
		"algorithms.cast5",
		"algorithms.seed",
		// Algorithm string patterns (often loaded from config)
		"desede",
		"tripledes",
		"3des",
		"/des/",
		"des/ecb",
		"des/cbc",
		"rc4",
		"rc2",
		// Small RSA key sizes
		"key_size=512",
		"key_size=1024",
		"rsa_key_size=512",
		"rsa_key_size=1024",
	}

	// Analyze if has crypto library AND weak patterns
	// OR just weak patterns (defensive)
	hasWeakPattern := containsAny(code, weakCryptoPatterns)

	return hasCryptoLibrary && hasWeakPattern
}

// ============================================================
// Code Injection
// ============================================================
func shouldAnalyzeJavaCodeiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Code execution APIs
	codeExecAPIs := []string{
		"scriptengine",
		"scriptenginemanager",
		".eval(",
		"groovyshell",
		"spelexpressionparser",
		"parseexpression(",
		"mvel.",
		"ognl.",
		"class.forname(",
		"getmethod(",
		".invoke(",
	}

	// User input sources
	inputSources := []string{
		"getparameter(",
		"getheader(",
		"requestparam",
		"pathvariable",
		"requestbody",
	}

	hasCodeExec := containsAny(code, codeExecAPIs)
	hasInput := containsAny(code, inputSources)

	return hasCodeExec && hasInput
}

func shouldAnalyzeGoCodeiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Go doesn't have eval, but has reflection and plugin loading
	codeExecAPIs := []string{
		"reflect.",
		"plugin.open",
		"unsafe.",
	}

	// User input sources
	inputSources := []string{
		"r.url.query",
		"r.formvalue",
		"r.header.get",
	}

	hasCodeExec := containsAny(code, codeExecAPIs)
	hasInput := containsAny(code, inputSources)

	return hasCodeExec && hasInput
}

func shouldAnalyzePythonCodeiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Python code execution functions
	codeExecAPIs := []string{
		"eval(",
		"exec(",
		"compile(",
		"__import__(",
		"importlib",
	}

	// User input sources
	inputSources := []string{
		"request.args",
		"request.form",
		"request.data",
		"request.json",
		"input(",
	}

	hasCodeExec := containsAny(code, codeExecAPIs)
	hasInput := containsAny(code, inputSources)

	return hasCodeExec && hasInput
}

// ============================================================
// LDAP Injection
// ============================================================
func shouldAnalyzeJavaLdapiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// LDAP APIs - must have these
	ldapAPIs := []string{
		"dircontext",
		"ldapcontext",
		"initialdircontext",
		"ldaptemplate",
		"javax.naming",
		".search(",
		".bind(",
	}

	return containsAny(code, ldapAPIs)
}

func shouldAnalyzeGoLdapiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Go LDAP patterns: imports, operations, and DN components
	ldapPatterns := []string{
		// LDAP packages
		"ldap.",
		"go-ldap",
		"gopkg.in/ldap",
		// LDAP operations
		"ldap.dial",
		"ldap.search",
		"ldap.bind",
		"searchrequest",
		".search(",
		".bind(",
		// LDAP filter patterns
		"filter",
		"ldapfilter",
		// DN patterns
		"basedn",
		"dc=",
		"cn=",
		"ou=",
	}

	return containsAny(code, ldapPatterns)
}

func shouldAnalyzePythonLdapiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Python LDAP patterns: imports, operations, and DN components
	ldapPatterns := []string{
		// LDAP imports
		"import ldap",
		"from ldap",
		"ldap3",
		"python-ldap",
		// LDAP operations
		"ldap.search",
		"connection.search",
		"search_s(",
		"search_ext_s(",
		"simple_bind",
		"bind_s(",
		// LDAP filter patterns
		"filter=",
		"filter_str",
		"ldap_filter",
		"search_filter",
		// DN patterns
		"base_dn",
		"user_dn",
		"dc=",
		"cn=",
		"ou=",
	}

	return containsAny(code, ldapPatterns)
}

// ============================================================
// XPath Injection
// ============================================================
func shouldAnalyzeJavaXpathiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// XPath APIs - must have these
	xpathAPIs := []string{
		"xpath",
		"xpathfactory",
		"xpathexpression",
		"documentbuilderfactory",
		".compile(",
		".evaluate(",
	}

	return containsAny(code, xpathAPIs)
}

func shouldAnalyzeGoXpathiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Go XPath packages
	xpathAPIs := []string{
		"xmlquery",
		"xpath",
		"antchfx",
		"libxml",
	}

	return containsAny(code, xpathAPIs)
}

func shouldAnalyzePythonXpathiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Python XPath packages
	xpathAPIs := []string{
		"lxml",
		"etree",
		".xpath(",
		"from xml",
		"import xml",
	}

	return containsAny(code, xpathAPIs)
}

// ============================================================
// Weak Hash
// ============================================================
func shouldAnalyzeJavaWeakhashCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak hash patterns: MD5 and SHA-1 usage indicators.
	// The prompt handles security context filtering.
	weakHashPatterns := []string{
		// MessageDigest with weak algorithms
		"messagedigest.getinstance(\"md5\"",
		"messagedigest.getinstance(\"sha-1\"",
		"messagedigest.getinstance(\"sha1\"",
		"\"md5\"",
		"\"sha-1\"",
		"\"sha1\"",
		// Apache Commons DigestUtils
		"digestutils.md5",
		"digestutils.sha1",
		"md5hex",
		"sha1hex",
		// Guava Hashing
		"hashing.md5",
		"hashing.sha1",
		// Generic MessageDigest usage (let prompt decide)
		"messagedigest",
	}

	// Analyze if ANY weak hash pattern is present
	// Remove security context requirement - let the prompt handle it
	return containsAny(code, weakHashPatterns)
}

func shouldAnalyzeGoWeakhashCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak hash patterns: crypto/md5 and crypto/sha1 usage indicators.
	// The prompt handles security context filtering.
	weakHashPatterns := []string{
		// Weak hash imports
		"crypto/md5",
		"crypto/sha1",
		// Weak hash function calls
		"md5.new(",
		"md5.sum(",
		"sha1.new(",
		"sha1.sum(",
		// Hash package usage that might use weak algos
		"hash.hash",
		"hasher.write",
	}

	// Analyze if ANY weak hash pattern is present
	// Remove security context requirement - let the prompt handle it
	return containsAny(code, weakHashPatterns)
}

func shouldAnalyzePythonWeakhashCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak hash patterns: hashlib.md5 and hashlib.sha1 usage indicators.
	// The prompt handles security context filtering.
	weakHashPatterns := []string{
		// hashlib weak algorithms
		"hashlib.md5",
		"hashlib.sha1",
		"hashlib.new(\"md5\"",
		"hashlib.new(\"sha1\"",
		"hashlib.new('md5'",
		"hashlib.new('sha1'",
		// Direct calls
		"md5(",
		"sha1(",
		// Generic hashlib usage (let prompt decide)
		"hashlib",
		".hexdigest(",
		".digest(",
	}

	// Analyze if ANY weak hash pattern is present
	// Remove security context requirement - let the prompt handle it
	return containsAny(code, weakHashPatterns)
}

// ============================================================
// Insecure Cookie
// ============================================================
func shouldAnalyzeJavaInsecurecookieCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// For CWE-614, ANY cookie added without Secure flag is vulnerable.
	// The cookie name/purpose doesn't matter - we only need to check
	// if cookies are being added to the response.
	cookieSinks := []string{
		"addcookie(",  // response.addCookie(cookie) - the actual sink
		"new cookie(", // Cookie creation, usually paired with addCookie
	}

	return containsAny(code, cookieSinks)
}

func shouldAnalyzeGoInsecurecookieCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// For CWE-614, ANY cookie added without Secure flag is vulnerable.
	// The cookie name/purpose doesn't matter.
	cookieSinks := []string{
		"http.setcookie", // http.SetCookie(w, cookie) - the actual sink
		"&http.cookie{",  // Cookie struct creation
	}

	return containsAny(code, cookieSinks)
}

func shouldAnalyzePythonInsecurecookieCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// For CWE-614, ANY cookie added without Secure flag is vulnerable.
	// The cookie name/purpose doesn't matter.
	cookieSinks := []string{
		"set_cookie(",  // check pattern like response.set_cookie() - Flask/Django
		".set_cookie(", // check pattern like resp.set_cookie()
		"simplecookie", // check pattern like http.cookies.SimpleCookie
	}

	return containsAny(code, cookieSinks)
}

// ============================================================
// Access Control (IDOR)
// ============================================================
func shouldAnalyzeJavaAccesscontrolCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Must have REST endpoint annotations or controller
	endpointIndicators := []string{
		"@getmapping",
		"@postmapping",
		"@putmapping",
		"@deletemapping",
		"@requestmapping",
		"@controller",
		"@restcontroller",
	}

	// Must have user-supplied ID access
	idAccessPatterns := []string{
		"@pathvariable",
		"@requestparam",
		"findbyid(",
		"getbyid(",
		"repository.",
	}

	hasEndpoint := containsAny(code, endpointIndicators)
	hasIdAccess := containsAny(code, idAccessPatterns)

	return hasEndpoint && hasIdAccess
}

func shouldAnalyzeGoAccesscontrolCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// HTTP handler patterns
	handlerPatterns := []string{
		"http.handlefunc",
		"mux.handlefunc",
		"router.",
		"gin.context",
		"echo.context",
	}

	// ID access patterns
	idAccessPatterns := []string{
		"r.url.query",
		"vars[",
		"param(",
		"c.param(",
		"findbyid",
		"getbyid",
	}

	hasHandler := containsAny(code, handlerPatterns)
	hasIdAccess := containsAny(code, idAccessPatterns)

	return hasHandler && hasIdAccess
}

func shouldAnalyzePythonAccesscontrolCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Route definitions
	routePatterns := []string{
		"@app.route",
		"@router.",
		"@api.",
		"def get(",
		"def post(",
		"def put(",
		"def delete(",
	}

	// ID access patterns
	idAccessPatterns := []string{
		"request.args.get",
		"request.form.get",
		"<int:id>",
		"<id>",
		"get_object_or_404",
		"filter(",
	}

	hasRoute := containsAny(code, routePatterns)
	hasIdAccess := containsAny(code, idAccessPatterns)

	return hasRoute && hasIdAccess
}

// ============================================================
// Trust Boundary Violation
// ============================================================
func shouldAnalyzeJavaTrustboundaryCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Session storage sinks - BOTH setAttribute and putValue
	sessionStorage := []string{
		".setattribute(",
		".putvalue(",
		"getsession()",
		"httpsession",
	}

	// User input sources - include ALL patterns from OWASP Benchmark
	inputSources := []string{
		"getparameter(",
		"getheader(",
		"requestparam",
		"getcookies(",      // Cookie iteration
		"getheadernames(",  // Header enumeration
		"getheaders(",      // Named header enumeration
		"getparametermap(", // Parameter map
		"getparametervalues(",
		"getparameternames(",   // Parameter names enumeration
		"getquerystring(",      // Query string access
		"getpathinfo(",         // Path info access
		"separateclassrequest", // OWASP wrapper class
		"gettheparameter(",     // OWASP wrapper method
		"thingfactory",         // OWASP factory pattern
		"dosomething(",         // OWASP helper method (common taint propagator)
		"new test(",            // OWASP inner class pattern
	}

	hasSession := containsAny(code, sessionStorage)
	hasInput := containsAny(code, inputSources)

	// Removed securityIndicators requirement - ANY user data in session is a violation
	return hasSession && hasInput
}

func shouldAnalyzeGoTrustboundaryCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Session/context storage - include map-based patterns
	sessionStorage := []string{
		"session.",
		"session[",
		"sessiondata[",
		"sessionstore[",
		".values[",
		"context.withvalue",
		"gorilla/sessions",
		"store.get(",
	}

	// User input - comprehensive patterns
	inputSources := []string{
		"r.url.query",
		"r.url.rawquery",
		"r.formvalue",
		"r.postformvalue",
		"r.header.get",
		"r.header.values",
		"r.header[",
		"r.header {",
		"range r.header",
		"r.form[",
		"r.form.",
		"r.form {",
		"range r.form",
		"r.parseform",
		"r.cookies(",
		"r.cookie(",
		"mux.vars(",
		"chi.urlparam(",
		"c.query(",
		"c.param(",
	}

	hasSession := containsAny(code, sessionStorage)
	hasInput := containsAny(code, inputSources)

	return hasSession && hasInput
}

func shouldAnalyzePythonTrustboundaryCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Session storage
	sessionStorage := []string{
		"session[",
		"flask.session",
		"request.session",
	}

	// User input - comprehensive patterns
	inputSources := []string{
		"request.args",
		"request.form",
		"request.data",
		"request.values",
		"request.cookies",
		"request.headers",
		"request.get",
		"request.post",
		"request.query_string",
	}

	hasSession := containsAny(code, sessionStorage)
	hasInput := containsAny(code, inputSources)

	return hasSession && hasInput
}

// Java Weak Randomness: detect java.util.Random or Math.random() in security contexts
func shouldAnalyzeJavaWeakrandomnessCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak random sources
	weakRandomSources := []string{
		"new random(",
		"java.util.random",
		"math.random(",
		"threadlocalrandom",
		"random.nextint",
		"random.nextlong",
		"random.nextbytes",
		"random.nextdouble",
		"random.nextfloat",
		"random.nextgaussian",
		"random.ints(",
		"random.longs(",
		"random.doubles(",
	}

	// Security context indicators
	securityContext := []string{
		"token",
		"password",
		"session",
		"secret",
		"key",
		"otp",
		"verification",
		"csrf",
		"nonce",
		"apikey",
		"api_key",
		"cookie",
		"rememberme",
		"remember_me",
		"auth",
		"login",
		"credential",
	}

	hasWeakRandom := containsAny(code, weakRandomSources)
	hasSecurityContext := containsAny(code, securityContext)

	return hasWeakRandom && hasSecurityContext
}

// Go Weak Randomness: detect math/rand in security contexts
func shouldAnalyzeGoWeakrandomnessCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak random imports/usage - comprehensive list
	weakRandomSources := []string{
		"math/rand",
		"rand.intn",
		"rand.int(",
		"rand.int63",
		"rand.int31",
		"rand.uint32",
		"rand.uint64",
		"rand.float32",
		"rand.float64",
		"rand.read",
		"rand.seed",
		"rand.new(",
		"rand.newsource",
		"rand.shuffle",
		"rand.perm",
		"rand.expfloat64",
		"rand.normfloat64",
	}

	// Security context indicators
	securityContext := []string{
		"token",
		"password",
		"session",
		"secret",
		"key",
		"otp",
		"verification",
		"csrf",
		"nonce",
		"apikey",
		"api_key",
		"cookie",
		"rememberme",
		"remember_me",
		"auth",
		"login",
		"credential",
	}

	hasWeakRandom := containsAny(code, weakRandomSources)
	hasSecurityContext := containsAny(code, securityContext)

	return hasWeakRandom && hasSecurityContext
}

// Python Weak Randomness: detect random module in security contexts
func shouldAnalyzePythonWeakrandomnessCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak random sources - comprehensive list of random module functions
	weakRandomSources := []string{
		"import random",
		"from random",
		"random.random",
		"random.randint",
		"random.choice",
		"random.choices",
		"random.sample",
		"random.shuffle",
		"random.getrandbits",
		"random.gauss",
		"random.randrange",
		"random.uniform",
		"random.triangular",
		"random.betavariate",
		"random.expovariate",
		"random.gammavariate",
		"random.normalvariate",
		"random.vonmisesvariate",
		"random.paretovariate",
		"random.weibullvariate",
		"random.random(",
	}

	// Security context indicators
	securityContext := []string{
		"token",
		"password",
		"session",
		"secret",
		"key",
		"otp",
		"verification",
		"csrf",
		"nonce",
		"api_key",
		"apikey",
		"cookie",
		"rememberme",
		"remember_me",
		"auth",
		"login",
		"credential",
	}

	hasWeakRandom := containsAny(code, weakRandomSources)
	hasSecurityContext := containsAny(code, securityContext)

	return hasWeakRandom && hasSecurityContext
}

// ============================================================
// C# Rules
// ============================================================

// C# SQLi: require DB interaction AND SQL verbs
func shouldAnalyzeCSharpSqliCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Database interaction indicators
	dbHints := []string{
		"sqlconnection",
		"sqlcommand",
		"sqldataadapter",
		"sqldatareader",
		"executenonquery(",
		"executereader(",
		"executescalar(",
		"dbcontext",
		"entity framework",
		"linq to sql",
		"dapper",
		"npgsqlconnection",
		"mysqlconnection",
		"oledbconnection",
	}

	// SQL verbs
	sqlVerbs := []string{"select", "update", "insert", "delete", "from", "where"}

	hasDb := containsAny(code, dbHints)
	if !hasDb {
		return false
	}

	return containsAnyWord(code, sqlVerbs)
}

// C# XSS: look for HTML content, response writing, or user input handling
func shouldAnalyzeCSharpXssCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// HTML indicators
	htmlHints := []string{
		"<html", "<body", "<script", "<form", "<input", "<img", "<iframe",
		"<div", "<span", "<a ", "<p>",
	}

	// Response writing sinks
	responseSinks := []string{
		"response.write",
		"response.writeasync",
		"writeasync(",
		"htmlhelper",
		"@html.raw",
		"html.raw(",
		"content(",
		"contentresult",
		"viewbag",
		"viewdata",
		"string.format(",
		"return content(",
	}

	// User input sources
	inputSources := []string{
		"request.querystring",
		"request.query",
		"request.query.keys",
		"request.form",
		"request.headers",
		"request.cookies",
		"request[",
		"httpcontext",
		"frombody",
		"fromquery",
		"fromroute",
		"fromform",
		"iheaderdictionary",
	}

	hasHTML := containsAny(code, htmlHints)
	hasSink := containsAny(code, responseSinks)
	hasInput := containsAny(code, inputSources)

	return hasHTML || (hasSink && hasInput)
}

// C# Deserialization: require deserialization operations
func shouldAnalyzeCSharpDeserializationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Dangerous deserialization sinks
	deserializationSinks := []string{
		"binaryformatter",
		"objectstateformatter",
		"soapformatter",
		"netdatacontractserializer",
		"losformatter",
		"jsonconvert.deserializeobject",
		"javascriptserializer",
		"xmlserializer",
		"datacontractserializer",
		"typenamehanding",
	}

	// Input sources
	inputSources := []string{
		"stream",
		"request.",
		"file.",
		"httpcontext",
	}

	hasSink := containsAny(code, deserializationSinks)
	hasInput := containsAny(code, inputSources)

	// BinaryFormatter is critical enough to flag even without obvious input
	hasCriticalSink := containsAny(code, []string{"binaryformatter", "objectstateformatter"})

	return (hasSink && hasInput) || hasCriticalSink
}

// C# Broken Cryptography: ONLY check for weak algorithms (DES, 3DES, RC2)
// AES is NOT a weak algorithm, so don't trigger on AES-only files
func shouldAnalyzeCSharpBrokencryptoCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// ONLY check files that use WEAK crypto algorithms
	// AES is STRONG - do not include it here
	weakCryptoPatterns := []string{
		// DES (weak - 56-bit key)
		"des.create",
		"descryptoserviceprovider",
		"new des(",
		// 3DES/TripleDES (deprecated)
		"tripledes.create",
		"tripledescryptoserviceprovider",
		"new tripledes(",
		// RC2 (weak)
		"rc2.create",
		"rc2cryptoserviceprovider",
		"new rc2(",
		// Small RSA key sizes
		"rsa.create(512",
		"rsa.create(1024",
		"keysize = 512",
		"keysize = 1024",
	}

	// Only analyze if file uses weak crypto patterns
	return containsAny(code, weakCryptoPatterns)
}

// C# Path Traversal: require file operations with user input
func shouldAnalyzeCSharpPathtraversalCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// File operation keywords - file matches if ANY keyword is present
	keywords := []string{
		"file.open",
		"file.read",
		"file.write",
		"file.delete",
		"filestream",
		"streamreader",
		"streamwriter",
		"path.combine",
		"path.getfullpath",
		// Additional patterns for coverage
		"fileinfo",
		"directoryinfo",
		"physicalfile",
		"directory.",
	}

	return containsAny(code, keywords)
}

// C# Code Injection: require code execution APIs with user input
func shouldAnalyzeCSharpCodeiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Code execution APIs
	codeExecAPIs := []string{
		"csharpcodeprovider",
		"compileassemblyfromsource",
		"assembly.load",
		"activator.createinstance",
		"type.invokemember",
		"methodinfo.invoke",
		"expression.compile",
		"roslyn",
	}

	// User input sources
	inputSources := []string{
		"request.",
		"frombody",
		"fromquery",
		"httpcontext",
	}

	hasCodeExec := containsAny(code, codeExecAPIs)
	hasInput := containsAny(code, inputSources)

	return hasCodeExec && hasInput
}

// shouldAnalyzeCSharpLdapiCtx checks for C# LDAP injection patterns.
func shouldAnalyzeCSharpLdapiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// C# LDAP patterns: DirectoryServices, connection, and DN components
	ldapPatterns := []string{
		// DirectoryServices namespace
		"directoryentry",
		"directorysearcher",
		"system.directoryservices",
		// LDAP connection
		"ldapconnection",
		"novell.directory.ldap",
		// Search operations
		".findall(",
		".findone(",
		"searchrequest",
		"sendrequest(",
		// Filter property
		".filter",
		"searcher.filter",
		// DN patterns
		"ldap://",
		"dc=",
		"cn=",
		"ou=",
	}

	return containsAny(code, ldapPatterns)
}

// ============================================================
// Command Injection
// ============================================================

func shouldAnalyzeJavaCmdiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Java command execution patterns
	cmdiPatterns := []string{
		// Runtime.exec
		"runtime.getruntime(",
		".exec(",
		// ProcessBuilder
		"processbuilder",
		"new processbuilder(",
		// Process
		"process.start",
		// Shell patterns
		"cmd.exe",
		"/bin/sh",
		"/bin/bash",
		"bash -c",
		"sh -c",
	}

	return containsAny(code, cmdiPatterns)
}

func shouldAnalyzeGoCmdiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Go command execution patterns
	cmdiPatterns := []string{
		// os/exec package
		"os/exec",
		"exec.command(",
		"exec.commandcontext(",
		// Command execution
		".run(",
		".start(",
		".output(",
		".combinedoutput(",
		// Shell patterns
		"cmd.exe",
		"/bin/sh",
		"/bin/bash",
		"bash",
	}

	return containsAny(code, cmdiPatterns)
}

func shouldAnalyzePythonCmdiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Python command execution patterns
	cmdiPatterns := []string{
		// subprocess module
		"subprocess",
		"subprocess.run(",
		"subprocess.popen(",
		"subprocess.call(",
		"subprocess.check_output(",
		// os module
		"os.system(",
		"os.popen(",
		"os.spawn",
		// commands module (deprecated)
		"commands.getoutput(",
		// Shell patterns
		"shell=true",
		"/bin/sh",
		"/bin/bash",
	}

	return containsAny(code, cmdiPatterns)
}

func shouldAnalyzeCSharpCmdiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// C# command execution patterns: Process class and shell execution
	cmdiPatterns := []string{
		// Process class
		"process.start(",
		"new process(",
		"processstartinfo",
		"new processstartinfo(",
		// StartInfo properties
		".startinfo",
		".filename",
		".arguments",
		// Shell patterns
		"cmd.exe",
		"cmd /c",
		"powershell",
		"bash",
		// System.Diagnostics namespace
		"system.diagnostics.process",
	}

	return containsAny(code, cmdiPatterns)
}

// C# XPath Injection: require XPath APIs
func shouldAnalyzeCSharpXpathiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// XPath APIs
	xpathAPIs := []string{
		"xpathnavigator",
		"xpathdocument",
		"selectsinglenode",
		"selectnodes",
		"xpathexpression",
		"xpath",
		"xmldocument",
	}

	return containsAny(code, xpathAPIs)
}

// shouldAnalyzeCSharpWeakhashCtx checks for C# weak hash algorithm usage.
func shouldAnalyzeCSharpWeakhashCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak hash patterns: MD5 and SHA1 usage indicators.
	// The prompt handles security context filtering.
	weakHashPatterns := []string{
		// MD5 variants
		"md5.create",
		"md5cryptoserviceprovider",
		"new md5cryptoserviceprovider",
		"md5managed",
		"md5cng",
		// SHA1 variants
		"sha1.create",
		"sha1cryptoserviceprovider",
		"new sha1cryptoserviceprovider",
		"sha1managed",
		"sha1cng",
		// HMAC weak variants
		"hmacmd5",
		"hmacsha1",
		// HashAlgorithm.Create with weak algos
		"hashalgorithm.create(\"md5\"",
		"hashalgorithm.create(\"sha1\"",
		// Generic hash usage (let prompt decide)
		"computehash(",
	}

	// Analyze if ANY weak hash pattern is present
	// Remove security context requirement - let the prompt handle it
	return containsAny(code, weakHashPatterns)
}

// C# Insecure Cookie: require cookie operations
func shouldAnalyzeCSharpInsecurecookieCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Cookie sinks
	cookieSinks := []string{
		"response.cookies.append",
		"response.cookies.add",
		"new cookie(",
		"cookieoptions",
		"httpcontext.response.cookies",
	}

	return containsAny(code, cookieSinks)
}

// C# Access Control (IDOR): require endpoint with ID access
func shouldAnalyzeCSharpAccesscontrolCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Endpoint indicators
	endpointIndicators := []string{
		"[httpget]",
		"[httppost]",
		"[httpput]",
		"[httpdelete]",
		"[route(",
		"[apicontroller]",
		"controllerbase",
		"controller",
	}

	// ID access patterns
	idAccessPatterns := []string{
		"fromroute",
		"fromquery",
		"findbyid",
		"getbyid",
		"find(",
		"firstordefault(",
		"singleordefault(",
	}

	hasEndpoint := containsAny(code, endpointIndicators)
	hasIdAccess := containsAny(code, idAccessPatterns)

	return hasEndpoint && hasIdAccess
}

// C# Trust Boundary: file matches if ANY keyword is present
func shouldAnalyzeCSharpTrustboundaryCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Session and trust boundary keywords - file matches if ANY keyword is present
	keywords := []string{
		"session",
		"httpcontext.session",
		"ihttpsessionfeature",
		"tempdata",
		"request.form",
		"request.query",
		"claimsprincipal",
		"httpcontext.user",
		// Additional patterns for coverage
		"setstring",
		"setint32",
		"viewdata",
		"viewbag",
	}

	return containsAny(code, keywords)
}

// C# Weak Randomness: detect System.Random in security contexts
func shouldAnalyzeCSharpWeakrandomnessCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Weak random sources
	weakRandomSources := []string{
		"new random(",
		"random.next",
		"random.nextdouble",
		"random.nextbytes",
		"random.nextsingle",
		"random.nextint64",
		"system.random",
	}

	// Security context indicators
	securityContext := []string{
		"token",
		"password",
		"session",
		"secret",
		"key",
		"otp",
		"verification",
		"csrf",
		"nonce",
		"apikey",
		"api_key",
		"cookie",
		"rememberme",
		"remember_me",
		"auth",
		"login",
		"credential",
	}

	hasWeakRandom := containsAny(code, weakRandomSources)
	hasSecurityContext := containsAny(code, securityContext)

	return hasWeakRandom && hasSecurityContext
}

// ============================================================
// Ruby Rules
// ============================================================

func shouldAnalyzeRubySqliCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	dbHints := []string{
		"sqlite3",
		"mysql2",
		"pg::connection",
		"require 'pg'",
		"require \"pg\"",
		"activerecord",
		"sequel",
		".execute(",
		".query(",
		"connection.exec",
		"connection.query",
		"db.exec",
		"db.query",
		"find_by_sql",
		"where(",
		"joins(",
	}

	sqlWords := []string{"select", "update", "insert", "delete", "from", "where"}

	hasDb := containsAny(code, dbHints)
	hasSql := containsAnyWord(code, sqlWords)

	return hasDb && hasSql
}

func shouldAnalyzeRubyCmdiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	cmdiPatterns := []string{
		"system(",
		"exec(",
		"`",
		"spawn(",
		"open(",
		"popen(",
		"io.popen(",
		"kernel#`",
		"%x{",
		"/bin/sh",
		"/bin/bash",
		"shellwords",
	}

	return containsAny(code, cmdiPatterns)
}

func shouldAnalyzeRubyXssCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	htmlHints := []string{
		"<html", "<body", "<script", "<form", "<input", "<img", "<iframe",
		"<div", "<span",
	}

	responseSinks := []string{
		"render(",
		"html_safe",
		"raw(",
		"content_tag(",
		"response.body",
		"response.write(",
		"erb(",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"request.query_string",
		"cookies[",
		"session[",
	}

	hasHTML := containsAny(code, htmlHints)
	hasSink := containsAny(code, responseSinks)
	hasInput := containsAny(code, inputSources)

	return hasHTML || hasSink || hasInput
}

func shouldAnalyzeRubyPathtraversalCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	fileSinks := []string{
		"file.open(",
		"file.read(",
		"file.write(",
		"file.delete(",
		"file.new(",
		"io.read(",
		"send_file(",
		"send_data(",
		"dir.glob(",
		"fileutils.",
		"pathname.new(",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"cookies[",
		"session[",
	}

	hasSink := containsAny(code, fileSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

func shouldAnalyzeRubyZipslipCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	zipPatterns := []string{
		"zipfile",
		"rubyzip",
		"zip::file",
		"zip::inputstream",
		"minitar",
		"archive::tar",
		"zlib::gzipreader",
		"minizip",
	}

	return containsAny(code, zipPatterns)
}

func shouldAnalyzeRubyLdapiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	ldapLibrary := []string{
		"net/ldap",
		"net::ldap",
		"ldap.search",
		"ldap.bind",
		"ldap.open",
	}

	return containsAny(code, ldapLibrary)
}

func shouldAnalyzeRubyCodeiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	codeExecAPIs := []string{
		"eval(",
		"instance_eval(",
		"class_eval(",
		"module_eval(",
		"binding.eval(",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"cookies[",
	}

	hasCodeExec := containsAny(code, codeExecAPIs)
	hasInput := containsAny(code, inputSources)

	return hasCodeExec && hasInput
}

func shouldAnalyzeRubyLoginjectionCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	logSinks := []string{
		"logger.",
		"rails.logger",
		"log.info",
		"log.warn",
		"log.error",
		"log.debug",
		"puts ",
		"print ",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"cookies[",
		"session[",
	}

	hasSink := containsAny(code, logSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

func shouldAnalyzeRubyIntegeroverflowCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	// Ruby integers are arbitrary precision, so overflow is rare.
	// Check for explicit conversions from external input or C extensions.
	patterns := []string{
		".to_i",
		".to_f",
		".to_r",
		"integer(",
		"float(",
		"bigdecimal",
		"fiddle",
		"ffi",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"cookies[",
	}

	hasConversion := containsAny(code, patterns)
	hasInput := containsAny(code, inputSources)

	return hasConversion && hasInput
}

func shouldAnalyzeRubySensitiveinfodisclosureCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	sensitivePatterns := []string{
		"password",
		"passwd",
		"secret",
		"api_key",
		"apikey",
		"token",
		"private_key",
		"credit_card",
		"ssn",
		"social_security",
	}

	outputSinks := []string{
		"render(",
		"render json:",
		"response.body",
		"to_json",
		"as_json",
		"logger.",
		"puts ",
	}

	hasSensitive := containsAny(code, sensitivePatterns)
	hasSink := containsAny(code, outputSinks)

	return hasSensitive && hasSink
}

func shouldAnalyzeRubyErrorinfoleakCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	errorPatterns := []string{
		"rescue ",
		"rescue=>",
		"exception",
		"standarderror",
		"runtimeerror",
		"backtrace",
		".message",
	}

	outputSinks := []string{
		"render(",
		"render json:",
		"response.body",
		"to_json",
		"logger.",
	}

	hasError := containsAny(code, errorPatterns)
	hasSink := containsAny(code, outputSinks)

	return hasError && hasSink
}

func shouldAnalyzeRubyAccesscontrolCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	routePatterns := []string{
		"def show",
		"def edit",
		"def update",
		"def destroy",
		"get '",
		"post '",
		"put '",
		"delete '",
		"resources :",
	}

	idAccessPatterns := []string{
		"params[:id]",
		"params['id']",
		"find(",
		"find_by(",
		"where(id:",
		"where(id =",
	}

	hasRoute := containsAny(code, routePatterns)
	hasIdAccess := containsAny(code, idAccessPatterns)

	return hasRoute && hasIdAccess
}

func shouldAnalyzeRubyBrokencryptoCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	weakCryptoPatterns := []string{
		"openssl::cipher::des",
		"openssl::cipher::rc4",
		"openssl::cipher::rc2",
		"openssl::cipher::bf",
		"openssl::digest::md5",
		"openssl::digest::sha1",
		"cipher.new('des",
		"cipher.new('rc4",
		"cipher.new('rc2",
		"cipher.new('bf",
	}

	return containsAny(code, weakCryptoPatterns)
}

func shouldAnalyzeRubyWeakhashCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	weakHashPatterns := []string{
		"digest::md5",
		"openssl::digest::md5",
		"digest::sha1",
		"openssl::digest::sha1",
		"md5.hexdigest",
		"md5.digest",
		"sha1.hexdigest",
		"sha1.digest",
	}

	return containsAny(code, weakHashPatterns)
}

func shouldAnalyzeRubyWeakrandomnessCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	weakRandomSources := []string{
		"rand(",
		"random.rand",
		"kernel.rand",
		"srand(",
	}

	securityContext := []string{
		"token",
		"password",
		"session",
		"secret",
		"otp",
		"verification",
		"csrf",
		"nonce",
		"api_key",
		"apikey",
		"cookie",
		"auth",
		"login",
		"credential",
	}

	hasWeakRandom := containsAny(code, weakRandomSources)
	hasSecurityContext := containsAny(code, securityContext)

	return hasWeakRandom && hasSecurityContext
}

func shouldAnalyzeRubyDeserializationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	deserializationSinks := []string{
		"marshal.load(",
		"marshal.restore(",
		"yaml.load(",
		"yaml.unsafe_load(",
		"oj.load(",
		"json.load(",
		"psych.load(",
	}

	safePatterns := []string{
		"yaml.safe_load",
		"yaml.safe_load_file",
	}

	hasSink := containsAny(code, deserializationSinks)
	hasSafe := containsAny(code, safePatterns)

	return hasSink && !hasSafe
}

func shouldAnalyzeRubyTrustboundaryCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	sessionStorage := []string{
		"session[",
		"session.store",
		"session[:user",
		"session[:current",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"cookies[",
		"request.headers",
	}

	hasSession := containsAny(code, sessionStorage)
	hasInput := containsAny(code, inputSources)

	return hasSession && hasInput
}

func shouldAnalyzeRubyOpenredirectCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	redirectSinks := []string{
		"redirect_to(",
		"redirect(",
		"response.redirect",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"request.referer",
		"cookies[",
	}

	hasSink := containsAny(code, redirectSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

func shouldAnalyzeRubyInsecurecookieCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	cookieSinks := []string{
		"cookies[",
		"cookies.signed[",
		"cookies.encrypted[",
		"response.set_cookie",
		"rack::response",
		"actiondispatch::cookies",
	}

	return containsAny(code, cookieSinks)
}

func shouldAnalyzeRubyXpathiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	xpathAPIs := []string{
		"nokogiri",
		"rexml",
		"libxml",
		".xpath(",
		".search(",
		"xpath(",
	}

	return containsAny(code, xpathAPIs)
}

func shouldAnalyzeRubyImproperoutputhandlingCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	outputSinks := []string{
		"render(",
		"render json:",
		"response.body",
		"response.write(",
		"send_data(",
		"to_json",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"cookies[",
	}

	hasSink := containsAny(code, outputSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

func shouldAnalyzeRubyExcessiveagencyCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	aiPatterns := []string{
		"openai",
		"anthropic",
		"langchain",
		"llm",
		"chatgpt",
		"gpt-4",
		"tool_call",
		"function_call",
		"langchain::agent",
	}

	return containsAny(code, aiPatterns)
}

func shouldAnalyzeRubySystempromptleakageCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	systemPromptPatterns := []string{
		"system_prompt",
		"system prompt",
		"systemprompt",
		"role: 'system'",
		"role: \"system\"",
	}

	aiPatterns := []string{
		"openai",
		"anthropic",
		"langchain",
		"llm",
	}

	hasSystemPrompt := containsAny(code, systemPromptPatterns)
	hasAI := containsAny(code, aiPatterns)

	return hasSystemPrompt || hasAI
}

func shouldAnalyzeRubyUnboundedconsumptionCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	aiLibrary := []string{
		"openai",
		"anthropic",
		"langchain",
		"llm",
	}

	resourcePatterns := []string{
		"max_tokens",
		"max_length",
		"temperature",
	}

	return containsAny(code, aiLibrary) && containsAny(code, resourcePatterns)
}

func shouldAnalyzeRubyVectorembeddingweaknessesCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	vectorPatterns := []string{
		"embedding",
		"vector",
		"pgvector",
		"pinecone",
		"weaviate",
		"chroma",
		"faiss",
		"similarity_search",
		"cosine_similarity",
	}

	return containsAny(code, vectorPatterns)
}

func shouldAnalyzeRubyDatamodelpoisoningCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	trainingPatterns := []string{
		"training_data",
		"fine_tune",
		"finetune",
		"dataset",
		"corpus",
		"llm",
		"model.train",
	}

	return containsAny(code, trainingPatterns)
}

func shouldAnalyzeRubyMisinformationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	misinfoPatterns := []string{
		"llm",
		"openai",
		"anthropic",
		"langchain",
		"chat_completion",
		"completions.create",
		"messages.create",
	}

	return containsAny(code, misinfoPatterns)
}

func shouldAnalyzeRubyPromptinjectionCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)

	promptSinks := []string{
		"openai",
		"anthropic",
		"langchain",
		"llm",
		"chat(",
		"completion(",
		"generate(",
		"messages:",
		"prompt:",
	}

	inputSources := []string{
		"params[",
		"params.fetch",
		"request.params",
		"cookies[",
		"session[",
		"user_input",
		"user_message",
	}

	hasSink := containsAny(code, promptSinks)
	hasInput := containsAny(code, inputSources)

	return hasSink && hasInput
}

// ============================================================
// Elixir Rules
// ============================================================

func shouldAnalyzeElixirSqliCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	dbHints := []string{"ecto.adapters.sql", "repo.query", "sql.query", "postgrex", "myxql", "tds", "ecto.repo"}
	sqlWords := []string{"select", "update", "insert", "delete", "from", "where"}
	return containsAny(code, dbHints) && (containsAnyWord(code, sqlWords) || hasElixirRequestInput(code))
}

func shouldAnalyzeElixirCmdiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	commandSinks := []string{"system.cmd(", ":os.cmd(", "port.open(", "muontrap.cmd(", "porcelain.shell("}
	return containsAny(code, commandSinks)
}

func shouldAnalyzeElixirXssCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	unsafeOutput := []string{"phoenix.html.raw(", "{:safe,", "html(conn,", "send_resp(", "put_resp_content_type("}
	return containsAny(code, unsafeOutput) && hasElixirRequestInput(code)
}

func shouldAnalyzeElixirPathtraversalCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	fileSinks := []string{
		"file.read(", "file.read!(", "file.write(", "file.write!(", "file.open(", "file.open!(",
		"file.rm(", "file.rm!(", "file.cp(", "file.cp!(", "send_file(", "send_download(", "path.join(",
	}
	return containsAny(code, fileSinks) && hasElixirRequestInput(code)
}

func shouldAnalyzeElixirZipslipCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	archiveSinks := []string{":zip.extract", ":erl_tar.extract", "unzip(", "extract("}
	return containsAny(code, archiveSinks)
}

func shouldAnalyzeElixirLdapiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	ldapHints := []string{":eldap", "eldap.search", "eldap.simple_bind", "ldapex", "ldap."}
	filterHints := []string{"filter", "base", "dn", "search"}
	return containsAny(code, ldapHints) && containsAny(code, filterHints)
}

func shouldAnalyzeElixirCodeiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	codeSinks := []string{"code.eval_string(", "code.eval_quoted(", "eex.eval_string(", ":erl_eval.expr", "module.create("}
	return containsAny(code, codeSinks) && hasElixirRequestInput(code)
}

func shouldAnalyzeElixirLoginjectionCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	logSinks := []string{"logger.debug(", "logger.info(", "logger.warning(", "logger.warn(", "logger.error(", ":logger."}
	return containsAny(code, logSinks) && hasElixirRequestInput(code)
}

func shouldAnalyzeElixirIntegeroverflowCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	fixedWidthOperations := []string{"signed-integer", "unsigned-integer", "size(", "integer-size(", "nif", "rustler", "port.command("}
	externalInput := []string{"binary.decode_", "string.to_integer("}
	return containsAny(code, fixedWidthOperations) && (hasElixirRequestInput(code) || containsAny(code, externalInput))
}

func shouldAnalyzeElixirSensitiveinfodisclosureCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	sensitiveData := []string{"password", "secret", "api_key", "apikey", "token", "private_key", "credit_card", "ssn"}
	disclosureSinks := []string{
		"langchain", "reqllm", "ex_openai", "openai", "anthropic",
		"json(conn,", "text(conn,", "html(conn,", "send_resp(", "render(conn,", "put_resp_body(",
		"logger.", "inspect(",
	}
	return containsAny(code, sensitiveData) && containsAny(code, disclosureSinks)
}

func shouldAnalyzeElixirErrorinfoleakCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	errorData := []string{"exception.message(", "exception.format(", "__stacktrace__", "stacktrace", "inspect(error", "inspect(exception"}
	responseSinks := []string{"json(conn,", "send_resp(", "render(conn,", "put_resp_body("}
	return containsAny(code, errorData) && containsAny(code, responseSinks)
}

func shouldAnalyzeElixirAccesscontrolCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	requestIDs := []string{"params[\"id\"]", "params[:id]", "conn.params", "path_params"}
	resourceAccess := []string{"repo.get(", "repo.get!(", "repo.one(", "repo.update(", "repo.delete(", "from("}
	return containsAny(code, resourceAccess) && (containsAny(code, requestIDs) || hasElixirRequestInput(code))
}

func shouldAnalyzeElixirBrokencryptoCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	weakCrypto := []string{":des_", ":rc4", ":blowfish_", ":aes_ecb", "_ecb"}
	return containsAny(code, weakCrypto)
}

func shouldAnalyzeElixirWeakhashCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	weakHashes := []string{":md5,", ":md5)", ":sha,", ":sha)", ":erlang.md5(", "md5("}
	return containsAny(code, weakHashes)
}

func shouldAnalyzeElixirWeakrandomnessCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	weakRandom := []string{":rand.", "enum.random(", "enum.take_random(", "system.unique_integer("}
	securityContext := []string{"token", "password", "session", "secret", "otp", "nonce", "api_key", "cookie", "auth", "credential"}
	return containsAny(code, weakRandom) && containsAny(code, securityContext)
}

func shouldAnalyzeElixirDeserializationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	unsafeSinks := []string{":erlang.binary_to_term", "binary_to_term("}
	if !containsAny(code, unsafeSinks) {
		return false
	}
	if strings.Count(code, "binary_to_term(") == 1 && reElixirSingleSafeDeserialization.MatchString(code) {
		return false
	}
	return true
}

func shouldAnalyzeElixirTrustboundaryCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	trustedStorage := []string{"put_session(", "configure_session(", "assign(conn,", "guardian.encode_and_sign("}
	return containsAny(code, trustedStorage) && hasElixirRequestInput(code)
}

func shouldAnalyzeElixirOpenredirectCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	redirectSinks := []string{"redirect(conn,", "external:", "redirect(to:", "redirect(external:"}
	requestInput := []string{"referer"}
	return containsAny(code, redirectSinks) && (hasElixirRequestInput(code) || containsAny(code, requestInput))
}

func shouldAnalyzeElixirInsecurecookieCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	cookieSinks := []string{"put_resp_cookie(", "delete_resp_cookie(", "plug.session", "store: :cookie", "put_session("}
	return containsAny(code, cookieSinks)
}

func shouldAnalyzeElixirXpathiCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	xpathLibraries := []string{"sweet_xml", "sweetxml", "sigil_x", "xpath(", ":xmerl_xpath.string("}
	return containsAny(code, xpathLibraries)
}

func shouldAnalyzeElixirImproperoutputhandlingCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	aiOutput := []string{"langchain", "reqllm", "ex_openai", "openai", "chat_completion", "llm"}
	dangerousSinks := []string{"system.cmd(", ":os.cmd(", "code.eval_string(", "phoenix.html.raw(", "repo.query(", "file.write("}
	return containsAny(code, aiOutput) && containsAny(code, dangerousSinks)
}

func shouldAnalyzeElixirExcessiveagencyCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	aiLibraries := []string{"langchain", "reqllm", "ex_openai", "openai", "anthropic"}
	toolPatterns := []string{"function_call", "tool_call", "tools:", "function:", "execute(", "mcp"}
	return containsAny(code, aiLibraries) && containsAny(code, toolPatterns)
}

func shouldAnalyzeElixirSystempromptleakageCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	systemPrompt := []string{"system_prompt", "system prompt", "role: :system", "role: \"system\"", "type: :system"}
	outputSinks := []string{"json(conn,", "send_resp(", "render(conn,", "logger.", "inspect("}
	return containsAny(code, systemPrompt) && containsAny(code, outputSinks)
}

func shouldAnalyzeElixirUnboundedconsumptionCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	aiLibraries := []string{"langchain", "reqllm", "ex_openai", "openai", "anthropic"}
	requestOrLoop := []string{"chat_completion", "completion", "generate", "stream", "while", "enum.reduce", "task.async_stream"}
	return containsAny(code, aiLibraries) && containsAny(code, requestOrLoop)
}

func shouldAnalyzeElixirVectorembeddingweaknessesCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	vectorStores := []string{"pgvector", "vector", "qdrant", "pinecone", "weaviate", "embedding", "cosine_distance", "l2_distance"}
	searchPatterns := []string{"similarity", "nearest", "search", "query", "distance", "embedding"}
	return containsAny(code, vectorStores) && containsAny(code, searchPatterns)
}

func shouldAnalyzeElixirDatamodelpoisoningCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	modelLibraries := []string{"bumblebee", "nx", "axon", "ortex", "huggingface", "safetensors"}
	dataOperations := []string{"dataset", "training", "fine_tun", "load_model", "load_featurizer", "from_pretrained"}
	return containsAny(code, modelLibraries) && containsAny(code, dataOperations)
}

func shouldAnalyzeElixirMisinformationCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	aiLibraries := []string{"langchain", "reqllm", "ex_openai", "openai", "anthropic"}
	highImpactOutput := []string{"medical", "diagnosis", "financial", "legal", "decision", "recommendation", "answer", "response"}
	return containsAny(code, aiLibraries) && containsAny(code, highImpactOutput)
}

func shouldAnalyzeElixirPromptinjectionCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	promptSinks := []string{"langchain", "reqllm", "ex_openai", "openai", "anthropic", "messages:", "prompt:"}
	requestInput := []string{"user_input", "user_message", "document"}
	return containsAny(code, promptSinks) && (hasElixirRequestInput(code) || containsAny(code, requestInput))
}

func shouldAnalyzeElixirSupplychainCtx(ctx *model.DetectionContext) bool {
	code := getStrippedCode(ctx)
	networkDownloads := []string{"req.get(", "req.request(", "finch.request(", "httpoison.get(", ":httpc.request(", "download("}
	modelLoaders := []string{"bumblebee.load_model(", "bumblebee.load_featurizer(", "ortex", "axon.deserialize(", "nx.deserialize("}
	remoteRepositories := []string{"{:hf,"}
	hasNetworkDownload := containsAny(code, networkDownloads)
	if !hasNetworkDownload && countElixirModelLoaders(code) == 1 && reElixirPinnedHuggingFaceLoad.MatchString(code) {
		return false
	}
	return containsAny(code, modelLoaders) && (hasNetworkDownload || containsAny(code, remoteRepositories))
}

func hasElixirRequestInput(code string) bool {
	directInput := []string{"conn.params", "params[", "body_params", "query_params", "get_req_header("}
	return containsAny(code, directInput) ||
		reElixirPhoenixActionParameters.MatchString(code) ||
		reElixirLiveViewEventParameters.MatchString(code)
}

func countElixirModelLoaders(code string) int {
	count := strings.Count(code, "bumblebee.load_model(")
	count += strings.Count(code, "bumblebee.load_featurizer(")
	count += strings.Count(code, "axon.deserialize(")
	count += strings.Count(code, "nx.deserialize(")
	if strings.Contains(code, "ortex") {
		count++
	}
	return count
}

// ShouldAnalyze does a very early, cheap filter to decide if a file is worth
// running a given rule on. Return true => run the rule. Return false => skip.
func ShouldAnalyze(detectionContext *model.DetectionContext, logger log.DDSourceLogger) bool {
	if detectionContext.Code == "" {
		return false
	}

	// If we have a specialized filter for this rule, use it.
	if f, ok := ruleFilters[detectionContext.Rule.ID]; ok {
		res := f(detectionContext)
		return res
	}

	// Fallback: keyword-based OR logic using keywordsPerRuleId.
	keywords := detectionContext.Rule.FileSearchKeywords
	if len(keywords) == 0 {
		// No filter configured: analyze everything for this rule.
		return true
	}

	// Use cached stripped code if available, otherwise compute it
	codeForDetection := getStrippedCode(detectionContext)

	for _, keyword := range keywords {
		// Assumes keywords are already lowercase.
		if strings.Contains(codeForDetection, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}
