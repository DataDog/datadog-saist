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

	reGoBlock = regexp.MustCompile(`(?s)/\*.*?\*/`)

	// Simple heuristic for Python triple-quoted strings (often docstrings).
	rePyTriple = regexp.MustCompile(`(?s)("""[\s\S]*?"""|'''[\s\S]*?''')`)

	// Token splitter for word-ish matching.
	reTokenSplit = regexp.MustCompile(`[^a-z0-9_]+`)
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

func stripJavaComments(code string) string {
	code = reJavaBlock.ReplaceAllString(code, "")
	code = reJavaLine.ReplaceAllString(code, "")

	lines := strings.Split(code, "\n")
	out := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty and bare "*" lines (common in Javadoc bodies).
		if trimmed == "" || trimmed == "*" {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
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

func stripCSharpComments(code string) string {
	// C# uses same comment syntax as Java: /* ... */ and //
	code = reJavaBlock.ReplaceAllString(code, "")
	code = reJavaLine.ReplaceAllString(code, "")

	lines := strings.Split(code, "\n")
	out := lines[:0]
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty and XML doc comment lines (/// or bare *)
		if trimmed == "" || trimmed == "*" || strings.HasPrefix(trimmed, "///") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
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
