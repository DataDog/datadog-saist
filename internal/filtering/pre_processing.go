package filtering

import (
	"regexp"
	"strings"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
)

var (
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
	case model.Swift:
		return stripSwiftComments(inputCode)
	case model.Dart:
		return stripDartComments(inputCode)
	case model.Cpp:
		return stripCppComments(inputCode)
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

type cStyleStringDelimiter struct {
	value   string
	closing string
	escapes bool
}

type cStyleCommentOptions struct {
	hashLineComments           bool
	stringDelimiters           []cStyleStringDelimiter
	nestedBlockComments        bool
	failOpenUnterminatedString bool
	cppRawStrings              bool
}

// stripCStyleComments removes comments while preserving comment delimiters in
// string literals. If a block comment is unterminated, it returns the original
// code so keyword filtering cannot silently discard the rest of the file.
func stripCStyleComments(code string, options cStyleCommentOptions) string {
	var result strings.Builder
	result.Grow(len(code))

	for i := 0; i < len(code); {
		if options.cppRawStrings {
			if end, ok := copyCppRawString(&result, code, i); ok {
				i = end
				continue
			}
		}
		if delimiter, ok := matchingStringDelimiter(code[i:], options.stringDelimiters); ok {
			var terminated bool
			i, terminated = copyStringLiteral(&result, code, i, delimiter)
			if !terminated {
				if options.failOpenUnterminatedString {
					return code
				}
				return result.String()
			}
			continue
		}

		commentLength := lineCommentLength(code[i:], options.hashLineComments)
		if commentLength > 0 {
			i += commentLength
			for i < len(code) && code[i] != '\n' {
				i++
			}
			continue
		}

		if strings.HasPrefix(code[i:], "/*") {
			var terminated bool
			i, terminated = skipBlockComment(&result, code, i, options.nestedBlockComments)
			if !terminated {
				return code
			}
			continue
		}

		result.WriteByte(code[i])
		i++
	}

	return result.String()
}

func stripCppComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters: []cStyleStringDelimiter{{value: `"`, escapes: true}, {value: `'`, escapes: true}},
		cppRawStrings:    true,
	})
}

func copyCppRawString(result *strings.Builder, code string, start int) (int, bool) {
	if !strings.HasPrefix(code[start:], `R"`) {
		return start, false
	}

	delimiterStart := start + 2
	open := delimiterStart
	for open < len(code) && code[open] != '(' {
		if open-delimiterStart == 16 || strings.ContainsRune(" ()\\\t\r\n", rune(code[open])) {
			return start, false
		}
		open++
	}
	if open == len(code) {
		return start, false
	}

	closing := ")" + code[delimiterStart:open] + `"`
	endOffset := strings.Index(code[open+1:], closing)
	if endOffset == -1 {
		result.WriteString(code[start:])
		return len(code), true
	}
	end := open + 1 + endOffset + len(closing)
	result.WriteString(code[start:end])
	return end, true
}

func copyStringLiteral(result *strings.Builder, code string, start int, delimiter cStyleStringDelimiter) (int, bool) {
	closing := delimiter.closing
	if closing == "" {
		closing = delimiter.value
	}
	result.WriteString(delimiter.value)
	for i := start + len(delimiter.value); i < len(code); {
		if delimiter.escapes && code[i] == '\\' && i+1 < len(code) {
			result.WriteString(code[i : i+2])
			i += 2
			continue
		}
		if strings.HasPrefix(code[i:], closing) {
			result.WriteString(closing)
			return i + len(closing), true
		}
		result.WriteByte(code[i])
		i++
	}
	return len(code), false
}

func lineCommentLength(code string, hashLineComments bool) int {
	if strings.HasPrefix(code, "//") {
		return 2
	}
	if hashLineComments && code[0] == '#' && !strings.HasPrefix(code, "#[") {
		return 1
	}
	return 0
}

func skipBlockComment(result *strings.Builder, code string, start int, nested bool) (int, bool) {
	depth := 1
	for i := start + 2; i < len(code); {
		switch {
		case nested && strings.HasPrefix(code[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(code[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i, true
			}
		case code[i] == '\n':
			result.WriteByte('\n')
			i++
		default:
			i++
		}
	}
	return len(code), false
}

func matchingStringDelimiter(code string, delimiters []cStyleStringDelimiter) (cStyleStringDelimiter, bool) {
	for _, delimiter := range delimiters {
		if strings.HasPrefix(code, delimiter.value) {
			return delimiter, true
		}
	}
	return cStyleStringDelimiter{}, false
}

func stripJavaComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters: []cStyleStringDelimiter{{value: `"""`, escapes: true}, {value: `"`, escapes: true}, {value: `'`, escapes: true}},
	})
}

func stripGoComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters: []cStyleStringDelimiter{{value: "`"}, {value: `"`, escapes: true}},
	})
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
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters: []cStyleStringDelimiter{{value: "`", escapes: true}, {value: `"`, escapes: true}, {value: `'`, escapes: true}},
	})
}

func stripTypeScriptComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters: []cStyleStringDelimiter{{value: "`", escapes: true}, {value: `"`, escapes: true}, {value: `'`, escapes: true}},
	})
}

func stripKotlinComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters:    []cStyleStringDelimiter{{value: `"""`}, {value: `"`, escapes: true}, {value: `'`, escapes: true}},
		nestedBlockComments: true,
	})
}

func stripPHPComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		hashLineComments: true,
		stringDelimiters: []cStyleStringDelimiter{{value: `"`, escapes: true}, {value: `'`, escapes: true}},
	})
}

func stripRustComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters:    []cStyleStringDelimiter{{value: `"`, escapes: true}},
		nestedBlockComments: true,
	})
}

func stripSwiftComments(code string) string {
	var result strings.Builder
	result.Grow(len(code))
	blockDepth := 0
	inString := false

	for i := 0; i < len(code); {
		if inString {
			i, inString = copySwiftStringByte(code, i, &result)
			continue
		}
		if startsSwiftString(code, i, blockDepth) {
			inString = true
			result.WriteByte(code[i])
			i++
			continue
		}
		if startsSwiftBlockComment(code, i) {
			blockDepth++
			i += 2
			continue
		}
		if endsSwiftBlockComment(code, i, blockDepth) {
			blockDepth--
			i += 2
			continue
		}
		writeSwiftNonCommentByte(&result, code[i], blockDepth)
		i++
	}

	lines := strings.Split(result.String(), "\n")
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), "//") {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}

func stripDartComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters: []cStyleStringDelimiter{
			{value: `r"""`, closing: `"""`},
			{value: `R"""`, closing: `"""`},
			{value: `r'''`, closing: `'''`},
			{value: `R'''`, closing: `'''`},
			{value: `"""`, escapes: true},
			{value: `'''`, escapes: true},
			{value: `r"`, closing: `"`},
			{value: `R"`, closing: `"`},
			{value: `r'`, closing: `'`},
			{value: `R'`, closing: `'`},
			{value: `"`, escapes: true},
			{value: `'`, escapes: true},
		},
		nestedBlockComments:        true,
		failOpenUnterminatedString: true,
	})
}

func copySwiftStringByte(code string, index int, result *strings.Builder) (int, bool) {
	result.WriteByte(code[index])
	if code[index] == '\\' && index+1 < len(code) {
		result.WriteByte(code[index+1])
		return index + 2, true
	}
	return index + 1, code[index] != '"'
}

func startsSwiftString(code string, index, blockDepth int) bool {
	return blockDepth == 0 && code[index] == '"'
}

func startsSwiftBlockComment(code string, index int) bool {
	return index+1 < len(code) && code[index:index+2] == "/*"
}

func endsSwiftBlockComment(code string, index, blockDepth int) bool {
	return blockDepth > 0 && index+1 < len(code) && code[index:index+2] == "*/"
}

func writeSwiftNonCommentByte(result *strings.Builder, character byte, blockDepth int) {
	if blockDepth == 0 || character == '\n' {
		result.WriteByte(character)
	}
}

func stripCSharpComments(code string) string {
	return stripCStyleComments(code, cStyleCommentOptions{
		stringDelimiters: []cStyleStringDelimiter{{value: `"`, escapes: true}, {value: `'`, escapes: true}},
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

// ShouldAnalyze does a very early, cheap filter to decide if a file is worth
// running a given rule on. Return true => run the rule. Return false => skip.
func ShouldAnalyze(detectionContext *model.DetectionContext, logger log.DDSourceLogger) bool {
	if detectionContext.Code == "" {
		return false
	}

	if filter := detectionContext.Rule.AnalysisFilter; filter != nil && filter.Version == api.AnalysisFilterVersion {
		if matches, supported := matchFilterExpression(getStrippedCode(detectionContext), &filter.Expression); supported {
			return matches
		}
	}

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
