package agents

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetViolationsFromContent_DirectJSON(t *testing.T) {
	jsonContent := `{"violations":[{"startLine":10,"startColumn":1,"endLine":10,"endColumn":25,"reason":"SQL injection vulnerability"}]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(10), result.Violations[0].StartLine)
	assert.Equal(t, uint(1), result.Violations[0].StartColumn)
	assert.Equal(t, uint(10), result.Violations[0].EndLine)
	assert.Equal(t, uint(25), result.Violations[0].EndColumn)
	assert.Equal(t, "SQL injection vulnerability", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_JSONCodeBlock(t *testing.T) {
	content := "Here's the analysis result:\n\n```json\n{\"violations\":[{\"startLine\":25,\"startColumn\":5,\"endLine\":25,\"endColumn\":42,\"reason\":\"XSS vulnerability detected\"}]}\n```\n\nThis shows one violation found."

	result, err := getViolationsFromContent(content)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(25), result.Violations[0].StartLine)
	assert.Equal(t, uint(5), result.Violations[0].StartColumn)
	assert.Equal(t, "XSS vulnerability detected", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_CodeBlock(t *testing.T) {
	content := "Here's the analysis result:\n\n```\n{\"violations\":[{\"startLine\":25,\"startColumn\":5,\"endLine\":25,\"endColumn\":42,\"reason\":\"XSS vulnerability detected\"}]}\n```\n\nThis shows one violation found."

	result, err := getViolationsFromContent(content)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(25), result.Violations[0].StartLine)
	assert.Equal(t, "XSS vulnerability detected", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_NoViolation(t *testing.T) {
	content := "NO VIOLATION AMIGO - the code looks clean"

	result, err := getViolationsFromContent(content)
	assert.Nil(t, err)
	assert.Nil(t, result)
}

func TestGetViolationsFromContent_MultipleViolations(t *testing.T) {
	jsonContent := `{"violations":[
		{"startLine":15,"startColumn":1,"endLine":15,"endColumn":30,"reason":"Buffer overflow risk"},
		{"startLine":32,"startColumn":5,"endLine":32,"endColumn":55,"reason":"Hardcoded credentials"}
	]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 2)
	assert.Equal(t, uint(15), result.Violations[0].StartLine)
	assert.Equal(t, "Buffer overflow risk", result.Violations[0].Reason)
	assert.Equal(t, uint(32), result.Violations[1].StartLine)
	assert.Equal(t, "Hardcoded credentials", result.Violations[1].Reason)
}

func TestGetViolationsFromContent_EmptyViolations(t *testing.T) {
	jsonContent := `{"violations":[]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 0)
}

func TestGetViolationsFromContent_InvalidJSON(t *testing.T) {
	content := `{invalid json content}`

	result, err := getViolationsFromContent(content)
	assert.NotNil(t, err)
	assert.Nil(t, result)
}

func TestGetViolationsFromContent_JSONCodeBlockWithExtraWhitespace(t *testing.T) {
	content := "Analysis complete:\n\n```json\n  {\n    \"violations\": [\n      {\n        \"startLine\": 42,\n        \"startColumn\": 10,\n        \"endLine\": 42,\n        \"endColumn\": 55,\n        \"reason\": \"Potential path traversal\"\n      }\n    ]\n  }\n```\n\nEnd of analysis."

	result, err := getViolationsFromContent(content)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(42), result.Violations[0].StartLine)
	assert.Equal(t, uint(10), result.Violations[0].StartColumn)
	assert.Equal(t, "Potential path traversal", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_JSONCodeBlockMalformed(t *testing.T) {
	content := "Here's the result:\n\n```json\n{invalid json in code block}\n```\n\nDone."

	result, err := getViolationsFromContent(content)
	assert.NotNil(t, err)
	assert.Nil(t, result)
}

func TestGetViolationsFromContent_MissingStartLine(t *testing.T) {
	// startLine is 0 (missing/invalid)
	jsonContent := `{"violations":[{"startLine":0,"startColumn":1,"endLine":10,"endColumn":25,"reason":"test"}]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.NotNil(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "startLine is required")
}

func TestGetViolationsFromContent_MissingStartColumn(t *testing.T) {
	// startColumn is 0 (missing/invalid)
	jsonContent := `{"violations":[{"startLine":10,"startColumn":0,"endLine":10,"endColumn":25,"reason":"test"}]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.NotNil(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "startColumn is required")
}

func TestGetViolationsFromContent_MissingEndLine(t *testing.T) {
	// endLine is 0 (missing/invalid)
	jsonContent := `{"violations":[{"startLine":10,"startColumn":1,"endLine":0,"endColumn":25,"reason":"test"}]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.NotNil(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "endLine is required")
}

func TestGetViolationsFromContent_MissingEndColumn(t *testing.T) {
	// endColumn is 0 (missing/invalid)
	jsonContent := `{"violations":[{"startLine":10,"startColumn":1,"endLine":10,"endColumn":0,"reason":"test"}]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.NotNil(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "endColumn is required")
}

func TestGetViolationsFromContent_EndLineBeforeStartLine(t *testing.T) {
	// endLine (5) is before startLine (10)
	jsonContent := `{"violations":[{"startLine":10,"startColumn":1,"endLine":5,"endColumn":25,"reason":"test"}]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.NotNil(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "endLine")
	assert.Contains(t, err.Error(), "cannot be before startLine")
}

func TestGetViolationsFromContent_EndColumnBeforeStartColumnSameLine(t *testing.T) {
	// On same line (10), endColumn (5) is before startColumn (20)
	jsonContent := `{"violations":[{"startLine":10,"startColumn":20,"endLine":10,"endColumn":5,"reason":"test"}]}`

	result, err := getViolationsFromContent(jsonContent)
	assert.NotNil(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "endColumn")
	assert.Contains(t, err.Error(), "cannot be before startColumn")
}

func TestGetViolationsFromContent_WrappedInContentField(t *testing.T) {
	// Test case where violations JSON is wrapped in a "content" field
	wrappedContent := `{"content": "{\"violations\":[{\"startLine\":9,\"startColumn\":9,\"endLine\":9,\"endColumn\":65,\"reason\":\"The envVar parameter is concatenated directly\"}]}"}`

	result, err := getViolationsFromContent(wrappedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(9), result.Violations[0].StartLine)
	assert.Equal(t, uint(9), result.Violations[0].StartColumn)
	assert.Equal(t, uint(9), result.Violations[0].EndLine)
	assert.Equal(t, uint(65), result.Violations[0].EndColumn)
	assert.Equal(t, "The envVar parameter is concatenated directly", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_WrappedInContentFieldWithEscapedNewlines(t *testing.T) {
	// Test case with escaped newlines in the wrapped content
	wrappedContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 9,\n      \"startColumn\": 9,\n      \"endLine\": 9,\n      \"endColumn\": 65,\n      \"reason\": \"The envVar parameter is concatenated directly\"\n    }\n  ]\n}"}`

	result, err := getViolationsFromContent(wrappedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(9), result.Violations[0].StartLine)
	assert.Equal(t, uint(9), result.Violations[0].StartColumn)
	assert.Equal(t, uint(9), result.Violations[0].EndLine)
	assert.Equal(t, uint(65), result.Violations[0].EndColumn)
	assert.Equal(t, "The envVar parameter is concatenated directly", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_WrappedContentXPathExample(t *testing.T) {
	// Test case with wrapped content and specific XPath injection example
	// This matches the format where content has escaped newlines and specific line/column positions
	wrappedContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 20,\n      \"startColumn\": 20,\n      \"endLine\": 20,\n      \"endColumn\": 39,\n      \"reason\": \"The XPath query ` + "`xpathQuery`" + "is constructed by concatenating user-controlled input " + "`userType`" + `"}`

	result, err := getViolationsFromContent(wrappedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(20), result.Violations[0].StartLine)
	assert.Equal(t, uint(20), result.Violations[0].StartColumn)
	assert.Equal(t, uint(20), result.Violations[0].EndLine)
	assert.Equal(t, uint(39), result.Violations[0].EndColumn)
	assert.Equal(t, "The XPath query `xpathQuery`is constructed by concatenating user-controlled input `userType`", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_TruncatedReasonString1(t *testing.T) {
	// Test case where the reason field is truncated mid-sentence
	// This simulates LLM output being cut off due to token limits or other constraints
	truncatedContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 14,\n      \"startColumn\": 9,\n      \"endLine\": 14,\n      \"endColumn\": 38,\n      \"reason\": \"User-controlled input from os.Args[1] is split by spaces and passed directly as arguments to"}`

	result, err := getViolationsFromContent(truncatedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(14), result.Violations[0].StartLine)
	assert.Equal(t, uint(9), result.Violations[0].StartColumn)
	assert.Equal(t, uint(14), result.Violations[0].EndLine)
	assert.Equal(t, uint(38), result.Violations[0].EndColumn)
	// The reason should be repaired with the truncated text
	assert.Contains(t, result.Violations[0].Reason, "User-controlled input from os.Args[1] is split by spaces and passed directly as arguments to")
}

func TestGetViolationsFromContent_TruncatedReasonString2(t *testing.T) {
	// Test case where the reason field is truncated mid-sentence with a different pattern
	truncatedContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 89,\n      \"startColumn\": 10,\n      \"endLine\": 89,\n      \"endColumn\": 44,\n      \"reason\": \"User-controlled input from query parameters, headers, and form data (extracted in the middleware and"}`

	result, err := getViolationsFromContent(truncatedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(89), result.Violations[0].StartLine)
	assert.Equal(t, uint(10), result.Violations[0].StartColumn)
	assert.Equal(t, uint(89), result.Violations[0].EndLine)
	assert.Equal(t, uint(44), result.Violations[0].EndColumn)
	// The reason should be repaired with the truncated text
	assert.Contains(t, result.Violations[0].Reason, "User-controlled input from query parameters, headers, and form data (extracted in the middleware and")
}

func TestGetViolationsFromContent_TruncatedReasonString3(t *testing.T) {
	truncatedContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 36,\n      \"startColumn\": 10,\n      \"endLine\": 36,\n      \"endColumn\": 48,\n      \"reason\": \"User-controlled input from the 'log_message' and 'log_filename' cookies is"}`

	result, err := getViolationsFromContent(truncatedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(36), result.Violations[0].StartLine)
	assert.Equal(t, uint(10), result.Violations[0].StartColumn)
	assert.Equal(t, uint(36), result.Violations[0].EndLine)
	assert.Equal(t, uint(48), result.Violations[0].EndColumn)
	// The reason should be repaired with the truncated text
	assert.Contains(t, result.Violations[0].Reason, "User-controlled input from the 'log_message' and 'log_filename' cookies is")
}

func TestGetViolationsFromContent_TruncatedReasonString4(t *testing.T) {
	truncatedContent := `
{
  "violations": [
    {
      "startLine": 13,
      "startColumn": 9,
      "endLine": 13,
      "endColumn": 47,
      "reason": "User-controlled input from 'os.Args[1]' is interpolated into a string and executed as
`

	result, err := getViolationsFromContent(truncatedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
}

func TestGetViolationsFromContent_TruncatedMultipleViolations(t *testing.T) {
	// Test case where content is truncated in the middle of multiple violations
	truncatedContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 10,\n      \"startColumn\": 5,\n      \"endLine\": 10,\n      \"endColumn\": 20,\n      \"reason\": \"Complete violation description\"\n    },\n    {\n      \"startLine\": 25,\n      \"startColumn\": 8,\n      \"endLine\": 25,\n      \"endColumn\": 35,\n      \"reason\": \"This violation description is cut off and incomplete because"}`

	result, err := getViolationsFromContent(truncatedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	// We expect to get both violations, even though the second one is truncated
	assert.Len(t, result.Violations, 2)

	// First violation should be complete
	assert.Equal(t, uint(10), result.Violations[0].StartLine)
	assert.Equal(t, "Complete violation description", result.Violations[0].Reason)

	// Second violation should have repaired content
	assert.Equal(t, uint(25), result.Violations[1].StartLine)
	assert.Contains(t, result.Violations[1].Reason, "This violation description is cut off and incomplete because")
}

func TestGetViolationsFromContent_TruncatedBeforeReason(t *testing.T) {
	// Test case where content is truncated before the reason field even starts
	truncatedContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 42,\n      \"startColumn\": 12,\n      \"endLine\": 42,\n      \"endColumn\": 55,\n      \"reason\": \""}`

	result, err := getViolationsFromContent(truncatedContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(42), result.Violations[0].StartLine)
	assert.Equal(t, uint(12), result.Violations[0].StartColumn)
	// Empty reason is acceptable - the important fields are the location
	assert.Equal(t, "", result.Violations[0].Reason)
}

func TestGetViolationsFromContent_CompleteContentNotRepaired(t *testing.T) {
	// Test that properly formatted complete JSON is not affected by repair logic
	completeContent := `{"content": "{\n  \"violations\": [\n    {\n      \"startLine\": 15,\n      \"startColumn\": 20,\n      \"endLine\": 15,\n      \"endColumn\": 45,\n      \"reason\": \"Complete and properly formatted violation description\"\n    }\n  ]\n}"}`

	result, err := getViolationsFromContent(completeContent)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.Violations, 1)
	assert.Equal(t, uint(15), result.Violations[0].StartLine)
	assert.Equal(t, uint(20), result.Violations[0].StartColumn)
	assert.Equal(t, uint(15), result.Violations[0].EndLine)
	assert.Equal(t, uint(45), result.Violations[0].EndColumn)
	assert.Equal(t, "Complete and properly formatted violation description", result.Violations[0].Reason)
}
