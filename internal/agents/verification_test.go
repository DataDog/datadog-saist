package agents

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseVerificationResult_WithLiteralNewlines(t *testing.T) {
	// This test case reproduces the issue where the LLM outputs JSON with literal newlines
	// inside string values, which breaks standard JSON parsing.
	// We construct the content with actual newline bytes inside the JSON string value.
	content := "```json\n" +
		"{\n" +
		"  \"confirmed\": true,\n" +
		"  \"confidence\": \"high\",\n" +
		"  \"reason\": \"Source: The untrusted data originates from line 52.\n\nSink: The dangerous operation occurs at line 64.\n\nConclusion: This is a true positive.\"\n" +
		"}\n" +
		"```"

	ctx := context.Background()
	result, err := parseVerificationResult(ctx, content, false)

	if err != nil {
		t.Fatalf("parseVerificationResult failed: %v", err)
	}

	if !result.Confirmed {
		t.Errorf("expected Confirmed to be true, got false")
	}

	if result.Confidence != "high" {
		t.Errorf("expected Confidence to be 'high', got '%s'", result.Confidence)
	}

	if result.Reason == "" {
		t.Errorf("expected Reason to be non-empty")
	}

	// Verify the reason contains expected content
	if !contains(result.Reason, "Source:") {
		t.Errorf("expected Reason to contain 'Source:', got '%s'", result.Reason)
	}
	if !contains(result.Reason, "Sink:") {
		t.Errorf("expected Reason to contain 'Sink:', got '%s'", result.Reason)
	}
}

func TestParseVerificationResult_ValidJSON(t *testing.T) {
	// Test with properly formatted JSON (no literal newlines in strings)
	content := `{
		"confirmed": true,
		"confidence": "high",
		"reason": "This is a valid SQL injection vulnerability."
	}`

	ctx := context.Background()
	result, err := parseVerificationResult(ctx, content, false)

	if err != nil {
		t.Fatalf("parseVerificationResult failed: %v", err)
	}

	if !result.Confirmed {
		t.Errorf("expected Confirmed to be true, got false")
	}

	if result.Confidence != "high" {
		t.Errorf("expected Confidence to be 'high', got '%s'", result.Confidence)
	}
}

func TestParseVerificationResult_FalsePositive(t *testing.T) {
	content := `{"confirmed": false, "confidence": "high", "reason": "The input is properly sanitized before use."}`

	ctx := context.Background()
	result, err := parseVerificationResult(ctx, content, false)

	if err != nil {
		t.Fatalf("parseVerificationResult failed: %v", err)
	}

	if result.Confirmed {
		t.Errorf("expected Confirmed to be false, got true")
	}
}

func TestParseVerificationResult_Incomplete1(t *testing.T) {
	content := `
{
  "confirmed": true,
  "confidence": "high",
  "reason": "Source: 'req.Args' and 'req.Code' from the JSON body of the POST request.\nSink: 'exec.Command(\"python3\", \"-c\", script)' on line 45.\nDataflow:
`

	ctx := context.Background()
	result, err := parseVerificationResult(ctx, content, false)

	assert.Nil(t, err)
	assert.True(t, result.Confirmed)
	assert.Equal(t, "high", result.Confidence)
}

func TestParseVerificationResult_Incomplete2(t *testing.T) {
	content := `
{
  "confirmed": true,
  "confidence": "high",
  "reason": "Source: c.Query(\"q\") at line 16.\n\nSink: exec.Command(\"sqlite3\", ...) at line 25.\n\nDataflow: Untrusted user input from the 'q
`

	ctx := context.Background()
	result, err := parseVerificationResult(ctx, content, false)

	assert.Nil(t, err)
	assert.True(t, result.Confirmed)
	assert.Equal(t, "high", result.Confidence)
}

func TestParseVerificationResult_Incomplete3(t *testing.T) {
	truncatedContent := `
{
  "confirmed": true,
  "confidence": "high",
  "reason": "Source: 'req.Args' and 'req.Code' from the JSON body of the POST request.\nSink: 'exec.Command(\"python3\", \"-c\", script)' on line 45.\nDataflow:
`

	result, err := parseVerificationResult(context.Background(), truncatedContent, false)
	assert.Nil(t, err)
	assert.True(t, result.Confirmed)
	assert.Equal(t, "high", result.Confidence)
}

func TestParseVerificationResult_WithCodeBlockMarkers(t *testing.T) {
	content := "```json\n{\"confirmed\": true, \"confidence\": \"low\", \"reason\": \"Potential vulnerability detected.\"}\n```"

	ctx := context.Background()
	result, err := parseVerificationResult(ctx, content, false)

	if err != nil {
		t.Fatalf("parseVerificationResult failed: %v", err)
	}

	if !result.Confirmed {
		t.Errorf("expected Confirmed to be true, got false")
	}

	if result.Confidence != "low" {
		t.Errorf("expected Confidence to be 'low', got '%s'", result.Confidence)
	}
}

func TestParseVerificationResult_WrappedInContentField(t *testing.T) {
	// Test case where verification result is wrapped in a "content" object field
	content := `{
		"content": {
			"confirmed": true,
			"confidence": "high",
			"reason": "This is a valid SQL injection vulnerability."
		}
	}`

	ctx := context.Background()
	result, err := parseVerificationResult(ctx, content, false)

	if err != nil {
		t.Fatalf("parseVerificationResult failed: %v", err)
	}

	if !result.Confirmed {
		t.Errorf("expected Confirmed to be true, got false")
	}

	if result.Confidence != "high" {
		t.Errorf("expected Confidence to be 'high', got '%s'", result.Confidence)
	}

	if result.Reason != "This is a valid SQL injection vulnerability." {
		t.Errorf("expected Reason to be 'This is a valid SQL injection vulnerability.', got '%s'", result.Reason)
	}
}

func TestSanitizeJSONString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no newlines",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "newline outside string",
			input:    "{\n\"key\": \"value\"\n}",
			expected: "{\n\"key\": \"value\"\n}",
		},
		{
			name:     "literal newline inside string",
			input:    "{\"key\": \"line1\nline2\"}",
			expected: "{\"key\": \"line1\\nline2\"}",
		},
		{
			name:     "multiple newlines inside string",
			input:    "{\"reason\": \"Source: test\n\nSink: test\"}",
			expected: "{\"reason\": \"Source: test\\n\\nSink: test\"}",
		},
		{
			name:     "already escaped newline",
			input:    `{"key": "line1\nline2"}`,
			expected: `{"key": "line1\nline2"}`,
		},
		{
			name:     "carriage return removed",
			input:    "{\"key\": \"line1\r\nline2\"}",
			expected: "{\"key\": \"line1\\nline2\"}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeJSONString(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeJSONString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
