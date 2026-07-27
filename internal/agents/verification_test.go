package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerificationPromptHashIncludesAgenticPolicy(t *testing.T) {
	before, err := VerificationPromptHash(true)
	require.NoError(t, err)
	standard, err := VerificationPromptHash(false)
	require.NoError(t, err)
	assert.NotEqual(t, standard, before)
}

func TestVerificationOptionsHaveNoCompletionCeiling(t *testing.T) {
	assert.Zero(t, standardVerificationOptions().MaxTokens)
	assert.Zero(t, agenticVerificationOptions().MaxTokens)
	assert.Zero(t, locationDeterminationOptions().MaxTokens)
}

func TestAgenticVerificationPromptAddsGoPathTraversalGuidance(t *testing.T) {
	violation := model.LLMResultViolation{StartLine: 1, Reason: "candidate"}
	scanData := &model.ScanData{
		RelativeFilePath: "tool.go",
		FileText:         "danger()",
		Rule: &api.AiPrompt{
			ID:      "datadog/go-pathtraversal",
			Content: "path traversal rule",
		},
	}

	agenticPrompt := getAgenticVerificationUserPrompt(scanData, violation, "tool.go")
	standardPrompt := getVerificationUserPrompt(scanData, violation)

	assert.Contains(t, agenticPrompt, goPathTraversalAgenticGuidance)
	assert.Contains(t, agenticPrompt, "A path from a command-line flag is not automatically attacker-controlled.")
	assert.Contains(t, agenticPrompt, "less-privileged actor")
	assert.NotContains(t, standardPrompt, goPathTraversalAgenticGuidance)
}

func TestAgenticVerificationPromptAddsGoPromptInjectionGuidance(t *testing.T) {
	violation := model.LLMResultViolation{StartLine: 10, Reason: "candidate"}
	scanData := &model.ScanData{
		RelativeFilePath: "eval.go",
		FileText:         "judge(output)",
		Rule: &api.AiPrompt{
			ID:      "datadog/go-promptinjection",
			Content: "prompt injection rule",
		},
	}

	agenticPrompt := getAgenticVerificationUserPrompt(scanData, violation, "eval.go")
	standardPrompt := getVerificationUserPrompt(scanData, violation)

	assert.Contains(t, agenticPrompt, promptInjectionAgenticGuidance)
	assert.Contains(t, agenticPrompt, "both that a less-privileged actor can directly or indirectly influence")
	assert.Contains(t, agenticPrompt, "Internal evaluation scoring alone is not a protected security effect.")
	assert.Contains(t, agenticPrompt, "Do not infer attacker control from a hypothetical statement")
	assert.Contains(t, agenticPrompt, "changes to durable stored content")
	assert.Contains(t, agenticPrompt, "release, review, or validation gates")
	assert.Contains(t, agenticPrompt, "Indirect influence remains relevant.")
	assert.NotContains(t, standardPrompt, promptInjectionAgenticGuidance)
}

func TestAgenticVerificationPromptAddsPythonPromptInjectionGuidance(t *testing.T) {
	violation := model.LLMResultViolation{StartLine: 10, Reason: "candidate"}
	scanData := &model.ScanData{
		RelativeFilePath: "eval.py",
		FileText:         "judge(output)",
		Rule: &api.AiPrompt{
			ID:      "datadog/python-promptinjection",
			Content: "prompt injection rule",
		},
	}

	agenticPrompt := getAgenticVerificationUserPrompt(scanData, violation, "eval.py")
	standardPrompt := getVerificationUserPrompt(scanData, violation)

	assert.Contains(t, agenticPrompt, promptInjectionAgenticGuidance)
	assert.Contains(t, agenticPrompt, "Local developer input")
	assert.Contains(t, agenticPrompt, "Require cited evidence of an actual less-privileged influence path.")
	assert.Contains(t, agenticPrompt, "Inspect API callers, ingestion paths, PR provenance")
	assert.NotContains(t, standardPrompt, promptInjectionAgenticGuidance)
}

func TestAgenticVerificationPromptAddsPythonWeakHashGuidance(t *testing.T) {
	violation := model.LLMResultViolation{StartLine: 20, Reason: "candidate"}
	scanData := &model.ScanData{
		RelativeFilePath: "signing.py",
		FileText:         "hmac.new(key, value, hashlib.sha1)",
		Rule: &api.AiPrompt{
			ID:      "datadog/python-weakhash",
			Content: "weak hash rule",
		},
	}

	agenticPrompt := getAgenticVerificationUserPrompt(scanData, violation, "signing.py")
	standardPrompt := getVerificationUserPrompt(scanData, violation)

	assert.Contains(t, agenticPrompt, pythonWeakHashAgenticGuidance)
	assert.Contains(t, agenticPrompt, "does not by itself establish a weak-hash vulnerability")
	assert.Contains(t, agenticPrompt, "construction-specific weakness")
	assert.Contains(t, agenticPrompt, "Preserve separately evidenced weak cases.")
	assert.NotContains(t, standardPrompt, pythonWeakHashAgenticGuidance)
}

func TestAgenticVerificationPromptRequiresExactCandidateSinkCitation(t *testing.T) {
	violation := model.LLMResultViolation{StartLine: 98, Reason: "candidate"}
	scanData := &model.ScanData{
		RelativeFilePath: "collect_codex.go",
		FileText:         "outputPath := flags.output",
		Rule: &api.AiPrompt{
			ID:      "datadog/go-pathtraversal",
			Content: "path traversal rule",
		},
	}
	repositoryRelativePath := "domains/ai-devx/pr-replay-tool/cmd/collect_codex.go"

	agenticPrompt := getAgenticVerificationUserPrompt(scanData, violation, repositoryRelativePath)
	standardPrompt := getVerificationUserPrompt(scanData, violation)

	assert.Contains(t, agenticPrompt, "path \"domains/ai-devx/pr-replay-tool/cmd/collect_codex.go\" and line 98")
	assert.Contains(t, agenticPrompt, "Cite that exact numbered row as the sink.")
	assert.Contains(t, agenticPrompt, "Downstream assignments, calls, or dangerous operations belong in flow evidence")
	assert.NotContains(t, standardPrompt, "Downstream assignments, calls, or dangerous operations belong in flow evidence")
}

func TestAgenticVerificationPromptDoesNotAddPathTraversalGuidanceToOtherRules(t *testing.T) {
	violation := model.LLMResultViolation{StartLine: 1, Reason: "candidate"}
	scanData := &model.ScanData{
		RelativeFilePath: "tool.go",
		FileText:         "danger()",
		Rule: &api.AiPrompt{
			ID:      "datadog/go-sql-injection",
			Content: "SQL injection rule",
		},
	}

	prompt := getAgenticVerificationUserPrompt(scanData, violation, "tool.go")

	assert.NotContains(t, prompt, goPathTraversalAgenticGuidance)
	assert.NotContains(t, prompt, promptInjectionAgenticGuidance)
	assert.NotContains(t, prompt, pythonWeakHashAgenticGuidance)
}

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

// standardVerifierRequestFingerprint hashes the complete standard verifier
// request tuple for a fixed candidate: the system prompt, the rendered user
// prompt, and the response schema and decoding settings exactly as serialized
// today. It is the byte-identity anchor for the standard arm.
func standardVerifierRequestFingerprint(t *testing.T) string {
	t.Helper()
	scanData := &model.ScanData{
		RelativeFilePath: "internal/handler/user.go",
		NumberedFileText: "1: package handler\n2: func h() { db.Query(userInput) }\n",
		Rule: &api.AiPrompt{
			ID:      "datadog/go-sqli",
			Content: "Detect SQL injection via untrusted input reaching a query sink.",
		},
	}
	violation := model.LLMResultViolation{StartLine: 2, Reason: "userInput flows into db.Query without sanitization"}
	opts := standardVerificationOptions()
	schemaJSON, err := json.Marshal(opts.Schema.JsonSchema)
	require.NoError(t, err)
	payload := []any{
		VerificationSystemPrompt,
		getVerificationUserPrompt(scanData, violation),
		opts.Schema.Name,
		opts.Schema.Description,
		string(schemaJSON),
		opts.ResponseType,
		opts.Temperature,
		opts.MaxTokens,
	}
	encoded, err := json.Marshal(payload)
	require.NoError(t, err)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// TestStandardVerifierRequestIsByteStable freezes the exact standard verifier
// request. If this fails, the standard arm is no longer byte-identical to the
// frozen baseline. Update the golden only after confirming that a change to the
// standard arm is truly intended.
func TestStandardVerifierRequestIsByteStable(t *testing.T) {
	const golden = "017e536cc2d33406aee199088a9e6c0da5e0f72bbfa8cbb4551f8d379d12ff52"
	assert.Equal(t, golden, standardVerifierRequestFingerprint(t))
}

// TestFinalVerifierContractHashIsArmIndependent proves the shared final-verifier
// contract is deterministic and carries no agentic-only content, so the standard
// and agentic arms hash to the same value.
func TestFinalVerifierContractHashIsArmIndependent(t *testing.T) {
	first, err := FinalVerifierContractHash()
	require.NoError(t, err)
	second, err := FinalVerifierContractHash()
	require.NoError(t, err)
	assert.Equal(t, first, second, "contract hash must be deterministic")

	encoded, err := json.Marshal(finalVerifierContract())
	require.NoError(t, err)
	contract := string(encoded)
	assert.NotContains(t, contract, AgenticVerificationSystemPrompt, "agentic system prompt must not enter the shared contract")
	assert.NotContains(t, contract, "Rule-specific guidance", "agentic rule guidance must not enter the shared contract")
	assert.NotContains(t, contract, LocationDeterminationSystemPrompt, "location determination must not enter the verifier decision contract")
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
