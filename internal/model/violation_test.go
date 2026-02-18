package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLineContent(t *testing.T) {
	fileText := `line 1
line 2
line 3
line 4`

	tests := []struct {
		name       string
		fileText   string
		lineNumber uint
		expected   string
	}{
		{
			name:       "get first line",
			fileText:   fileText,
			lineNumber: 1,
			expected:   "line 1",
		},
		{
			name:       "get middle line",
			fileText:   fileText,
			lineNumber: 2,
			expected:   "line 2",
		},
		{
			name:       "get last line",
			fileText:   fileText,
			lineNumber: 4,
			expected:   "line 4",
		},
		{
			name:       "line number 0 returns empty string",
			fileText:   fileText,
			lineNumber: 0,
			expected:   "",
		},
		{
			name:       "line number beyond file length returns empty string",
			fileText:   fileText,
			lineNumber: 10,
			expected:   "",
		},
		{
			name:       "empty file returns empty string",
			fileText:   "",
			lineNumber: 1,
			expected:   "",
		},
		{
			name:       "single line file",
			fileText:   "single line",
			lineNumber: 1,
			expected:   "single line",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetLineContent(tt.fileText, tt.lineNumber)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateFingerprint(t *testing.T) {
	repoID := "test-repo-123"
	ruleName := "sql-injection"
	filePath := "src/main/java/App.java"
	lineContent := "String query = \"SELECT * FROM users WHERE id = \" + userId;"

	tests := []struct {
		name        string
		repoID      string
		ruleName    string
		filePath    string
		lineContent string
	}{
		{
			name:        "generate fingerprint with all fields",
			repoID:      repoID,
			ruleName:    ruleName,
			filePath:    filePath,
			lineContent: lineContent,
		},
		{
			name:        "fingerprint with different repo ID",
			repoID:      "different-repo",
			ruleName:    ruleName,
			filePath:    filePath,
			lineContent: lineContent,
		},
		{
			name:        "fingerprint with different rule name",
			repoID:      repoID,
			ruleName:    "xss",
			filePath:    filePath,
			lineContent: lineContent,
		},
		{
			name:        "fingerprint with different file path",
			repoID:      repoID,
			ruleName:    ruleName,
			filePath:    "src/test/java/AppTest.java",
			lineContent: lineContent,
		},
		{
			name:        "fingerprint with different line content",
			repoID:      repoID,
			ruleName:    ruleName,
			filePath:    filePath,
			lineContent: "String query = preparedStatement.prepare();",
		},
	}

	// Generate base fingerprint
	baseFingerprint := GenerateFingerprint(repoID, ruleName, filePath, lineContent)

	// Verify base fingerprint is not empty and has expected length (SHA256 = 64 hex chars)
	assert.NotEmpty(t, baseFingerprint)
	assert.Equal(t, 64, len(baseFingerprint), "SHA256 hash should be 64 characters")

	// Verify fingerprint is consistent
	secondFingerprint := GenerateFingerprint(repoID, ruleName, filePath, lineContent)
	assert.Equal(t, baseFingerprint, secondFingerprint, "fingerprint should be consistent for same inputs")

	// Verify different inputs produce different fingerprints
	for _, tt := range tests[1:] { // Skip first test case as it's identical to base
		t.Run(tt.name, func(t *testing.T) {
			fingerprint := GenerateFingerprint(tt.repoID, tt.ruleName, tt.filePath, tt.lineContent)
			assert.NotEmpty(t, fingerprint)
			assert.Equal(t, 64, len(fingerprint))
			assert.NotEqual(t, baseFingerprint, fingerprint, "fingerprint should differ when inputs change")
		})
	}
}

func TestGenerateFingerprint_DirectoryLength(t *testing.T) {
	repoID := "test-repo"
	ruleName := "test-rule"
	lineContent := "test content"

	// Test that directory length is correctly incorporated
	filePath1 := "a/file.go"     // dir length: 1
	filePath2 := "abc/file.go"   // dir length: 3
	filePath3 := "a/b/c/file.go" // dir length: 5

	fp1 := GenerateFingerprint(repoID, ruleName, filePath1, lineContent)
	fp2 := GenerateFingerprint(repoID, ruleName, filePath2, lineContent)
	fp3 := GenerateFingerprint(repoID, ruleName, filePath3, lineContent)

	// All should be different because directory lengths differ
	assert.NotEqual(t, fp1, fp2, "fingerprints should differ with different directory lengths")
	assert.NotEqual(t, fp2, fp3, "fingerprints should differ with different directory lengths")
	assert.NotEqual(t, fp1, fp3, "fingerprints should differ with different directory lengths")
}

func TestGenerateFingerprint_LineLength(t *testing.T) {
	repoID := "test-repo"
	ruleName := "test-rule"
	filePath := "src/main.go"

	// Test that line length is correctly incorporated
	lineContent1 := "a"
	lineContent2 := "abc"
	lineContent3 := "this is a longer line of code"

	fp1 := GenerateFingerprint(repoID, ruleName, filePath, lineContent1)
	fp2 := GenerateFingerprint(repoID, ruleName, filePath, lineContent2)
	fp3 := GenerateFingerprint(repoID, ruleName, filePath, lineContent3)

	// All should be different because line lengths differ
	assert.NotEqual(t, fp1, fp2, "fingerprints should differ with different line lengths")
	assert.NotEqual(t, fp2, fp3, "fingerprints should differ with different line lengths")
	assert.NotEqual(t, fp1, fp3, "fingerprints should differ with different line lengths")
}

func TestGenerateFingerprint_EmptyInputs(t *testing.T) {
	// Test with empty inputs to ensure no panics
	fp := GenerateFingerprint("", "", "", "")
	assert.NotEmpty(t, fp)
	assert.Equal(t, 64, len(fp))
}
