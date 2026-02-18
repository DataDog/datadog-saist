package analysis

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/bmatcuk/doublestar/v4"
	"github.com/stretchr/testify/assert"
)

// Helper to create a test rule
func createTestRule() api.AiPrompt {
	cwe := "89"
	return api.AiPrompt{
		ID:               "sql-injection-test",
		Description:      "Detects potential SQL injection vulnerabilities in Go code",
		ShortDescription: "SQL Injection Detection",
		Content:          "Analyze the following Go code for SQL injection vulnerabilities where user input is directly concatenated into SQL queries: <code>",
		Globs:            []string{"*.go"},
		Cwe:              &cwe,
		Severity:         api.SeverityError,
		Category:         api.CategorySecurity,
		ExecutionMode:    api.ExecutionModeAuto,
		IsDefault:        true,
		IsTesting:        true,
		Checksum:         "test-checksum",
		Version:          "v1.0",
	}
}

func TestCreateTestRule(t *testing.T) {
	// Test our helper function
	rule := createTestRule()

	assert.Equal(t, "sql-injection-test", rule.ID)
	assert.Equal(t, "SQL Injection Detection", rule.ShortDescription)
	assert.Equal(t, api.SeverityError, rule.Severity)
	assert.Equal(t, api.CategorySecurity, rule.Category)
	assert.NotNil(t, rule.Cwe)
	assert.Equal(t, "89", *rule.Cwe)
	assert.Contains(t, rule.Globs, "*.go")
}

func TestRuleFileMatching(t *testing.T) {
	// Test cases for rule-specific file matching
	testCases := []struct {
		ruleGlobs   []string
		fileName    string
		shouldMatch bool
		description string
	}{
		{[]string{"*.go"}, "main.go", true, "Go rule should match Go file"},
		{[]string{"*.java"}, "Main.java", true, "Java rule should match Java file"},
		{[]string{"*.py"}, "script.py", true, "Python rule should match Python file"},
		{[]string{"*.go"}, "Main.java", false, "Go rule should not match Java file"},
		{[]string{"*.java"}, "script.py", false, "Java rule should not match Python file"},
		{[]string{"*.py"}, "main.go", false, "Python rule should not match Go file"},
		{[]string{"**/*.go", "**/*.java"}, "src/main/java/App.java", true, "Multi-glob rule should match Java file"},
		{[]string{"**/*.go", "**/*.java"}, "src/utils/script.py", false, "Multi-glob rule should not match Python file"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			// Create a rule with specific globs
			rule := createTestRuleWithGlobs(tc.ruleGlobs)

			// Test the matching logic (simulating what happens in analyzer.go)
			ruleMatches := false
			for _, ruleGlob := range rule.Globs {
				// Using the same doublestar.Match logic as in the analyzer
				if match, _ := doublestar.Match(ruleGlob, tc.fileName); match {
					ruleMatches = true
					break
				}
			}

			if tc.shouldMatch {
				assert.True(t, ruleMatches, "Expected rule to match file %s", tc.fileName)
			} else {
				assert.False(t, ruleMatches, "Expected rule to NOT match file %s", tc.fileName)
			}
		})
	}
}

// Helper to create a test rule with specific globs
func createTestRuleWithGlobs(globs []string) api.AiPrompt {
	cwe := "89"
	return api.AiPrompt{
		ID:               "test-rule",
		Description:      "Test rule for file matching",
		ShortDescription: "Test Rule",
		Content:          "Test content",
		Globs:            globs,
		Cwe:              &cwe,
		Severity:         api.SeverityError,
		Category:         api.CategorySecurity,
		ExecutionMode:    api.ExecutionModeAuto,
		IsDefault:        true,
		IsTesting:        true,
		Checksum:         "test-checksum",
		Version:          "v1.0",
	}
}
