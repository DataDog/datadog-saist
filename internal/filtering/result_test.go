package filtering

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestFilterViolationsByMessageContent(t *testing.T) {
	violations := []model.Violation{
		{Message: "SQL injection vulnerability", StartLine: 10},
		{Message: "Cross-site scripting", StartLine: 20},
		{Message: "Buffer overflow", StartLine: 30},
		{Message: "Authentication bypass", StartLine: 40},
	}

	filtered := FilterViolations(violations, func(v model.Violation) bool {
		return v.Message == "SQL injection vulnerability"
	})

	assert.Len(t, filtered, 1, "expected 1 violation")
	assert.Equal(t, "SQL injection vulnerability", filtered[0].Message)
}

func TestFilterViolationsByLineNumber(t *testing.T) {
	violations := []model.Violation{
		{Message: "SQL injection vulnerability", StartLine: 10},
		{Message: "Cross-site scripting", StartLine: 20},
		{Message: "Buffer overflow", StartLine: 30},
		{Message: "Authentication bypass", StartLine: 40},
	}

	filtered := FilterViolations(violations, func(v model.Violation) bool {
		return v.StartLine > 25
	})

	assert.Len(t, filtered, 2, "expected 2 violations")
}

func TestFilterViolationsWithEmptySlice(t *testing.T) {
	var empty []model.Violation
	filtered := FilterViolations(empty, func(v model.Violation) bool {
		return true
	})

	assert.Empty(t, filtered, "expected 0 violations")
}

func TestFilterViolationsByKeywordsWithCommonKeywords(t *testing.T) {
	violations := []model.Violation{
		{Message: "SQL injection vulnerability", StartLine: 10},
		{Message: "This is a test violation", StartLine: 20},
		{Message: "DEBUG: potential issue here", StartLine: 30},
		{Message: "TODO: fix this later", StartLine: 40},
		{Message: "Cross-site scripting attack", StartLine: 50},
		{Message: "Temporary workaround needed", StartLine: 60},
	}

	keywords := []string{"test", "debug", "todo", "temporary"}
	filtered := FilterViolationsByKeywords(violations, keywords)

	expected := 2
	assert.Len(t, filtered, expected, "expected %d violations", expected)

	for _, violation := range filtered {
		assert.NotContains(t, []string{"This is a test violation", "DEBUG: potential issue here", "TODO: fix this later", "Temporary workaround needed"}, violation.Message, "violation with keyword was not filtered out")
	}
}

func TestFilterViolationsByKeywordsWithNoMatchingKeywords(t *testing.T) {
	violations := []model.Violation{
		{Message: "SQL injection vulnerability", StartLine: 10},
		{Message: "This is a test violation", StartLine: 20},
		{Message: "DEBUG: potential issue here", StartLine: 30},
		{Message: "TODO: fix this later", StartLine: 40},
		{Message: "Cross-site scripting attack", StartLine: 50},
		{Message: "Temporary workaround needed", StartLine: 60},
	}

	keywords := []string{"nonexistent", "missing"}
	filtered := FilterViolationsByKeywords(violations, keywords)

	assert.Len(t, filtered, len(violations), "expected %d violations", len(violations))
}

func TestFilterViolationsByKeywordsWithEmptyKeywords(t *testing.T) {
	violations := []model.Violation{
		{Message: "SQL injection vulnerability", StartLine: 10},
		{Message: "This is a test violation", StartLine: 20},
		{Message: "DEBUG: potential issue here", StartLine: 30},
		{Message: "TODO: fix this later", StartLine: 40},
		{Message: "Cross-site scripting attack", StartLine: 50},
		{Message: "Temporary workaround needed", StartLine: 60},
	}

	var keywords []string
	filtered := FilterViolationsByKeywords(violations, keywords)

	assert.Len(t, filtered, len(violations), "expected %d violations", len(violations))
}

func TestFilterViolationsByKeywordsCaseInsensitiveMatching(t *testing.T) {
	violations := []model.Violation{
		{Message: "SQL injection vulnerability", StartLine: 10},
		{Message: "This is a test violation", StartLine: 20},
		{Message: "DEBUG: potential issue here", StartLine: 30},
		{Message: "TODO: fix this later", StartLine: 40},
		{Message: "Cross-site scripting attack", StartLine: 50},
		{Message: "Temporary workaround needed", StartLine: 60},
	}

	keywords := []string{"DEBUG", "Test", "TODO"}
	filtered := FilterViolationsByKeywords(violations, keywords)

	expected := 3
	assert.Len(t, filtered, expected, "expected %d violations", expected)
	if len(filtered) != expected {
		for i, v := range filtered {
			t.Logf("remaining violation %d: %s", i, v.Message)
		}
	}
}

func TestFilterViolationsByKeywordsWithEmptyViolationsSlice(t *testing.T) {
	var empty []model.Violation
	keywords := []string{"test", "debug"}
	filtered := FilterViolationsByKeywords(empty, keywords)

	assert.Empty(t, filtered, "expected 0 violations")
}
