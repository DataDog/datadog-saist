package sarif

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

func TestAddPropertyTag(t *testing.T) {
	t.Run("add tag to empty properties", func(t *testing.T) {
		properties := sarif.Properties{}
		result := AddPropertyTag(properties, "TEST_TAG", "test_value")

		assert.NotNil(t, result)
		tagsInterface, ok := result[tagsKey]
		assert.True(t, ok)

		tags := tagsInterface.([]any)
		assert.Len(t, tags, 1)
		assert.Equal(t, "TEST_TAG:test_value", tags[0])
	})

	t.Run("add tag to existing properties", func(t *testing.T) {
		properties := sarif.Properties{
			tagsKey: []any{"EXISTING_TAG:existing_value"},
		}
		result := AddPropertyTag(properties, "NEW_TAG", "new_value")

		tagsInterface, ok := result[tagsKey]
		assert.True(t, ok)

		tags := tagsInterface.([]any)
		assert.Len(t, tags, 2)
		assert.Equal(t, "EXISTING_TAG:existing_value", tags[0])
		assert.Equal(t, "NEW_TAG:new_value", tags[1])
	})

	t.Run("add multiple tags", func(t *testing.T) {
		properties := sarif.Properties{}
		properties = AddPropertyTag(properties, "TAG1", "value1")
		properties = AddPropertyTag(properties, "TAG2", "value2")
		properties = AddPropertyTag(properties, "TAG3", "value3")

		tagsInterface, ok := properties[tagsKey]
		assert.True(t, ok)

		tags := tagsInterface.([]any)
		assert.Len(t, tags, 3)
	})
}

func TestCreateResult_WithFingerprint(t *testing.T) {
	cwe := "89"
	violation := model.Violation{
		Rule:        "sql-injection",
		Cwe:         &cwe,
		Path:        "src/main/java/App.java",
		FileHash:    "abc123",
		StartLine:   42,
		Message:     "Potential SQL injection vulnerability",
		Fingerprint: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}

	// When no rule description is provided, message should be the violation message
	result := createResult(&violation, map[string]string{}, map[string]int{})

	// Verify basic fields
	assert.NotNil(t, result)
	assert.Equal(t, "sql-injection", *result.RuleID)
	assert.Equal(t, "Potential SQL injection vulnerability", *result.Message.Text)
	assert.Equal(t, "warning", *result.Level)

	// Verify location
	assert.Len(t, result.Locations, 1)
	assert.Equal(t, "src/main/java/App.java", *result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 42, *result.Locations[0].PhysicalLocation.Region.StartLine)

	// Verify fingerprint is present
	assert.NotNil(t, result.PartialFingerprints)
	fingerprint, ok := result.PartialFingerprints["DATADOG_FINGERPRINT"]
	assert.True(t, ok, "DATADOG_FINGERPRINT should be present")
	assert.Equal(t, violation.Fingerprint, fingerprint)

	// Verify CWE property
	assert.NotNil(t, result.Properties)
	tagsInterface, ok := result.Properties[tagsKey]
	assert.True(t, ok)
	tags := tagsInterface.([]any)
	assert.Contains(t, tags, "CWE:89")

	// Verify confidence properties
	assert.Contains(t, tags, "DATADOG_CONFIDENCE:HIGH")
	assert.Contains(t, tags, "DATADOG_CONFIDENCE_REASON:Potential SQL injection vulnerability")
}

func TestCreateResult_WithoutFingerprint(t *testing.T) {
	violation := model.Violation{
		Rule:        "xss",
		Cwe:         nil,
		Path:        "src/main.go",
		FileHash:    "def456",
		StartLine:   10,
		Message:     "Cross-site scripting vulnerability",
		Fingerprint: "", // No fingerprint
	}

	result := createResult(&violation, map[string]string{}, map[string]int{})

	// Verify basic fields
	assert.NotNil(t, result)
	assert.Equal(t, "xss", *result.RuleID)

	// Verify fingerprint is NOT present when empty
	if result.PartialFingerprints != nil {
		_, ok := result.PartialFingerprints["DATADOG_FINGERPRINT"]
		assert.False(t, ok, "DATADOG_FINGERPRINT should not be present when fingerprint is empty")
	}

	// Verify confidence properties are still present
	assert.NotNil(t, result.Properties)
	tagsInterface, ok := result.Properties[tagsKey]
	assert.True(t, ok)
	tags := tagsInterface.([]any)
	assert.Contains(t, tags, "DATADOG_CONFIDENCE:HIGH")
}

func TestCreateResult_WithoutCwe(t *testing.T) {
	violation := model.Violation{
		Rule:        "custom-rule",
		Cwe:         nil,
		Path:        "test.py",
		StartLine:   5,
		Message:     "Custom vulnerability",
		Fingerprint: "abcd1234",
	}

	result := createResult(&violation, map[string]string{}, map[string]int{})

	assert.NotNil(t, result)
	assert.Equal(t, "custom-rule", *result.RuleID)

	// Verify fingerprint is still present
	assert.NotNil(t, result.PartialFingerprints)
	assert.Equal(t, "abcd1234", result.PartialFingerprints["DATADOG_FINGERPRINT"])

	// Properties should contain confidence but not CWE
	assert.NotNil(t, result.Properties)
	tagsInterface, ok := result.Properties[tagsKey]
	assert.True(t, ok)
	tags := tagsInterface.([]any)
	// Should not contain CWE tag
	for _, tag := range tags {
		assert.NotContains(t, tag.(string), "CWE:")
	}
	// Should contain confidence
	assert.Contains(t, tags, "DATADOG_CONFIDENCE:HIGH")
}

func TestGenerateSarifReport_WithFingerprints(t *testing.T) {
	cwe1 := "89"
	cwe2 := "79"

	violations := []model.Violation{
		{
			Rule:        "sql-injection",
			Cwe:         &cwe1,
			Path:        "src/db.go",
			StartLine:   20,
			Message:     "SQL injection found",
			Fingerprint: "fp1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		},
		{
			Rule:        "xss",
			Cwe:         &cwe2,
			Path:        "src/web.go",
			StartLine:   15,
			Message:     "XSS vulnerability found",
			Fingerprint: "fp9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
		},
	}

	rules := []api.AiPrompt{
		{
			ID:               "sql-injection",
			ShortDescription: "SQL Injection Detection",
			Description:      "Detects potential SQL injection vulnerabilities",
			Cwe:              &cwe1,
			Severity:         api.SeverityError,
			Category:         api.CategorySecurity,
		},
		{
			ID:               "xss",
			ShortDescription: "XSS Detection",
			Description:      "Detects cross-site scripting vulnerabilities",
			Cwe:              &cwe2,
			Severity:         api.SeverityWarning,
			Category:         api.CategorySecurity,
		},
	}

	fileResults := []model.FileResult{
		{
			Path:           "src/db.go",
			RulesSucceeded: []string{"sql-injection"},
			RulesFailed:    []string{},
		},
		{
			Path:           "src/web.go",
			RulesSucceeded: []string{"xss"},
			RulesFailed:    []string{},
		},
	}

	sarifInfo := SarifReportInformation{
		Violations:   violations,
		InputTokens:  1000,
		OutputTokens: 500,
		FileResults:  fileResults,
		Rules:        rules,
	}

	report, err := GenerateSarifReport(&sarifInfo)

	// Verify report generation
	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Len(t, report.Runs, 1)

	run := report.Runs[0]

	// Verify results
	assert.Len(t, run.Results, 2)

	// Check first result
	result1 := run.Results[0]
	assert.Equal(t, "sql-injection", *result1.RuleID)
	assert.NotNil(t, result1.PartialFingerprints)
	fingerprint1, ok := result1.PartialFingerprints["DATADOG_FINGERPRINT"]
	assert.True(t, ok)
	assert.Equal(t, violations[0].Fingerprint, fingerprint1)

	// Check second result
	result2 := run.Results[1]
	assert.Equal(t, "xss", *result2.RuleID)
	assert.NotNil(t, result2.PartialFingerprints)
	fingerprint2, ok := result2.PartialFingerprints["DATADOG_FINGERPRINT"]
	assert.True(t, ok)
	assert.Equal(t, violations[1].Fingerprint, fingerprint2)

	// Verify rules
	assert.Len(t, run.Tool.Driver.Rules, 2)

	// Verify token counts in properties
	assert.NotNil(t, run.Properties)
	tagsInterface, ok := run.Properties[tagsKey]
	assert.True(t, ok)
	tags := tagsInterface.([]any)
	assert.Contains(t, tags, "DATADOG_SAIST_INPUT_TOKENS:1000")
	assert.Contains(t, tags, "DATADOG_SAIST_OUTPUT_TOKENS:500")
}

func TestGenerateSarifReport_MixedFingerprints(t *testing.T) {
	// Test with some violations having fingerprints and others not
	cwe := "89"
	violations := []model.Violation{
		{
			Rule:        "rule1",
			Cwe:         &cwe,
			Path:        "file1.go",
			StartLine:   10,
			Message:     "Issue 1",
			Fingerprint: "has_fingerprint_123456789012345678901234567890123456789012345678",
		},
		{
			Rule:        "rule2",
			Cwe:         &cwe,
			Path:        "file2.go",
			StartLine:   20,
			Message:     "Issue 2",
			Fingerprint: "", // No fingerprint
		},
	}

	rules := []api.AiPrompt{
		{
			ID:               "rule1",
			ShortDescription: "Rule 1",
			Description:      "Test rule 1",
			Cwe:              &cwe,
			Severity:         api.SeverityError,
		},
		{
			ID:               "rule2",
			ShortDescription: "Rule 2",
			Description:      "Test rule 2",
			Cwe:              &cwe,
			Severity:         api.SeverityError,
		},
	}

	sarifInfo := SarifReportInformation{
		Violations:   violations,
		InputTokens:  100,
		OutputTokens: 50,
		FileResults:  []model.FileResult{},
		Rules:        rules,
	}

	report, err := GenerateSarifReport(&sarifInfo)

	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Len(t, report.Runs[0].Results, 2)

	// First result should have fingerprint
	result1 := report.Runs[0].Results[0]
	assert.NotNil(t, result1.PartialFingerprints)
	_, ok := result1.PartialFingerprints["DATADOG_FINGERPRINT"]
	assert.True(t, ok)

	// Second result should not have fingerprint
	result2 := report.Runs[0].Results[1]
	if result2.PartialFingerprints != nil {
		_, ok := result2.PartialFingerprints["DATADOG_FINGERPRINT"]
		assert.False(t, ok)
	}
}

func TestGenerateSarifReport_EmptyViolations(t *testing.T) {
	sarifInfo := SarifReportInformation{
		Violations:   []model.Violation{},
		InputTokens:  0,
		OutputTokens: 0,
		FileResults:  []model.FileResult{},
		Rules:        []api.AiPrompt{},
	}

	report, err := GenerateSarifReport(&sarifInfo)

	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Len(t, report.Runs, 1)
	assert.Len(t, report.Runs[0].Results, 0)
}

func TestGenerateSarifReport_RuleMetadata(t *testing.T) {
	cwe := "89"
	rule := api.AiPrompt{
		ID:               "test-rule",
		ShortDescription: "Test Rule",
		Description:      "This is a test rule",
		Cwe:              &cwe,
		Severity:         api.SeverityError,
		Category:         api.CategorySecurity,
	}

	sarifInfo := SarifReportInformation{
		Violations:   []model.Violation{},
		InputTokens:  0,
		OutputTokens: 0,
		FileResults:  []model.FileResult{},
		Rules:        []api.AiPrompt{rule},
	}

	report, err := GenerateSarifReport(&sarifInfo)

	assert.NoError(t, err)
	assert.NotNil(t, report)

	run := report.Runs[0]
	assert.Len(t, run.Tool.Driver.Rules, 1)

	ruleDescriptor := run.Tool.Driver.Rules[0]
	assert.Equal(t, "test-rule", ruleDescriptor.ID)
	assert.Equal(t, "Test Rule", *ruleDescriptor.ShortDescription.Text)
	assert.Equal(t, "This is a test rule", *ruleDescriptor.FullDescription.Text)

	// Verify rule properties contain CWE, severity, and category
	assert.NotNil(t, ruleDescriptor.Properties)
	tagsInterface, ok := ruleDescriptor.Properties[tagsKey]
	assert.True(t, ok)
	tags := tagsInterface.([]any)
	assert.Contains(t, tags, "CWE:89")
	assert.Contains(t, tags, "SEVERITY:ERROR")
	assert.Contains(t, tags, "CATEGORY:SECURITY")
	assert.Contains(t, tags, "DATADOG_RULE_TYPE:datadog-ai-static-analyzer")
}

func TestGenerateSarifReport_ToolVersion(t *testing.T) {
	sarifInfo := SarifReportInformation{
		Violations:   []model.Violation{},
		InputTokens:  0,
		OutputTokens: 0,
		FileResults:  []model.FileResult{},
		Rules:        []api.AiPrompt{},
	}

	report, err := GenerateSarifReport(&sarifInfo)

	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Len(t, report.Runs, 1)

	run := report.Runs[0]

	// Verify tool driver metadata
	assert.NotNil(t, run.Tool.Driver)
	assert.Equal(t, toolName, run.Tool.Driver.Name)
	assert.NotNil(t, run.Tool.Driver.Version, "Tool version should be set")
	assert.Equal(t, model.EngineVersion, *run.Tool.Driver.Version)
	assert.NotNil(t, run.Tool.Driver.InformationURI, "Tool information URI should be set")
	assert.Equal(t, toolInformationURI, *run.Tool.Driver.InformationURI)
}

func TestGenerateSarifReport_ConfidenceAndMessageReplacement(t *testing.T) {
	cwe := "89"
	violationMessage := "User input flows into SQL query without sanitization"
	ruleShortDescription := "SQL Injection Detection"

	violations := []model.Violation{
		{
			Rule:        "sql-injection",
			Cwe:         &cwe,
			Path:        "src/db.go",
			StartLine:   20,
			Message:     violationMessage,
			Fingerprint: "fp123",
		},
	}

	rules := []api.AiPrompt{
		{
			ID:               "sql-injection",
			ShortDescription: ruleShortDescription,
			Description:      "Detects potential SQL injection vulnerabilities where user-controlled input is concatenated into SQL queries",
			Cwe:              &cwe,
			Severity:         api.SeverityError,
			Category:         api.CategorySecurity,
		},
	}

	sarifInfo := SarifReportInformation{
		Violations:   violations,
		InputTokens:  100,
		OutputTokens: 50,
		FileResults:  []model.FileResult{},
		Rules:        rules,
	}

	report, err := GenerateSarifReport(&sarifInfo)

	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Len(t, report.Runs[0].Results, 1)

	result := report.Runs[0].Results[0]

	// Verify message is replaced with rule short description
	assert.Equal(t, ruleShortDescription, *result.Message.Text, "Result message should be the rule short description")

	// Verify confidence properties
	assert.NotNil(t, result.Properties)
	tagsInterface, ok := result.Properties[tagsKey]
	assert.True(t, ok)
	tags := tagsInterface.([]any)

	// Verify DATADOG_CONFIDENCE is HIGH
	assert.Contains(t, tags, "DATADOG_CONFIDENCE:HIGH")

	// Verify DATADOG_CONFIDENCE_REASON is the original violation message
	expectedReasonTag := "DATADOG_CONFIDENCE_REASON:" + violationMessage
	assert.Contains(t, tags, expectedReasonTag, "Confidence reason should be the original violation message")
}

func TestCreateResult_WithRuleDescription(t *testing.T) {
	cwe := "79"
	violation := model.Violation{
		Rule:        "xss",
		Cwe:         &cwe,
		Path:        "src/web.go",
		StartLine:   15,
		Message:     "Original violation message",
		Fingerprint: "fp456",
	}

	ruleDescriptions := map[string]string{
		"xss": "Cross-site scripting vulnerability detected",
	}
	ruleIndices := map[string]int{
		"xss": 0,
	}

	result := createResult(&violation, ruleDescriptions, ruleIndices)

	// Verify message is replaced with rule description
	assert.Equal(t, "Cross-site scripting vulnerability detected", *result.Message.Text)

	// Verify rule index is set
	assert.NotNil(t, result.RuleIndex)
	assert.Equal(t, uint(0), *result.RuleIndex)

	// Verify confidence reason is the original message
	assert.NotNil(t, result.Properties)
	tagsInterface, ok := result.Properties[tagsKey]
	assert.True(t, ok)
	tags := tagsInterface.([]any)
	assert.Contains(t, tags, "DATADOG_CONFIDENCE_REASON:Original violation message")
}

func TestGenerateSarifReport_RuleIndex(t *testing.T) {
	cwe := "89"

	violations := []model.Violation{
		{
			Rule:      "sql-injection",
			Cwe:       &cwe,
			Path:      "src/db.go",
			StartLine: 20,
			Message:   "SQL issue found",
		},
		{
			Rule:      "xss",
			Cwe:       &cwe,
			Path:      "src/web.go",
			StartLine: 30,
			Message:   "XSS issue found",
		},
	}

	rules := []api.AiPrompt{
		{
			ID:               "sql-injection",
			ShortDescription: "SQL Injection",
			Description:      "SQL Injection vulnerability",
			Cwe:              &cwe,
		},
		{
			ID:               "xss",
			ShortDescription: "XSS",
			Description:      "Cross-site scripting vulnerability",
			Cwe:              &cwe,
		},
	}

	sarifInfo := SarifReportInformation{
		Violations:   violations,
		InputTokens:  100,
		OutputTokens: 50,
		FileResults:  []model.FileResult{},
		Rules:        rules,
	}

	report, err := GenerateSarifReport(&sarifInfo)

	assert.NoError(t, err)
	assert.NotNil(t, report)
	assert.Len(t, report.Runs[0].Results, 2)

	// First result should have ruleIndex 0 (sql-injection is first rule)
	result1 := report.Runs[0].Results[0]
	assert.Equal(t, "sql-injection", *result1.RuleID)
	assert.NotNil(t, result1.RuleIndex)
	assert.Equal(t, uint(0), *result1.RuleIndex)

	// Second result should have ruleIndex 1 (xss is second rule)
	result2 := report.Runs[0].Results[1]
	assert.Equal(t, "xss", *result2.RuleID)
	assert.NotNil(t, result2.RuleIndex)
	assert.Equal(t, uint(1), *result2.RuleIndex)
}
