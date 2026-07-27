package candidates

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestCandidateIDIsStable(t *testing.T) {
	input := candidateInputForTest()
	first, err := NewCandidate(input)
	assert.NoError(t, err)
	second, err := NewCandidate(input)
	assert.NoError(t, err)

	assert.Equal(t, first.ID, second.ID)
	assert.Equal(t, first.SinkLineHash, second.SinkLineHash)
	assert.Equal(t, first.SourceFileHash, second.SourceFileHash)
}

func TestCandidateIDDoesNotDependOnDetectionReason(t *testing.T) {
	firstInput := candidateInputForTest()
	first, err := NewCandidate(firstInput)
	assert.NoError(t, err)

	secondInput := candidateInputForTest()
	secondInput.DetectionReason = "A different model explanation"
	second, err := NewCandidate(secondInput)
	assert.NoError(t, err)

	assert.Equal(t, first.ID, second.ID)
	assert.NotEqual(t, first.DetectionReason, second.DetectionReason)
}

func TestCandidateSinkLineHashNormalizesWhitespace(t *testing.T) {
	firstInput := candidateInputForTest()
	firstInput.Source = []byte("\t database.Query( value,  other )  \r\n")
	first, err := NewCandidate(firstInput)
	assert.NoError(t, err)

	secondInput := candidateInputForTest()
	secondInput.Source = []byte("database.Query( value, other )\n")
	second, err := NewCandidate(secondInput)
	assert.NoError(t, err)

	assert.Equal(t, first.SinkLineHash, second.SinkLineHash)
	assert.Equal(t, first.ID, second.ID)
	assert.NotEqual(t, first.SourceFileHash, second.SourceFileHash)
}

func TestCandidateIDUsesRepositoryRelativePath(t *testing.T) {
	firstInput := candidateInputForTest()
	firstInput.ScanRoot = "domains/static-analysis"
	firstInput.RelativeFilePath = "apps/service/main.go"
	first, err := NewCandidate(firstInput)
	assert.NoError(t, err)

	secondInput := candidateInputForTest()
	secondInput.ScanRoot = ""
	secondInput.RelativeFilePath = "domains/static-analysis/apps/service/main.go"
	second, err := NewCandidate(secondInput)
	assert.NoError(t, err)

	assert.Equal(t, first.RepositoryRelativePath(), second.RepositoryRelativePath())
	assert.Equal(t, first.ID, second.ID)
}

func candidateInputForTest() NewCandidateInput {
	cwe := "89"
	return NewCandidateInput{
		RepositoryID:     "repository-123",
		RepositorySHA:    strings.Repeat("a", 40),
		RepositoryDirty:  false,
		ScanRoot:         "domains/example",
		RelativeFilePath: "service/main.go",
		Source:           []byte("  database.Query(query)  \r\n"),
		Rule: api.AiPrompt{
			ID:                    "go-security/sql-injection",
			Description:           "Detect SQL injection",
			ShortDescription:      "SQL injection",
			Content:               "Find SQL queries built from untrusted input.",
			Globs:                 []string{"**/*.go"},
			Directories:           []string{"service"},
			ExecutionMode:         api.ExecutionModeAuto,
			Cwe:                   &cwe,
			Checksum:              "rule-checksum",
			Severity:              api.SeverityError,
			Category:              api.CategorySecurity,
			IsTesting:             false,
			IsDefault:             true,
			Version:               "1.2.3",
			ResultKeywordsExclude: []string{"safe helper"},
			FileSearchKeywords:    []string{"Query("},
		},
		StartLine:       1,
		StartColumn:     3,
		EndLine:         1,
		EndColumn:       24,
		DetectionReason: "Untrusted data reaches a SQL query.",
		DetectionMode:   DetectionModeStandard,
	}
}
