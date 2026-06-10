package agents

import (
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/stretchr/testify/assert"
)

func TestParseLocationDeterminationResult_DirectJSON(t *testing.T) {
	content := `{"startLine":10,"startColumn":1,"endLine":10,"endColumn":25}`
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(10), got.StartLine)
	assert.Equal(t, uint(1), got.StartColumn)
	assert.Equal(t, uint(10), got.EndLine)
	assert.Equal(t, uint(25), got.EndColumn)
}

func TestParseLocationDeterminationResult_JSONCodeBlock(t *testing.T) {
	content := "x\n```json\n{\"startLine\":3,\"startColumn\":5,\"endLine\":3,\"endColumn\":20}\n```\n"
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(3), got.StartLine)
	assert.Equal(t, uint(5), got.StartColumn)
}

func TestParseLocationDeterminationResult_WrappedContentObject(t *testing.T) {
	content := `{"content":{"startLine":7,"startColumn":2,"endLine":8,"endColumn":10}}`
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(7), got.StartLine)
	assert.Equal(t, uint(8), got.EndLine)
}

func TestParseLocationDeterminationResult_DirectPreferredOverEmptyContentWrapper(t *testing.T) {
	// Top-level coordinates must win; a zero "content" object must not mask valid fields.
	content := `{"startLine":4,"startColumn":1,"endLine":4,"endColumn":9,"content":{}}`
	got, err := parseLocationDeterminationResult(content)
	assert.Nil(t, err)
	assert.Equal(t, uint(4), got.StartLine)
}

func TestParseLocationDeterminationResult_InvalidJSON(t *testing.T) {
	_, err := parseLocationDeterminationResult(`{not json`)
	assert.NotNil(t, err)
}

func TestPhysicalLineLocation(t *testing.T) {
	got, ok := physicalLineLocation("abc\nx\n", 2)
	assert.True(t, ok)
	assert.Equal(t, LocationDeterminationResultData{
		StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 2,
	}, got)

	_, ok = physicalLineLocation("abc", 2)
	assert.False(t, ok)
}

func TestValidateLocationDetermination_EndBeforeStart(t *testing.T) {
	err := validateLocationDetermination(LocationDeterminationResultData{
		StartLine: 5, StartColumn: 1, EndLine: 4, EndColumn: 10,
	})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "endLine")
}

func TestLocationFitsFile(t *testing.T) {
	d := LocationDeterminationResultData{StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 5}
	assert.True(t, locationFitsFile(d, "a\nb\nc"))
	assert.False(t, locationFitsFile(d, "onlyone"))
	assert.False(t, locationFitsFile(LocationDeterminationResultData{
		StartLine: 1, StartColumn: 1, EndLine: 99, EndColumn: 2,
	}, "a\nb"))
}

func TestGetLocationDeterminationUserPrompt_ReusableRulePrefixPrecedesDynamicFinding(t *testing.T) {
	rule := api.AiPrompt{Content: "Reusable path traversal rule instructions"}
	firstScanData := &model.ScanData{
		RelativeFilePath: "first.go",
		FileContent:      &model.FileContent{Text: "func first() {}"},
		Rule:             &rule,
	}
	secondScanData := &model.ScanData{
		RelativeFilePath: "second.go",
		FileContent:      &model.FileContent{Text: "func second() {}"},
		Rule:             &rule,
	}

	firstPrompt := getLocationDeterminationUserPrompt(
		firstScanData,
		model.LLMResultViolation{Reason: "first finding"},
		&VerificationResult{VerificationResultData: VerificationResultData{Reason: "first verification"}},
	)
	secondPrompt := getLocationDeterminationUserPrompt(
		secondScanData,
		model.LLMResultViolation{Reason: "second finding"},
		&VerificationResult{VerificationResultData: VerificationResultData{Reason: "second verification"}},
	)

	firstBoundary := strings.Index(firstPrompt, "Request-Specific Finding:")
	secondBoundary := strings.Index(secondPrompt, "Request-Specific Finding:")
	assert.Positive(t, firstBoundary)
	assert.Positive(t, secondBoundary)
	assert.Equal(t, firstPrompt[:firstBoundary], secondPrompt[:secondBoundary])
	assert.Contains(t, firstPrompt[:firstBoundary], rule.Content)
	assert.NotContains(t, firstPrompt[:firstBoundary], firstScanData.RelativeFilePath)
	assert.NotContains(t, firstPrompt[:firstBoundary], firstScanData.FileContent.Text)
}
