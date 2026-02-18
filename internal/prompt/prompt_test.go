package prompt

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
)

func TestPromptsHasOutputInstructions(t *testing.T) {
	for _, language := range model.GetAllLanguages() {
		for _, vuln := range model.GetAllVulnerabilities() {
			detectionContext := model.DetectionContext{
				Language: language,
				Rule:     api.AiPrompt{ID: vuln.ShortName(), Content: "test content with <code> and <path> and <relatedFilesInformation>"},
				Code:     "mycode",
				Path:     "/test/somecode",
			}

			result, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
			assert.NoError(t, err)
			assert.Contains(t, result, "mycode")
			assert.Contains(t, result, "/test/somecode")
		}
	}
}

func TestBuildDetectionUserPromptContent(t *testing.T) {
	detectionContext := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "sql-injection", Content: "Check for SQL injection in <code> at <path>. <relatedFilesInformation>"},
		Code:     "public class Test {}",
		Path:     "/test/file.java",
	}

	result, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)
	assert.Contains(t, result, "Check for SQL injection")
	assert.Contains(t, result, "public class Test {}")
	assert.Contains(t, result, "/test/file.java")
}

func TestBuildDetectionUserPrompt(t *testing.T) {
	detectionContext := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "sql-injection", Content: "Evaluate the following code located in <path>: <code>. <relatedFilesInformation>"},
		Code:     "public class Test {}",
		Path:     "/test/file.java",
	}

	result, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)
	assert.NotContains(t, result, "Related Files")
	assert.Contains(t, result, "Evaluate the following code located in /test/file.java")
	assert.Contains(t, result, "public class Test {}")
}

func TestBuildDetectionUserPromptOtherFiles(t *testing.T) {
	detectionContext := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "sql-injection", Content: "Evaluate the following code located in <path>: <code>. <relatedFilesInformation>"},
		Code:     "public class Test {}",
		Path:     "/test/file.java",
		RelatedFiles: []model.DetectionContextRelatedFile{
			{
				Path:    "path/to/foo.go",
				Content: "foobar",
			},
		},
	}

	result, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)
	assert.Contains(t, result, "Related Files")
	assert.Contains(t, result, "path/to/foo.go")
	assert.Contains(t, result, "Evaluate the following code located in /test/file.java")
	assert.Contains(t, result, "public class Test {}")
}

func TestBuildDetectionUserPromptOtherFilesTooLarge(t *testing.T) {
	detectionContext := model.DetectionContext{
		Language: model.Java,
		Rule:     api.AiPrompt{ID: "sql-injection", Content: "Evaluate the following code located in <path>: <code>. <relatedFilesInformation>"},
		Code:     "public class Test {}",
		Path:     "/test/file.java",
		RelatedFiles: []model.DetectionContextRelatedFile{
			{
				Path:    "path/to/foo.go",
				Content: "foobar",
			},
			{
				Path:    "path/to/foo.go",
				Content: strings.Repeat(strings.Repeat("X", CHARS_PER_TOKEN), MAX_TOKENS_IN_PROMPT),
			},
		},
	}

	result, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)
	assert.Contains(t, result, "Related Files")
	assert.Contains(t, result, "path/to/foo.go")
	assert.Contains(t, result, "Evaluate the following code located in /test/file.java")
	assert.Contains(t, result, "public class Test {}")
	assert.NotContains(t, result, "X")
}
