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
	assert.Contains(t, result, "Evaluate the following code located in "+analyzedFilePathReference)
	assert.Contains(t, result, "Path: /test/file.java")
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
	assert.Contains(t, result, "Evaluate the following code located in "+analyzedFilePathReference)
	assert.Contains(t, result, "Path: /test/file.java")
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
	assert.Contains(t, result, "Evaluate the following code located in "+analyzedFilePathReference)
	assert.Contains(t, result, "Path: /test/file.java")
	assert.Contains(t, result, "public class Test {}")
	assert.NotContains(t, result, "X")
}

func TestBuildDetectionUserPrompt_RelatedFilesHeaderAppearsOnce(t *testing.T) {
	detectionContext := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "test-rule", Content: "Code: <code>\n<relatedFilesInformation>"},
		Code:     "func main() {}",
		Path:     "main.go",
		RelatedFiles: []model.DetectionContextRelatedFile{
			{Path: "helper.go", Content: "func Helper() {}"},
			{Path: "utils.go", Content: "func Util() {}"},
		},
	}

	result, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)
	assert.Equal(t, 1, strings.Count(result, "## Related Files"),
		"Related Files header must appear exactly once with multiple related files")
	assert.Contains(t, result, "### helper.go")
	assert.Contains(t, result, "### utils.go")
}

func TestBuildDetectionUserPrompt_RelatedFilesAllRendered(t *testing.T) {
	detectionContext := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "test-rule", Content: "Code: <code>\n<relatedFilesInformation>"},
		Code:     "func main() {}",
		Path:     "main.go",
		RelatedFiles: []model.DetectionContextRelatedFile{
			{Path: "alpha.go", Content: "alpha content"},
			{Path: "beta.go", Content: "beta content"},
		},
	}

	result, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)
	assert.Contains(t, result, "### alpha.go")
	assert.Contains(t, result, "alpha content")
	assert.Contains(t, result, "### beta.go")
	assert.Contains(t, result, "beta content")
	// Verify ordering: alpha appears before beta
	assert.Less(t, strings.Index(result, "alpha.go"), strings.Index(result, "beta.go"),
		"related files must appear in the order they were provided")
}

func TestBuildDetectionUserPrompt_ReusableRulePrefixPrecedesDynamicFileContent(t *testing.T) {
	ruleContent := "Evaluate <path> for SQL injection:\n<code>\n<relatedFilesInformation>\nReusable example."
	detectionContext := model.DetectionContext{
		Language: model.Go,
		Rule:     api.AiPrompt{ID: "sql-injection", Content: ruleContent},
		Code:     "func first() {}",
		Path:     "first.go",
	}

	firstPrompt, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)

	detectionContext.Code = "func second() {}"
	detectionContext.Path = "second.go"
	secondPrompt, err := BuildDetectionUserPrompt(context.Background(), &detectionContext)
	assert.NoError(t, err)

	firstBoundary := strings.Index(firstPrompt, analyzedFileSectionHeader)
	secondBoundary := strings.Index(secondPrompt, analyzedFileSectionHeader)
	assert.Positive(t, firstBoundary)
	assert.Equal(t, firstPrompt[:firstBoundary], secondPrompt[:secondBoundary])
	assert.Less(t, strings.Index(firstPrompt, "Reusable example."), strings.Index(firstPrompt, "first.go"))
	assert.Less(t, strings.Index(firstPrompt, "Reusable example."), strings.Index(firstPrompt, "func first() {}"))
}
