package prompt

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/utils"
)

// how many characters per token on average
const CHARS_PER_TOKEN = 5
const MAX_TOKENS_IN_PROMPT = 8000
const maxRelatedFiles = 10

// PromptTemplate is a simple wrapper around Go's text/template
type PromptTemplate struct {
	template *template.Template
}

// NewPromptTemplate creates a new prompt template using Go's text/template
func NewPromptTemplate(templateStr string) *PromptTemplate {
	tmpl, err := template.New("prompt").Option("missingkey=error").Parse(templateStr)
	if err != nil {
		panic(fmt.Sprintf("failed to parse template: %v", err))
	}
	return &PromptTemplate{template: tmpl}
}

// Format executes the template with the given variables
func (pt *PromptTemplate) Format(variables map[string]any) (string, error) {
	var buf bytes.Buffer
	err := pt.template.Execute(&buf, variables)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %v", err)
	}
	return buf.String(), nil
}

//go:embed templates/detection/mainprompt.txt
var SystemPromptBytes []byte

func getNumberOfTokens(s string) int {
	return len(s) / CHARS_PER_TOKEN
}

func buildStableRulePrompt(ruleContent string) string {
	rulePrompt := strings.ReplaceAll(ruleContent, "<path>", analyzedFilePathReference)
	rulePrompt = strings.ReplaceAll(rulePrompt, "<code>", analyzedCodeReference)
	return strings.ReplaceAll(rulePrompt, "<relatedFilesInformation>", relatedFilesReference)
}

func buildAnalyzedFileSection(path, numberedCode string) string {
	return "\n\n" + AnalyzedFileSectionHeader + "\n\nPath: " + path + "\n\n```\n" + numberedCode + "\n```\n"
}

func BuildDetectionUserPrompt(ctx context.Context, detectionContext *model.DetectionContext, debugEnabled ...bool) (string, error) {
	systemPrompt := string(SystemPromptBytes)

	systemPromptTokens := getNumberOfTokens(systemPrompt)

	allFiles := make([]string, 0)
	includedFiles := make([]string, 0)

	for _, relatedFile := range detectionContext.RelatedFiles {
		allFiles = append(allFiles, relatedFile.Path)
	}

	// Keep reusable rule instructions before request-specific file content so provider
	// prefix caches can reuse the longest possible prefix.
	stableRulePrompt := buildStableRulePrompt(detectionContext.Rule.Content)
	numberedCode := utils.AddLineNumbers(detectionContext.Code)
	analyzedFileSection := buildAnalyzedFileSection(detectionContext.Path, numberedCode)

	relatedFilesSection := ""
	if len(detectionContext.RelatedFiles) > 0 {
		const header = "\n## Related Files\n"
		accumulated := header

		for _, relatedFile := range detectionContext.RelatedFiles {
			if len(includedFiles) >= maxRelatedFiles {
				break
			}
			entry := "\n### " + relatedFile.Path + "\n" + "```\n" + relatedFile.Content + "\n```\n\n"
			candidate := accumulated + entry
			tempPrompt := stableRulePrompt + analyzedFileSection + candidate
			nbTokens := systemPromptTokens + getNumberOfTokens(tempPrompt)
			if nbTokens > MAX_TOKENS_IN_PROMPT {
				// (Implemented as spread params to avoid needing to refactor all tests)
				if len(debugEnabled) > 0 && debugEnabled[0] {
					log.FromContext(ctx).
						Warnf("Too many tokens in detection context, dropping some related "+
							"files (analyzed file %s, included files: %v, all files: %v)",
							detectionContext.Path, includedFiles, allFiles)
				}
				break
			}

			accumulated = candidate
			includedFiles = append(includedFiles, relatedFile.Path)
		}

		if len(includedFiles) > 0 {
			relatedFilesSection = accumulated
		}
	}

	return stableRulePrompt + analyzedFileSection + relatedFilesSection, nil
}
