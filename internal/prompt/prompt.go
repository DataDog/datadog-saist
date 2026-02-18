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

// PromptTemplate is a simple wrapper around Go's text/template
type PromptTemplate struct {
	template *template.Template
}

// NewPromptTemplate creates a new prompt template using Go's text/template
func NewPromptTemplate(templateStr string, _ []string) *PromptTemplate {
	tmpl, err := template.New("prompt").Parse(templateStr)
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

func BuildDetectionUserPrompt(ctx context.Context, detectionContext *model.DetectionContext, debugEnabled ...bool) (string, error) {
	systemPrompt := string(SystemPromptBytes)

	systemPromptTokens := getNumberOfTokens(systemPrompt)

	allFiles := make([]string, 0)
	includedFiles := make([]string, 0)

	for _, relatedFile := range detectionContext.RelatedFiles {
		allFiles = append(allFiles, relatedFile.Path)
	}

	userTemplate := detectionContext.Rule.Content

	// Add line numbers to code for accurate LLM line identification
	numberedCode := utils.AddLineNumbers(detectionContext.Code)
	userTemplate = strings.ReplaceAll(userTemplate, "<code>", numberedCode)
	userTemplate = strings.ReplaceAll(userTemplate, "<path>", detectionContext.Path)

	relatedFilesSection := ""
	if len(detectionContext.RelatedFiles) > 0 {
		relatedFilesSection = "\n## Related Files\n"

		for _, relatedFile := range detectionContext.RelatedFiles {
			relatedFilesSectionAdditional := relatedFilesSection + "\n" + "### " + relatedFile.Path + "\n" +
				"```\n" + relatedFile.Content + "\n```" + "\n" + "\n"
			tempPrompt := strings.ReplaceAll(userTemplate, "<relatedFilesInformation>",
				relatedFilesSection+relatedFilesSectionAdditional)
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

			relatedFilesSection += relatedFilesSectionAdditional
		}
	}

	userTemplate = strings.ReplaceAll(userTemplate, "<relatedFilesInformation>", relatedFilesSection)

	return userTemplate, nil
}
