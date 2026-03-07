package sarif

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/owenrumney/go-sarif/v3/sarif"
)

const toolName = "datadog-ai-static-analyzer"
const toolInformationURI = "https://github.com/DataDog/datadog-saist"

const ruleSuccessTag = "RULE_SUCCESS"
const ruleFailureTag = "RULE_FAILURE"
const inputTokensTag = "DATADOG_SAIST_INPUT_TOKENS"   // nolint: gosec
const outputTokensTag = "DATADOG_SAIST_OUTPUT_TOKENS" // nolint: gosec
const cweTag = "CWE"
const ruleTypeTag = "DATADOG_RULE_TYPE"
const tagsKey = "tags"
const confidenceTag = "DATADOG_CONFIDENCE"
const confidenceReasonTag = "DATADOG_CONFIDENCE_REASON"
const highConfidence = "HIGH"

type SarifReportInformation struct {
	Violations    []model.Violation
	InputTokens   int32
	OutputTokens  int32
	FilesAnalyzed []string
	FileResults   []model.FileResult
	Rules         []api.AiPrompt
}

// Generate the information to process the SARIF file. Also, make sure that we filter the files analyzed
// in case the datadog driver is present.
func GenerateSarifInformation(opts *model.AnalysisOptions, filesResults []model.FileResult) SarifReportInformation {
	violations := make([]model.Violation, 0)
	fileAnalyzedSet := make(map[string]struct{})
	inputTokens := int32(0)
	outputTokens := int32(0)

	for _, fr := range filesResults {
		fileAnalyzedSet[fr.Path] = struct{}{}
		violations = append(violations, fr.Violations...)
		inputTokens += fr.InputTokens
		outputTokens += fr.OutputTokens
	}

	filesAnalyzed := make([]string, 0, len(fileAnalyzedSet))
	for path := range fileAnalyzedSet {
		filesAnalyzed = append(filesAnalyzed, path)
	}

	return SarifReportInformation{
		Violations:    violations,
		InputTokens:   inputTokens,
		OutputTokens:  outputTokens,
		Rules:         opts.Rules,
		FileResults:   filesResults,
		FilesAnalyzed: filesAnalyzed,
	}
}

func AddPropertyTag(properties sarif.Properties, tagName, tagValue string) sarif.Properties {
	tagsInterface, ok := properties[tagsKey]
	var tags []any
	if ok {
		tags = tagsInterface.([]any)
	}
	newTag := fmt.Sprintf("%s:%s", tagName, tagValue)
	tags = append(tags, newTag)
	properties[tagsKey] = tags
	return properties
}

func GenerateSarifReport(sarifInformation *SarifReportInformation) (*sarif.Report, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, fmt.Errorf("failed to create SARIF report: %w", err)
	}

	// Create a versioned driver with tool information
	driver := sarif.NewVersionedDriver(toolName, model.EngineVersion).
		WithInformationURI(toolInformationURI)
	run := sarif.NewRun(*sarif.NewTool(driver))

	// adding artifacts
	for _, fileResult := range sarifInformation.FileResults {
		newArtifact := run.AddArtifact()
		newArtifact.Location = &sarif.ArtifactLocation{
			URI: &fileResult.Path,
		}
		newArtifact.Length = 0
		newArtifact.Properties = sarif.Properties{}
		ruleSuccessTagValue := make([]string, 0)
		ruleFailureTagValue := make([]string, 0)

		if len(fileResult.RulesSucceeded) > 0 {
			ruleSuccessTagValue = append(ruleSuccessTagValue, fileResult.RulesSucceeded...)
			run.Properties = AddPropertyTag(newArtifact.Properties, ruleSuccessTag, strings.Join(ruleSuccessTagValue, ","))
		}
		if len(fileResult.RulesFailed) > 0 {
			ruleFailureTagValue = append(ruleFailureTagValue, fileResult.RulesFailed...)
			run.Properties = AddPropertyTag(newArtifact.Properties, ruleFailureTag, strings.Join(ruleFailureTagValue, ","))
		}
	}

	// adding rules from API definitions
	for i := range sarifInformation.Rules {
		rule := &sarifInformation.Rules[i]
		descriptor := run.AddRule(rule.ID)
		descriptor.ShortDescription = &sarif.MultiformatMessageString{
			Text: &rule.ShortDescription,
		}
		descriptor.FullDescription = &sarif.MultiformatMessageString{
			Text: &rule.Description,
		}

		descriptor.Properties = sarif.Properties{}
		descriptor.Properties = AddPropertyTag(descriptor.Properties, ruleTypeTag, "datadog-ai-static-analyzer")

		if rule.Cwe != nil {
			descriptor.Properties = AddPropertyTag(descriptor.Properties, cweTag, *rule.Cwe)
		}

		// Add severity information
		severityStr := string(rule.Severity)
		if severityStr != "" {
			descriptor.Properties = AddPropertyTag(descriptor.Properties, "SEVERITY", severityStr)
		}

		// Add category information
		categoryStr := string(rule.Category)
		if categoryStr != "" {
			descriptor.Properties = AddPropertyTag(descriptor.Properties, "CATEGORY", categoryStr)
		}
	}

	// Build maps of rule ID -> rule description and rule ID -> rule index
	ruleDescriptions := make(map[string]string)
	ruleIndices := make(map[string]int)
	for idx := range sarifInformation.Rules {
		rule := &sarifInformation.Rules[idx]
		ruleDescriptions[rule.ID] = rule.ShortDescription
		ruleIndices[rule.ID] = idx
	}

	for _, violation := range sarifInformation.Violations {
		result := createResult(&violation, ruleDescriptions, ruleIndices)
		run.AddResult(result)
	}
	run.Properties = sarif.Properties{}
	run.Properties = AddPropertyTag(run.Properties, outputTokensTag, strconv.Itoa(int(sarifInformation.OutputTokens)))
	run.Properties = AddPropertyTag(run.Properties, inputTokensTag, strconv.Itoa(int(sarifInformation.InputTokens)))

	report.AddRun(run)
	return report, nil
}

func createResult(violation *model.Violation, ruleDescriptions map[string]string, ruleIndices map[string]int) *sarif.Result {
	startLine := int(violation.StartLine)
	startColumn := int(violation.StartColumn)
	endLine := int(violation.EndLine)
	endColumn := int(violation.EndColumn)
	rule := violation.Rule
	level := "warning"

	// Location fields are validated upstream in detection.go
	// All fields (startLine, startColumn, endLine, endColumn) are guaranteed to be > 0

	region := &sarif.Region{
		StartLine:   &startLine,
		StartColumn: &startColumn,
		EndLine:     &endLine,
		EndColumn:   &endColumn,
	}

	location := &sarif.Location{
		PhysicalLocation: &sarif.PhysicalLocation{
			ArtifactLocation: &sarif.ArtifactLocation{
				URI: &violation.Path,
			},
			Region: region,
		},
	}

	// Use rule description as the message, falling back to violation message if not found
	message := violation.Message
	if desc, ok := ruleDescriptions[violation.Rule]; ok && desc != "" {
		message = desc
	}

	// Look up rule index
	var ruleIndex *uint
	if idx, ok := ruleIndices[violation.Rule]; ok {
		uintIdx := uint(idx)
		ruleIndex = &uintIdx
	}

	result := &sarif.Result{
		RuleID:    &rule,
		RuleIndex: ruleIndex,
		Message: sarif.Message{
			Text: &message,
		},
		Locations: []*sarif.Location{location},
		Level:     &level,
	}

	// Add fingerprint if available
	if violation.Fingerprint != "" {
		result.PartialFingerprints = map[string]interface{}{
			"DATADOG_FINGERPRINT": violation.Fingerprint,
		}
	}

	// Initialize properties if needed
	if result.Properties == nil {
		result.Properties = sarif.Properties{}
	}

	// Add CWE tag
	if violation.Cwe != nil {
		result.Properties = AddPropertyTag(result.Properties, cweTag, *violation.Cwe)
	}

	// Add confidence tags
	result.Properties = AddPropertyTag(result.Properties, confidenceTag, highConfidence)
	if violation.Message != "" {
		result.Properties = AddPropertyTag(result.Properties, confidenceReasonTag, violation.Message)
	}

	return result
}

func WriteSarifContent(sarifReport *sarif.Report, output string) error {
	// Remove the output file if it already exists, otherwise, the file is overwritten
	if _, err := os.Stat(output); err == nil {
		err = os.Remove(output)
		if err != nil {
			return err
		}
	}

	err := sarifReport.WriteFile(output)
	if err != nil {
		return err
	}
	return nil
}
