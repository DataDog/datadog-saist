// Package analysis provides rule processing and LLM-based security analysis for the SAIST engine.
// The RuleProcessor handles rule matching, AI detection calls, and result
// processing for individual files and security rules.
package analysis

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/DataDog/datadog-saist/internal/agents"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/filtering"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/prompt"
	"github.com/DataDog/datadog-saist/internal/utils"
)

const PromptDebugFileCreationMode = 0600

// RuleIndex pre-computes rule-language mappings for efficient lookup
type RuleIndex struct {
	// byLanguage maps each language to rules that apply to it
	byLanguage map[model.Language][]*api.AiPrompt
	// universalRules are rules that apply to all languages (when globs don't specify a language)
	universalRules []*api.AiPrompt
}

// buildRuleIndex creates a RuleIndex from the given rules
func buildRuleIndex(rules []api.AiPrompt) *RuleIndex {
	idx := &RuleIndex{
		byLanguage:     make(map[model.Language][]*api.AiPrompt),
		universalRules: make([]*api.AiPrompt, 0),
	}

	for i := range rules {
		rule := &rules[i]
		languages := utils.InferLanguagesFromGlobs(rule.Globs)

		if len(languages) == 0 {
			// Rule applies to all languages
			idx.universalRules = append(idx.universalRules, rule)
		} else {
			// Rule applies to specific languages
			for _, lang := range languages {
				idx.byLanguage[lang] = append(idx.byLanguage[lang], rule)
			}
		}
	}

	return idx
}

// getRulesForLanguage returns all rules that apply to the given language
func (idx *RuleIndex) getRulesForLanguage(lang model.Language) []*api.AiPrompt {
	langRules := idx.byLanguage[lang]
	if len(idx.universalRules) == 0 {
		return langRules
	}
	// Combine language-specific and universal rules
	result := make([]*api.AiPrompt, 0, len(langRules)+len(idx.universalRules))
	result = append(result, langRules...)
	result = append(result, idx.universalRules...)
	return result
}

// RuleProcessor handles per-file rule processing logic
type RuleProcessor struct {
	opts         model.AnalysisOptions
	agent        *agents.DetectionAgent
	orgID        int64
	repositoryID string
	aiContext    *model.AiContextProject
	debug        bool

	// Pre-computed rule-language index for fast lookup
	ruleIndex *RuleIndex
}

type ProcessFileResult struct {
	// RelPath is the relative path of the file processed.
	RelPath string
	// Scans contains scans that need to be executed for this file.
	// If empty, no rules apply to this file.
	Scans []model.ScanData

	// Internal fields for batched processing (not exported)
	applicableRules []*api.AiPrompt // Rules that apply to this file
	fileMeta        fileMeta        // File metadata for building ScanData later
}

// NewRuleProcessor creates a new rule processor
func NewRuleProcessor(agent *agents.DetectionAgent, opts *model.AnalysisOptions,
	aiContext *model.AiContextProject) (*RuleProcessor, error) {
	// Pre-compute rule-language index once at startup
	ruleIndex := buildRuleIndex(opts.Rules)

	rp := &RuleProcessor{
		opts:         *opts,
		agent:        agent,
		orgID:        opts.OrgID,
		repositoryID: opts.RepositoryID,
		aiContext:    aiContext,
		debug:        opts.Debug,
		ruleIndex:    ruleIndex,
	}

	return rp, nil
}

// GetApplicableRules returns rules that apply to the given file (used for fallback on errors)
func (rp *RuleProcessor) GetApplicableRules(fm fileMeta) []*api.AiPrompt {
	candidateRules := rp.ruleIndex.getRulesForLanguage(fm.Language)
	applicableRules := make([]*api.AiPrompt, 0, len(candidateRules))
	for _, rule := range candidateRules {
		if utils.RuleMatchesFile(rule, fm.RelPath) {
			applicableRules = append(applicableRules, rule)
		}
	}
	return applicableRules
}

// BatchSize is the number of files to process in a single batch
const BatchSize = 50

// ProcessFileRulesBatched processes multiple files at once, returning all applicable rules for scanning.
func (rp *RuleProcessor) ProcessFileRulesBatched(files []fileMeta) ([]ProcessFileResult, error) {
	if len(files) == 0 {
		return nil, nil
	}

	// Build results: for each file, get applicable rules for scanning
	results := make([]ProcessFileResult, 0, len(files))
	for _, fm := range files {
		candidateRules := rp.ruleIndex.getRulesForLanguage(fm.Language)
		applicableRules := make([]*api.AiPrompt, 0, len(candidateRules))
		for _, rule := range candidateRules {
			if utils.RuleMatchesFile(rule, fm.RelPath) {
				applicableRules = append(applicableRules, rule)
			}
		}

		results = append(results, ProcessFileResult{
			RelPath:         fm.RelPath,
			Scans:           nil,             // Will be populated in the next phase
			applicableRules: applicableRules, // All applicable rules for this file
			fileMeta:        fm,
		})
	}

	return results, nil
}

// BuildScanDataForResult reads file content and builds ScanData for rules that apply to this file.
// This should be called after ProcessFileRulesBatched for results that have applicableRules.
func (rp *RuleProcessor) BuildScanDataForResult(ctx context.Context, result *ProcessFileResult) error {
	if len(result.applicableRules) == 0 {
		return nil
	}

	// Read file content
	data, err := os.ReadFile(result.fileMeta.AbsPath)
	if err != nil {
		return fmt.Errorf("read file %s: %w", result.fileMeta.AbsPath, err)
	}

	fm := result.fileMeta
	fileText := string(data)
	strippedCode := filtering.StripCodeForDetection(fileText, fm.Language)
	numberedFileText := utils.AddLineNumbers(fileText)

	allScanData := make([]model.ScanData, 0, len(result.applicableRules))

	for _, rule := range result.applicableRules {
		dctx := model.DetectionContext{
			ProjectContext:      *rp.aiContext,
			Language:            fm.Language,
			RepositoryDirectory: rp.opts.Directory,
			Path:                fm.RelPath,
			Code:                fileText,
			StrippedCode:        strippedCode,
			WritePrompts:        rp.opts.WritePrompts,
			Rule:                *rule,
		}
		if !filtering.ShouldAnalyze(&dctx, log.FromContext(ctx)) {
			// Skip files that don't need analysis
			continue
		}

		relatedFiles, err := getRelatedFiles(&dctx, log.FromContext(ctx))
		if err != nil {
			return err
		}
		dctx.RelatedFiles = relatedFiles

		var userPrompt string
		var userPromptErr error
		if rp.opts.UseLocalPrompts {
			userPromptDetectionContext := dctx
			// Use embedded agent rule files instead of reading from filesystem
			ruleContent, err := agents.GetEmbeddedAgentRule(dctx.Rule.ID)
			if err == nil {
				userPromptDetectionContext.Rule.Content = ruleContent
			}
			userPrompt, userPromptErr = prompt.BuildDetectionUserPrompt(ctx, &userPromptDetectionContext, rp.debug)
		} else {
			userPrompt, userPromptErr = prompt.BuildDetectionUserPrompt(ctx, &dctx, rp.debug)
		}
		if userPromptErr != nil {
			return userPromptErr
		}

		systemPrompt := string(prompt.SystemPromptBytes)

		if dctx.WritePrompts {
			err := rp.writePrompts(&dctx, systemPrompt, userPrompt)
			if err != nil {
				log.FromContext(ctx).Warnf("error writing prompts: %s", err)
				return err
			}
		}

		scanData := model.ScanData{
			Model:            rp.opts.DetectionModel,
			UserPrompt:       userPrompt,
			SystemPrompt:     systemPrompt,
			EngineVersion:    model.EngineVersion,
			RelativeFilePath: fm.RelPath,
			FileHash:         fm.Hash,
			FileText:         fileText,
			NumberedFileText: numberedFileText,
			Rule: model.RuleData{
				ID:                    rule.ID,
				Version:               rule.Version,
				Content:               rule.Content,
				CWE:                   rule.Cwe,
				Severity:              rule.Severity,
				ResultKeywordsExclude: rule.ResultKeywordsExclude,
			},
		}
		allScanData = append(allScanData, scanData)
	}

	result.Scans = allScanData
	return nil
}

type RunScanResult struct {
	Violations       []model.Violation
	FileInputTokens  int32
	FileOutputTokens int32
}

// Runs an individual scan, returning input token count, output token count, and any violations found.
func (rp *RuleProcessor) runScan(ctx context.Context, scanData *model.ScanData) (RunScanResult, error) {
	dr, err := rp.agent.Detect(ctx, scanData)
	if err != nil {
		if rp.debug {
			log.FromContext(ctx).Debugf("detect error file=%s rule=%s: %v", scanData.RelativeFilePath, scanData.Rule.ID, err)
		}
		return RunScanResult{}, err
	}

	// Use keywords from rule definition for result filtering
	filtered := filtering.FilterViolationsByKeywords(dr.Violations, scanData.Rule.ResultKeywordsExclude)
	for i := range filtered {
		filtered[i].FileHash = scanData.FileHash

		// Generate fingerprint for each violation
		lineContent := model.GetLineContent(scanData.FileText, filtered[i].StartLine)
		filtered[i].Fingerprint = model.GenerateFingerprint(
			rp.repositoryID,
			filtered[i].Rule,
			filtered[i].Path,
			lineContent,
		)
	}

	return RunScanResult{
		Violations:       filtered,
		FileInputTokens:  dr.InputTokens,
		FileOutputTokens: dr.OutputTokens,
	}, nil
}

type RunScansResult struct {
	RulesSuccess     []string
	RulesFailed      []string
	Violations       []model.Violation
	FileInputTokens  int32
	FileOutputTokens int32
	FileLLMCalls     int32
}

// RunScans runs and returns metrics for the provided list of ScanData. For accurate metrics, the caller should ensure
// that all ScanData are for the same file.
func (rp *RuleProcessor) RunScans(ctx context.Context, scanDataList []model.ScanData) (RunScansResult, error) {
	rulesSuccess := make([]string, 0)
	rulesFailed := make([]string, 0)
	fileInputTokens := int32(0)
	fileOutputTokens := int32(0)
	fileLLMCalls := int32(0)
	fileViolations := make([]model.Violation, 0)

	for i := range scanDataList {
		scanData := &scanDataList[i]
		runScanResult, err := rp.runScan(ctx, scanData)
		fileLLMCalls++
		if err != nil {
			// On rate limit, return error immediately
			if clients.IsRateLimitError(err) {
				return RunScansResult{
					RulesSuccess:     rulesSuccess,
					RulesFailed:      rulesFailed,
					Violations:       fileViolations,
					FileInputTokens:  fileInputTokens,
					FileOutputTokens: fileOutputTokens,
					FileLLMCalls:     fileLLMCalls,
				}, err
			}

			if rp.debug {
				log.FromContext(ctx).Debugf("detect error file=%s rule=%s: %v", scanData.RelativeFilePath, scanData.Rule.ID, err)
			}

			rulesFailed = append(rulesFailed, scanData.Rule.ID)
			fileInputTokens += runScanResult.FileInputTokens
			fileOutputTokens += runScanResult.FileOutputTokens
			continue
		}

		rulesSuccess = append(rulesSuccess, scanData.Rule.ID)
		fileViolations = append(fileViolations, runScanResult.Violations...)
		fileInputTokens += runScanResult.FileInputTokens
		fileOutputTokens += runScanResult.FileOutputTokens
	}

	return RunScansResult{
		RulesSuccess:     rulesSuccess,
		RulesFailed:      rulesFailed,
		Violations:       fileViolations,
		FileInputTokens:  fileInputTokens,
		FileOutputTokens: fileOutputTokens,
		FileLLMCalls:     fileLLMCalls,
	}, nil
}

func formatRuleIdForDebugging(ruleId string) string {
	return strings.ReplaceAll(ruleId, "/", "-")
}

func (rp *RuleProcessor) writePrompts(detectionContext *model.DetectionContext, systemPrompt, userPrompt string) error {
	userPromptPath := path.Join(detectionContext.RepositoryDirectory,
		detectionContext.Path+"."+formatRuleIdForDebugging(detectionContext.Rule.ID)+".userprompt")

	systemPromptPath := path.Join(detectionContext.RepositoryDirectory,
		detectionContext.Path+"."+formatRuleIdForDebugging(detectionContext.Rule.ID)+".systemprompt") // systemPromptPath for future use

	// Remove the file if it already exists
	if _, err := os.Stat(userPromptPath); err == nil {
		err = os.Remove(userPromptPath)
		if err != nil {
			return fmt.Errorf("error removing existing user prompt file '%s': %w", userPromptPath, err)
		}
	}

	// Write user prompt to file
	err := os.WriteFile(userPromptPath, []byte(userPrompt), PromptDebugFileCreationMode)
	if err != nil {
		return fmt.Errorf("error writing user prompt to file '%s': %w", userPromptPath, err)
	}

	// Remove the file if it already exists
	if _, err := os.Stat(systemPromptPath); err == nil {
		err = os.Remove(systemPromptPath)
		if err != nil {
			return fmt.Errorf("error removing existing user prompt file '%s': %w", systemPromptPath, err)
		}
	}

	// Write user prompt to file
	err = os.WriteFile(systemPromptPath, []byte(systemPrompt), PromptDebugFileCreationMode)
	if err != nil {
		return fmt.Errorf("error writing system prompt to file '%s': %w", systemPromptPath, err)
	}
	return nil
}
