package analysis

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/DataDog/datadog-saist/internal/agents"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/codesecurity"
	"github.com/DataDog/datadog-saist/internal/llmcontext"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/sarif"
	"github.com/panjf2000/ants/v2"
)

type fileMeta struct {
	RelPath  string
	AbsPath  string
	Language model.Language
	Hash     string
}

// ResultAggregator handles result collection with single mutex
type ResultAggregator struct {
	outputPath        string
	rules             []api.AiPrompt
	allViolations     []model.Violation
	allFileResults    []model.FileResult
	totalInputTokens  int32
	totalOutputTokens int32
	totalLLMCalls     int32
	mu                sync.Mutex
}

// ProcessResults processes file results (thread-safe)
func (w *ResultAggregator) ProcessResults(fileResults []model.FileResult, violations []model.Violation,
	inputTokens, outputTokens, llmCalls int32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.allFileResults = append(w.allFileResults, fileResults...)
	w.allViolations = append(w.allViolations, violations...)
	w.totalInputTokens += inputTokens
	w.totalOutputTokens += outputTokens
	w.totalLLMCalls += llmCalls
}

// Finalize writes the complete SARIF report
func (w *ResultAggregator) Finalize() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Generate final SARIF report
	sarifReport, err := sarif.GenerateSarifReport(&sarif.SarifReportInformation{
		Violations:   w.allViolations,
		OutputTokens: w.totalOutputTokens,
		InputTokens:  w.totalInputTokens,
		FileResults:  w.allFileResults,
		Rules:        w.rules,
	})
	if err != nil {
		return fmt.Errorf("error generating sarif report: %v", err)
	}

	if err := sarif.WriteSarifContent(sarifReport, w.outputPath); err != nil {
		return fmt.Errorf("error writing sarif report: %v", err)
	}

	return nil
}

// GetSummary returns current processing summary
func (w *ResultAggregator) GetSummary() (violationCount, filesAnalyzed int, inputTokens, outputTokens, llmCalls int32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return len(w.allViolations), len(w.allFileResults), w.totalInputTokens, w.totalOutputTokens, w.totalLLMCalls
}

// BatchConcurrency is the number of parallel file processing batches
const BatchConcurrency = 4

// determineApplicableRules processes files in parallel batches to find which rules apply to each file.
// It returns ProcessFileResult with applicableRules populated and Scans still nil.
// Call buildScanDataForResults after indexing to assemble prompts with full context.
func determineApplicableRules(ctx context.Context, files []fileMeta, ruleProcessor *RuleProcessor) []ProcessFileResult {
	if len(files) == 0 {
		return []ProcessFileResult{}
	}

	totalBatches := (len(files) + BatchSize - 1) / BatchSize
	log.FromContext(ctx).
		Infof("Processing %d files (batch size: %d files, %d concurrent batches)", len(files), BatchSize, BatchConcurrency)

	// Build all batches upfront
	var batches [][]fileMeta
	for start := 0; start < len(files); start += BatchSize {
		end := start + BatchSize
		if end > len(files) {
			end = len(files)
		}
		batches = append(batches, files[start:end])
	}

	type batchResult struct {
		index   int
		results []ProcessFileResult
	}

	resultCh := make(chan batchResult, len(batches))
	sem := make(chan struct{}, BatchConcurrency)
	var batchWg sync.WaitGroup

	for i, batch := range batches {
		if ctx.Err() != nil {
			break
		}

		batchWg.Add(1)
		go func(idx int, b []fileMeta) {
			defer batchWg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			if ctx.Err() != nil {
				return
			}

			if ruleProcessor.opts.Debug {
				log.FromContext(ctx).Debugf("Processing file batch %d/%d (%d files)", idx+1, totalBatches, len(b))
			}

			batchResults, err := ruleProcessor.ProcessFileRulesBatched(b)
			if err != nil {
				log.FromContext(ctx).Warnf("Batch processing error: %v", err)
				// On error, create fallback results
				var fallbackResults []ProcessFileResult
				for _, fm := range b {
					fallbackResults = append(fallbackResults, ProcessFileResult{
						RelPath:         fm.RelPath,
						applicableRules: ruleProcessor.GetApplicableRules(fm),
						fileMeta:        fm,
					})
				}
				resultCh <- batchResult{index: idx, results: fallbackResults}
				return
			}

			resultCh <- batchResult{index: idx, results: batchResults}
		}(i, batch)
	}

	go func() {
		batchWg.Wait()
		close(resultCh)
	}()

	var allResults []ProcessFileResult
	for br := range resultCh {
		allResults = append(allResults, br.results...)
	}

	if ruleProcessor.opts.Debug {
		log.FromContext(ctx).Infof("Determined applicable rules for %d files", len(allResults))
	}

	return allResults
}

// buildScanDataForResults assembles the LLM prompt for every file/rule pair that has applicable rules.
// This must be called after indexFilesForContext so that aiContext is populated and
// getRelatedFiles can return cross-file references for the prompt.
//
// Per-file build failures are treated as best-effort: they are logged as warnings but do not
// abort the run. Only fatal setup failures (e.g. worker pool creation) are returned as errors.
func buildScanDataForResults(ctx context.Context, results []ProcessFileResult, ruleProcessor *RuleProcessor) error {
	filePool, err := ants.NewPool(ruleProcessor.opts.FileConcurrency)
	if err != nil {
		return fmt.Errorf("error creating file worker pool: %v", err)
	}
	defer filePool.Release()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var buildErrors []error

	for i := range results {
		if len(results[i].applicableRules) == 0 {
			continue
		}

		wg.Add(1)
		idx := i
		err := filePool.Submit(func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}

			if err := ruleProcessor.BuildScanDataForResult(ctx, &results[idx]); err != nil {
				mu.Lock()
				buildErrors = append(buildErrors, err)
				mu.Unlock()
				log.FromContext(ctx).Warnf("Error building scan data for %s: %v", results[idx].RelPath, err)
			}
		})
		if err != nil {
			log.FromContext(ctx).Warnf("Error submitting build task: %v", err)
			wg.Done()
		}
	}

	wg.Wait()

	if len(buildErrors) > 0 {
		log.FromContext(ctx).Warnf("Encountered %d errors during scan data building", len(buildErrors))
	}

	return nil
}

func countFileRulePairs(m map[string][]string) int {
	n := 0
	for _, ids := range m {
		n += len(ids)
	}
	return n
}

func filterScanDataForDatadogDriver(filesAndRules map[string][]string, scans []model.ScanData) []model.ScanData {
	scansToPerform := make([]model.ScanData, 0)

	// we check all applicable rules and only add the ones
	for i := range scans {
		scanData := &scans[i]
		rulesForFile, ok := filesAndRules[scanData.RelativeFilePath]

		// file not requested to scan, skip
		if !ok {
			continue
		}

		if slices.Contains(rulesForFile, scanData.Rule.ID) {
			scansToPerform = append(scansToPerform, *scanData)
		}
	}
	return scansToPerform
}

// analyzeFiles processes files in batches to minimize memory usage
// nolint: gocyclo
func analyzeFiles(ctx context.Context, files []fileMeta, opts *model.AnalysisOptions,
	aiContext *model.AiContextProject) ([]model.FileResult, error) {
	agent, err := agents.NewDetectionAgent(ctx, &agents.AgentOption{
		DetectionModel:    opts.DetectionModel,
		ValidationModel:   opts.ValidationModel,
		OpenAiBaseUrl:     opts.OpenAIBaseURL,
		RequestTimeoutSec: opts.RequestTimeoutSec,
		IsAIGateway:       opts.IsAIGateway,
		AIGuardEnabled:    opts.AIGuardEnabled,
		OrgID:             opts.OrgID,
		DebugEnabled:      opts.Debug,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create detection agent for models detection=%s, validation=%s (timeout: %ds, AI gateway: %t): %w",
			opts.DetectionModel, opts.ValidationModel, opts.RequestTimeoutSec, opts.IsAIGateway, err)
	}

	// When not using Datadog driver mode (.datadog-driver.json + env), honor local Code Security YAML
	// (same filenames as dd-source SAIST) by narrowing rules and file→rule pairs like code-workload-runner.
	effectiveDriver := opts.DatadogDriver
	if effectiveDriver == nil {
		cfg, configBasename, err := codesecurity.LoadLocalFile(opts.Directory)
		if err != nil {
			log.FromContext(ctx).Warnf("Code Security config: %v", err)
		} else if cfg != nil && cfg.Sast == nil && configBasename != "" && opts.Debug {
			log.FromContext(ctx).Debugf(
				"Local Code Security config: parsed %s but no sast section; YAML scan narrowing skipped",
				configBasename)
		} else if cfg != nil && cfg.Sast != nil {
			rulesetToRules := codesecurity.BuildRulesetToRuleIDs(opts.Rules)
			enabled, filtered, fallbackUsed := codesecurity.FilterRulesBySastConfig(opts.Rules, cfg.Sast, rulesetToRules)
			if fallbackUsed {
				log.FromContext(ctx).Infof(
					"Code Security config produced zero valid AI SAST rulesets without explicit disablement; using all %d default rules",
					len(filtered))
			} else if len(filtered) == 0 {
				log.FromContext(ctx).Warn("Code Security config enabled zero SAIST rules; analysis will not run SAIST rules")
			}
			opts.Rules = filtered

			src := make([]codesecurity.SourceFile, len(files))
			for i := range files {
				src[i] = codesecurity.SourceFile{
					RelPath: files[i].RelPath,
					AbsPath: files[i].AbsPath,
					Lang:    files[i].Language,
				}
			}
			fileMap := codesecurity.MatchFilesToRules(src, filtered)
			fileMap = codesecurity.ApplyGlobalPathFiltersToFileRuleMapping(fileMap, cfg.Sast.GlobalConfig)
			if cfg.Sast.RulesetConfigs != nil {
				codesecurity.ForEachRulesetConfigPathFilter(ctx, *cfg.Sast.RulesetConfigs, enabled, rulesetToRules,
					func(cfgs map[string]codesecurity.YamlRuleConfig) {
						fileMap = codesecurity.ApplyRuleConfigFilters(fileMap, cfgs)
					})
			}
			effectiveDriver = &model.DatadogDriverConfig{Files: fileMap}
			schemaVer := cfg.SchemaVersion
			if schemaVer == "" {
				schemaVer = "(unset)"
			}
			log.FromContext(ctx).Infof(
				"Local Code Security config: using %s (schema-version=%s), %d rules after ruleset filter, %d file-rule pairs for scans",
				configBasename, schemaVer, len(filtered), countFileRulePairs(fileMap))
		} else {
			log.FromContext(ctx).Infof(
				"Local Code Security config: no YAML file in %s "+
					"(code-security.datadog.yaml|.yml or static-analysis.datadog.yaml|.yml); "+
					"scan scope not narrowed from disk",
				opts.Directory)
		}
	} else if opts.Debug {
		log.FromContext(ctx).Debugf(
			"Datadog driver mode: DATADOG_DRIVER_ENABLED + .datadog-driver.json defines scan scope; local Code Security YAML is not applied")
	}

	// Create rule processor once and reuse for both phases
	// (agent is set here so it can be used for scans after rule matching)
	ruleProcessor, err := NewRuleProcessor(agent, opts, aiContext)
	if err != nil {
		return nil, err
	}

	// Phase 1: Determine applicable rules for all files
	rulePhaseStart := time.Now()
	allResults := determineApplicableRules(ctx, files, ruleProcessor)
	log.FromContext(ctx).Infof("Rule matching phase: %d files in %v", len(files), time.Since(rulePhaseStart))

	// Collect files that have applicable rules; needed to scope indexing before prompt assembly.
	var filesToIndex []fileMeta
	for _, res := range allResults {
		if len(res.applicableRules) > 0 {
			filesToIndex = append(filesToIndex, res.fileMeta)
		}
	}

	// Phase 2: Index files BEFORE building scan data so that aiContext is populated
	// when BuildScanDataForResult calls getRelatedFiles and assembles the prompt.
	if len(filesToIndex) > 0 && !opts.SkipIndexing {
		indexStart := time.Now()
		indexFilesForContext(ctx, opts.Directory, filesToIndex, aiContext, opts.Debug)
		log.FromContext(ctx).Infof("Indexed %d files in %v", len(filesToIndex), time.Since(indexStart))
	}

	// Phase 3: Build ScanData (and prompts) now that aiContext is populated.
	// ShouldAnalyze inside BuildScanDataForResult may drop some file/rule pairs, so the
	// accurate scan count is only available after this call completes.
	if err := buildScanDataForResults(ctx, allResults, ruleProcessor); err != nil {
		return nil, err
	}

	// Count actual scans after filtering (res.Scans is now populated by buildScanDataForResults).
	filesNeedingScans := 0
	totalScansNeeded := 0
	for _, res := range allResults {
		if len(res.Scans) > 0 {
			filesNeedingScans++
			totalScansNeeded += len(res.Scans)
		}
	}
	log.FromContext(ctx).Infof("Scan phase: %d files need %d scans", filesNeedingScans, totalScansNeeded)

	scanPhaseStart := time.Now()
	filePool, err := ants.NewPool(opts.FileConcurrency)
	if err != nil {
		return nil, fmt.Errorf("error creating file worker pool: %v", err)
	}
	defer filePool.Release()

	// Create cancellable context for fail-fast on rate limit
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var filesWg sync.WaitGroup
	var rateLimitErr error
	var errOnce sync.Once
	var resultSync sync.Mutex
	allFilesResults := make([]model.FileResult, 0)
	for _, res := range allResults {
		scansToPerform := res.Scans
		// Datadog driver JSON or local Code Security YAML narrows (file, rule) pairs for scans
		if effectiveDriver != nil {
			scansToPerform = filterScanDataForDatadogDriver(effectiveDriver.Files, res.Scans)

			// if there is no scan to perform (e.g. no rule), do not analyze
			if len(scansToPerform) == 0 {
				continue
			}
		}

		filesWg.Add(1)
		res := res // nolint:copyloopvar
		err := filePool.Submit(func() {
			defer filesWg.Done()

			// Check if context is already canceled
			if ctx.Err() != nil {
				return
			}

			runScanResult, err :=
				ruleProcessor.RunScans(ctx, scansToPerform)
			if err != nil {
				// On rate limit, cancel all workers and capture the error
				if clients.IsRateLimitError(err) {
					errOnce.Do(func() {
						rateLimitErr = err
						log.FromContext(ctx).Warnf("Rate limit detected, stopping analysis")
						cancel()
					})
					return
				}
				log.FromContext(ctx).Warnf("Failed to run scans for file %s: %v", res.RelPath, err)
				return
			}

			fileResult := model.FileResult{
				Path:           res.RelPath,
				Violations:     runScanResult.Violations,
				InputTokens:    runScanResult.FileInputTokens,
				OutputTokens:   runScanResult.FileOutputTokens,
				LLMCalls:       runScanResult.FileLLMCalls,
				RulesSucceeded: runScanResult.RulesSuccess,
				RulesFailed:    runScanResult.RulesFailed,
			}
			resultSync.Lock()
			allFilesResults = append(allFilesResults, fileResult)
			resultSync.Unlock()
		})
		if err != nil {
			log.FromContext(ctx).Warnf("Error submitting file '%s': %s", res.RelPath, err)
			filesWg.Done() // Don't forget to decrement if submit failed
		}
	}

	// Wait for all files to complete
	filesWg.Wait()
	log.FromContext(ctx).Infof("Scan phase completed in %v", time.Since(scanPhaseStart))

	// Return rate limit error if encountered
	if rateLimitErr != nil {
		return nil, fmt.Errorf("analysis stopped: %w", rateLimitErr)
	}

	// Prepare analysis result
	return allFilesResults, nil
}

// analyzeAndGenerateReport performs analysis and generates SARIF report
func analyzeAndGenerateReport(ctx context.Context, opts *model.AnalysisOptions) ([]model.FileResult, error) {
	files, aiContext, err := processDirectory(ctx, opts)
	if err != nil {
		return nil, err
	}
	return analyzeFiles(ctx, files, opts, aiContext)
}

func processDirectory(ctx context.Context, opts *model.AnalysisOptions) ([]fileMeta, *model.AiContextProject, error) {
	if _, err := os.Stat(opts.Directory); os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("directory '%s' does not exist", opts.Directory)
	}

	if opts.Debug {
		log.FromContext(ctx).Infof("analyzing directory=%s, detection_model=%s, validation_model=%s",
			opts.Directory, opts.DetectionModel, opts.ValidationModel)
	}

	// Discover files
	discoveryStart := time.Now()
	fileDiscoverer := NewFileDiscoverer(opts.Directory, opts.Debug)
	files, err := fileDiscoverer.DiscoverFiles(ctx)
	if err != nil {
		return nil, nil, err
	}
	log.FromContext(ctx).Infof("File discovery: %d files in %v", len(files), time.Since(discoveryStart))

	// Create empty aiContext - indexing happens after determining applicable rules
	aiContext := model.NewAiContextProject()

	return files, &aiContext, nil
}

// indexFilesForContext indexes only the specified files into the aiContext.
// This is called after determining applicable rules to index files that need scanning.
func indexFilesForContext(ctx context.Context, directory string, files []fileMeta, aiContext *model.AiContextProject, debug bool) {
	if len(files) == 0 {
		return
	}

	nbCpus := runtime.NumCPU()
	if debug {
		log.FromContext(ctx).Debugf("Indexing %d files using %d cpus", len(files), nbCpus)
	}

	// Create indexing worker pool
	indexPool, err := ants.NewPool(nbCpus)
	if err != nil {
		log.FromContext(ctx).Warnf("Failed to create indexing worker pool: %v", err)
		return
	}
	defer indexPool.Release()

	var mtx sync.Mutex
	var wg sync.WaitGroup
	for _, fm := range files {
		wg.Add(1)
		fm := fm // nolint:copyloopvar
		err := indexPool.Submit(func() {
			defer wg.Done()
			fc, err := llmcontext.GetContextFromFile(directory, fm.RelPath)
			if err != nil || fc == nil {
				if debug {
					log.FromContext(ctx).Debugf("context error for %s: %v", fm.RelPath, err)
				}
				return
			}
			mtx.Lock()
			aiContext.MergeFileContext(fm.RelPath, *fc)
			mtx.Unlock()
		})
		if err != nil {
			log.FromContext(ctx).Debugf("Failed to submit indexing task for %s: %v", fm.RelPath, err)
			wg.Done()
		}
	}
	wg.Wait()
}
