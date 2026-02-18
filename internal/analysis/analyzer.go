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

// processFilesWithProcessor processes files using batched operations.
// This improves performance by processing multiple files concurrently in batches.
// nolint: gocyclo
func processFilesWithProcessor(ctx context.Context, files []fileMeta, ruleProcessor *RuleProcessor) ([]ProcessFileResult, error) {
	if len(files) == 0 {
		return []ProcessFileResult{}, nil
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

	// Phase 1: Parallel batch processing to determine applicable rules
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

	// Close result channel when all goroutines complete
	go func() {
		batchWg.Wait()
		close(resultCh)
	}()

	// Collect results (order doesn't matter)
	var allResults []ProcessFileResult
	for br := range resultCh {
		allResults = append(allResults, br.results...)
	}

	// Phase 2: Build ScanData for files with applicable rules (parallelized)
	filePool, err := ants.NewPool(ruleProcessor.opts.FileConcurrency)
	if err != nil {
		return nil, fmt.Errorf("error creating file worker pool: %v", err)
	}
	defer filePool.Release()

	var wg sync.WaitGroup
	var mu sync.Mutex
	var buildErrors []error

	for i := range allResults {
		if len(allResults[i].applicableRules) == 0 {
			continue
		}

		wg.Add(1)
		idx := i
		err := filePool.Submit(func() {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}

			if err := ruleProcessor.BuildScanDataForResult(ctx, &allResults[idx]); err != nil {
				mu.Lock()
				buildErrors = append(buildErrors, err)
				mu.Unlock()
				log.FromContext(ctx).Warnf("Error building scan data for %s: %v", allResults[idx].RelPath, err)
			}
		})
		if err != nil {
			log.FromContext(ctx).Warnf("Error submitting build task: %v", err)
			wg.Done()
		}
	}

	wg.Wait()

	// Report accumulated errors but don't fail (best-effort processing)
	if len(buildErrors) > 0 {
		log.FromContext(ctx).Warnf("Encountered %d errors during scan data building", len(buildErrors))
	}

	if ruleProcessor.opts.Debug {
		log.FromContext(ctx).Infof("Processed %d files, collected scan data", len(allResults))
	}

	return allResults, nil
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

	// Create rule processor once and reuse for both phases
	// (agent is set here so it can be used for scans after rule matching)
	ruleProcessor, err := NewRuleProcessor(agent, opts, aiContext)
	if err != nil {
		return nil, err
	}

	// Phase 1: Determine applicable rules for all files
	rulePhaseStart := time.Now()
	allResults, err := processFilesWithProcessor(ctx, files, ruleProcessor)
	if err != nil {
		return nil, err
	}
	log.FromContext(ctx).Infof("Rule matching phase: %d files in %v", len(files), time.Since(rulePhaseStart))

	// Count files needing scans
	filesNeedingScans := 0
	totalScansNeeded := 0
	var filesToIndex []fileMeta
	for _, res := range allResults {
		if len(res.Scans) > 0 {
			filesNeedingScans++
			totalScansNeeded += len(res.Scans)
			filesToIndex = append(filesToIndex, res.fileMeta)
		}
	}
	log.FromContext(ctx).Infof("Scan phase: %d files need %d scans", filesNeedingScans, totalScansNeeded)

	// Phase 2: Index files that have applicable rules
	if len(filesToIndex) > 0 && !opts.SkipIndexing {
		indexStart := time.Now()
		indexFilesForContext(ctx, opts.Directory, filesToIndex, aiContext, opts.Debug)
		log.FromContext(ctx).Infof("Indexed %d files in %v", len(filesToIndex), time.Since(indexStart))
	}

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
		// If there is a Datadog driver, we need to filter the files and applicable rules to scan
		if opts.DatadogDriver != nil {
			scansToPerform = filterScanDataForDatadogDriver(opts.DatadogDriver.Files, res.Scans)

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
