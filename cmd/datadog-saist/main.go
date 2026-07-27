package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/DataDog/datadog-saist/internal/analysis"
	"github.com/DataDog/datadog-saist/internal/model"
)

func main() {
	var directory string
	var output string
	var debug bool
	var detectionModelStr string
	var validationModelStr string
	var openaiBaseURL string
	var apiKey string
	var requestTimeoutSec int
	var fileConcurrency int
	var writePrompts bool
	var isAIGateway bool
	var aiGuardEnabled bool
	var jwtToken string
	var useLocalPrompts bool
	var agentic bool
	var agenticDetection bool
	var agenticVerification bool
	var agenticMaxIterations int
	var agenticMaxToolCalls int
	var exportCandidates string
	var replayCandidates string
	var allowSourceDrift bool
	var repositoryID string

	startTimestamp := time.Now()

	availableModels := strings.Join(model.GetAllModelStrings(), ", ")
	flag.StringVar(&directory, "directory", "", "Directory to analyze (required)")
	flag.StringVar(&output, "output", "", "SARIF output path or replay result JSONL path (required)")
	flag.StringVar(&detectionModelStr, "detection-model", "",
		fmt.Sprintf("Model to use for detection (required). Available: %s", availableModels))
	flag.StringVar(&validationModelStr, "validation-model", "",
		fmt.Sprintf("Model to use for validation (required). Available: %s", availableModels))
	flag.BoolVar(&debug, "debug", false, "Enable debug mode for verbose output")
	flag.StringVar(&openaiBaseURL, "openai-base-url", "", "Custom OpenAI base URL (optional)")
	flag.StringVar(&apiKey, "api-key", "",
		"API key for the selected model's provider (optional, falls back to provider-specific env vars)")
	flag.IntVar(&requestTimeoutSec, "request-timeout-sec", DefaultRequestTimeoutSec,
		"Request timeout in seconds for LLM API calls, zero disables the timeout")
	flag.IntVar(&fileConcurrency, "file-concurrency", DefaultFileConcurrency,
		"Number of concurrent files to analyze (default: 20)")
	flag.BoolVar(&writePrompts, "write-prompts", false,
		"Write prompts to files during analysis (suffix .userprompt and .systemprompt)")
	flag.BoolVar(&isAIGateway, "ai-gateway", false, "Use AI Gateway format for models (provider/model)")
	flag.BoolVar(&aiGuardEnabled, "ai-guard", false, "Enable AI Guard headers for AI Gateway requests")
	flag.StringVar(&jwtToken, "jwt-token", "", "JWT Token to use when fetching prompts")
	flag.BoolVar(&useLocalPrompts, "local-prompts", false,
		"Use local markdown files for rule content instead of API content")
	flag.BoolVar(&agentic, "agentic", false,
		"Enable tool-using detection and verification loops (sandboxed code search, read, and list tools)")
	flag.BoolVar(&agenticDetection, "agentic-detection", false,
		"Enable the tool-using detection loop")
	flag.BoolVar(&agenticVerification, "agentic-verification", false,
		"Enable the tool-using verification loop")
	flag.IntVar(&agenticMaxIterations, "agentic-max-iterations", DefaultAgenticMaxIterations,
		"Maximum model-to-tool round trips per enabled agentic phase")
	flag.IntVar(&agenticMaxToolCalls, "agentic-max-tool-calls", DefaultAgenticMaxToolCalls,
		"Maximum total tool calls per enabled agentic phase")
	flag.StringVar(&exportCandidates, "export-candidates", "",
		"Write pre-verification candidates to this JSONL path")
	flag.StringVar(&replayCandidates, "replay-candidates", "",
		"Replay candidates from this JSONL path without running detection")
	flag.BoolVar(&allowSourceDrift, "allow-source-drift", false,
		"Allow replay against a different or dirty source tree and mark every result contaminated")
	flag.StringVar(&repositoryID, "repository-id", "test-repo",
		"Stable repository identifier used in candidate identity")
	flag.Parse()

	agenticDetection, agenticVerification = effectiveAgenticModes(
		agentic, agenticDetection, agenticVerification)
	if err := validateCandidateModes(exportCandidates, replayCandidates, allowSourceDrift); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if directory == "" {
		fmt.Fprintf(os.Stderr, "Error: --directory flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if output == "" {
		fmt.Fprintf(os.Stderr, "Error: --output flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if detectionModelStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --detection-model flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	if validationModelStr == "" {
		fmt.Fprintf(os.Stderr, "Error: --validation-model flag is required\n")
		flag.Usage()
		os.Exit(1)
	}

	detectionModel, err := model.GetModelOrPassthrough(detectionModelStr, isAIGateway)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\nAvailable models: %s\n", err, availableModels)
		os.Exit(1)
	}

	validationModel, err := model.GetModelOrPassthrough(validationModelStr, isAIGateway)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\nAvailable models: %s\n", err, availableModels)
		os.Exit(1)
	}

	// Validate that custom models have baseURL
	if detectionModel.RawAPIModel != "" && openaiBaseURL == "" {
		fmt.Fprintf(os.Stderr, "Error: custom models require --openai-base-url to be specified\n")
		os.Exit(1)
	}

	if validationModel.RawAPIModel != "" && openaiBaseURL == "" {
		fmt.Fprintf(os.Stderr, "Error: custom models require --openai-base-url to be specified\n")
		os.Exit(1)
	}

	result, err := analysis.RunAnalysis(context.Background(), directory, detectionModelStr, validationModelStr,
		output, debug, openaiBaseURL, requestTimeoutSec, fileConcurrency, writePrompts, isAIGateway,
		aiGuardEnabled, apiKey, jwtToken, 2, repositoryID, useLocalPrompts,
		agenticDetection, agenticVerification, agenticMaxIterations, agenticMaxToolCalls,
		exportCandidates, replayCandidates, allowSourceDrift)

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error calling RunAnalysis: %s", err)
		os.Exit(1)
	}

	// Log basic result summary
	if debug {
		fmt.Printf("Analysis completed: %d violations found across %d files using %d rules\n",
			len(result.Violations), len(result.FilesAnalyzed), len(result.Rules))
	}

	analysisDuration := time.Since(startTimestamp)
	fmt.Fprintf(os.Stderr, "\nAnalysis completed in %.2f seconds\n", analysisDuration.Seconds())
}

func effectiveAgenticModes(agentic, agenticDetection, agenticVerification bool) (bool, bool) {
	return agentic || agenticDetection, agentic || agenticVerification
}

func validateCandidateModes(exportPath, replayPath string, allowSourceDrift bool) error {
	if exportPath != "" && replayPath != "" {
		return fmt.Errorf("candidate export and replay cannot be enabled together")
	}
	if allowSourceDrift && replayPath == "" {
		return fmt.Errorf("source drift can only be allowed during candidate replay")
	}
	return nil
}
