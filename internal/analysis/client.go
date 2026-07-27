package analysis

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DataDog/datadog-saist/internal/agents"
	"github.com/DataDog/datadog-saist/internal/api"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	modelApi "github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/sarif"
	"github.com/DataDog/datadog-saist/internal/utils"
)

// AnalysisSummary contains the results and metadata from running analysis
type AnalysisSummary struct {
	FilesAnalyzed []string
	Rules         []modelApi.AiPrompt
	Violations    []Violation
	InputTokens   int32
	OutputTokens  int32
	ModelCalls    int32
}

type Violation = model.Violation

func configure(ctx context.Context, directory string, detectionModelStr, validationModelStr string,
	debug bool, baseURL string, requestTimeoutSec, fileConcurrency int, writePrompts, isAIGateway, aiGuardEnabled bool,
	apiKey string, jwtToken string, orgID int64, repositoryID string, useLocalPrompts bool,
	agenticDetection, agenticVerification bool,
	agenticMaxIterations, agenticMaxToolCalls int,
	exportCandidatesPath, replayCandidatesPath string, allowSourceDrift bool) (model.AnalysisOptions, error) {
	if exportCandidatesPath != "" && replayCandidatesPath != "" {
		return model.AnalysisOptions{}, fmt.Errorf("candidate export and replay cannot be enabled together")
	}
	if allowSourceDrift && replayCandidatesPath == "" {
		return model.AnalysisOptions{}, fmt.Errorf("source drift can only be allowed during candidate replay")
	}
	if repositoryID == "" {
		return model.AnalysisOptions{}, fmt.Errorf("repository ID is required")
	}

	var rules []modelApi.AiPrompt
	if replayCandidatesPath != "" {
		if debug {
			log.FromContext(ctx).Info("Candidate replay uses rule metadata from the manifest")
		}
	} else if useLocalPrompts {
		var err error
		rules, err = agents.LoadLocalRules()
		if err != nil {
			return model.AnalysisOptions{}, fmt.Errorf("loading local rules: %w", err)
		}
		if debug {
			log.FromContext(ctx).Infof("Loaded %d local rules from embedded files", len(rules))
		}
	} else {
		datadogAuth, err := api.GetDatadogAuth()
		if err != nil {
			return model.AnalysisOptions{}, err
		}
		if jwtToken != "" {
			datadogAuth.JWTToken = &jwtToken
		}
		rules, err = api.GetPromptsFromApi(ctx, datadogAuth)
		if err != nil {
			return model.AnalysisOptions{}, err
		}
		if debug {
			log.FromContext(ctx).Infof("Got %d prompts from the Datadog API", len(rules))
		}
	}

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return model.AnalysisOptions{}, fmt.Errorf("directory '%s' does not exist", directory)
	}

	var repositoryRoot string
	var repositorySHA string
	var repositoryDirty bool
	var candidateScanRoot string
	if exportCandidatesPath != "" || replayCandidatesPath != "" {
		var err error
		repositoryRoot, repositorySHA, repositoryDirty, candidateScanRoot, err = resolveSourceRevision(ctx, directory)
		if err != nil {
			return model.AnalysisOptions{}, err
		}
		if exportCandidatesPath != "" {
			if err := validateCandidateExportPath(repositoryRoot, exportCandidatesPath); err != nil {
				return model.AnalysisOptions{}, err
			}
		}
	}

	detectionModel, err := model.GetModelOrPassthrough(detectionModelStr, isAIGateway)
	if err != nil {
		availableModels := strings.Join(model.GetAllModelStrings(), ", ")
		return model.AnalysisOptions{}, fmt.Errorf("invalid detection model '%s'. Available models: %s",
			detectionModelStr, availableModels)
	}

	validationModel, err := model.GetModelOrPassthrough(validationModelStr, isAIGateway)
	if err != nil {
		availableModels := strings.Join(model.GetAllModelStrings(), ", ")
		return model.AnalysisOptions{}, fmt.Errorf("invalid validation model '%s'. Available models: %s",
			validationModelStr, availableModels)
	}

	// Set API key for the selected models' providers (from function parameters, not env vars)
	setAPIKey(detectionModel, baseURL, apiKey)
	setAPIKey(validationModel, baseURL, apiKey)

	// Load Datadog driver configuration if enabled
	var driverConfig *model.DatadogDriverConfig
	datadogDriverEnabledEnvVar := os.Getenv(model.DatadogDriverEnabledEnvVar)
	if replayCandidatesPath == "" && datadogDriverEnabledEnvVar == "true" {
		config, err := utils.LoadDatadogDriverConfig(directory)
		if err != nil {
			return model.AnalysisOptions{}, fmt.Errorf("failed to load Datadog driver config: %w", err)
		}
		if debug {
			log.FromContext(ctx).Info("Datadog driver loaded")
		}

		driverConfig = &config
	}

	return model.AnalysisOptions{
		Directory:         directory,
		DetectionModel:    detectionModel,
		ValidationModel:   validationModel,
		Debug:             debug,
		OpenAIBaseURL:     baseURL,
		RequestTimeoutSec: requestTimeoutSec,
		FileConcurrency:   fileConcurrency,
		WritePrompts:      writePrompts,
		Rules:             rules,
		IsAIGateway:       isAIGateway,
		AIGuardEnabled:    aiGuardEnabled,
		OrgID:             orgID,
		RepositoryID:      repositoryID,
		SkipIndexing:      false, // Set to true to skip code indexing
		DatadogDriver:     driverConfig,

		AgenticDetection:     agenticDetection,
		AgenticVerification:  agenticVerification,
		AgenticMaxIterations: agenticMaxIterations,
		AgenticMaxToolCalls:  agenticMaxToolCalls,

		ExportCandidatesPath: exportCandidatesPath,
		ReplayCandidatesPath: replayCandidatesPath,
		AllowSourceDrift:     allowSourceDrift,
		RepositoryRoot:       repositoryRoot,
		RepositorySHA:        repositorySHA,
		RepositoryDirty:      repositoryDirty,
		CandidateScanRoot:    candidateScanRoot,
	}, nil
}

// Calls clients.SetProvidedAPIKey for the given model.
func setAPIKey(modelValue model.Model, baseURL, apiKey string) {
	if apiKey != "" {
		if baseURL != "" {
			// When base URL is provided, we always use OpenAI client, so store key as "openai"
			clients.SetProvidedAPIKey("openai", apiKey)
		} else if modelValue.RawAPIModel != "" {
			// Custom modelValue without baseURL - shouldn't happen with validation
			// but set for openai as fallback
			clients.SetProvidedAPIKey("openai", apiKey)
		} else {
			// No base URL - set key based on modelValue's detected provider
			switch {
			case modelValue.IsOpenAI():
				clients.SetProvidedAPIKey(model.ProviderOpenAI, apiKey)
			case modelValue.IsAnthropic():
				clients.SetProvidedAPIKey(model.ProviderAnthropic, apiKey)
			case modelValue.IsGoogle():
				clients.SetProvidedAPIKey(model.ProviderGoogle, apiKey)
			}
		}
	}
}

// RunAnalysis is the main public API function that runs analysis
func RunAnalysis(ctx context.Context, directory string, detectionModelStr, validationModelStr, output string,
	debug bool, baseURL string, requestTimeoutSec, fileConcurrency int, writePrompts, isAIGateway,
	aiGuardEnabled bool, apiKey string, jwtToken string, orgID int64, repositoryID string,
	useLocalPrompts bool, agenticDetection, agenticVerification bool,
	agenticMaxIterations, agenticMaxToolCalls int,
	exportCandidatesPath, replayCandidatesPath string, allowSourceDrift bool) (AnalysisSummary, error) {
	logger := log.NewDefaultLogger()
	ctx = ContextWithShimmedLogger(ctx, logger)

	opts, err := configure(ctx, directory, detectionModelStr, validationModelStr, debug, baseURL, requestTimeoutSec,
		fileConcurrency, writePrompts, isAIGateway, aiGuardEnabled, apiKey, jwtToken, orgID, repositoryID, useLocalPrompts,
		agenticDetection, agenticVerification, agenticMaxIterations, agenticMaxToolCalls,
		exportCandidatesPath, replayCandidatesPath, allowSourceDrift)
	if err != nil {
		return AnalysisSummary{}, err
	}
	logger.Infof("Agentic modes configured, detection=%t verification=%t",
		opts.AgenticDetection, opts.AgenticVerification)

	if opts.Debug {
		opts.Display()
	}
	if opts.ReplayCandidatesPath != "" {
		return runCandidateReplay(ctx, &opts, output)
	}

	result, err := analyzeAndGenerateReport(ctx, &opts)
	if err != nil {
		return AnalysisSummary{}, fmt.Errorf("analysis failed: %v", err)
	}

	sarifInformation := sarif.GenerateSarifInformation(&opts, result)
	sarifReport, err := sarif.GenerateSarifReport(&sarifInformation)
	if err != nil {
		return AnalysisSummary{}, err
	}

	err = sarif.WriteSarifContent(sarifReport, output)
	if err != nil {
		logger.Errorf("error writing sarif report: %v", err)
	} else {
		logger.Infof("Analysis completed successfully. Report written to: %s", output)
	}

	return AnalysisSummary{
		Violations:    sarifInformation.Violations,
		Rules:         sarifInformation.Rules,
		FilesAnalyzed: sarifInformation.FilesAnalyzed,
		InputTokens:   sarifInformation.InputTokens,
		OutputTokens:  sarifInformation.OutputTokens,
		ModelCalls:    sarifInformation.ModelCalls,
	}, nil
}

// ContextWithShimmedLogger returns a context using the provided logger.
func ContextWithShimmedLogger(ctx context.Context, l log.DDSourceLogger) context.Context {
	if l == nil {
		return ctx
	}
	return log.Shim(ctx, l)
}
