package analysis

import (
	"context"
	"fmt"
	"os"
	"strings"

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
}

type Violation = model.Violation

func configure(ctx context.Context, directory string, detectionModelStr, validationModelStr string,
	debug bool, baseURL string, requestTimeoutSec, fileConcurrency int, writePrompts, isAIGateway, aiGuardEnabled bool,
	apiKey string, jwtToken string, orgID int64, repositoryID string, useLocalPrompts bool) (model.AnalysisOptions, error) {
	datadogAuth, err := api.GetDatadogAuth()
	if err != nil {
		return model.AnalysisOptions{}, err
	}

	// Override with JWT token parameter if provided
	if jwtToken != "" {
		datadogAuth.JWTToken = &jwtToken
	}

	rules, err := api.GetPromptsFromApi(ctx, datadogAuth)

	if err != nil {
		return model.AnalysisOptions{}, err
	}

	if debug {
		log.FromContext(ctx).Infof("Got %d prompts from the Datadog API", len(rules))
	}

	if _, err := os.Stat(directory); os.IsNotExist(err) {
		return model.AnalysisOptions{}, fmt.Errorf("directory '%s' does not exist", directory)
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
	if datadogDriverEnabledEnvVar == "true" {
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
		UseLocalPrompts:   useLocalPrompts,
		DatadogDriver:     driverConfig,
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
	useLocalPrompts bool) (AnalysisSummary, error) {
	logger := log.NewDefaultLogger()
	ctx = ContextWithShimmedLogger(ctx, logger)

	opts, err := configure(ctx, directory, detectionModelStr, validationModelStr, debug, baseURL, requestTimeoutSec,
		fileConcurrency, writePrompts, isAIGateway, aiGuardEnabled, apiKey, jwtToken, orgID, repositoryID, useLocalPrompts)
	if err != nil {
		return AnalysisSummary{}, err
	}

	if opts.Debug {
		opts.Display()
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
	}, nil
}

// ContextWithShimmedLogger returns a context using the provided logger.
func ContextWithShimmedLogger(ctx context.Context, l log.DDSourceLogger) context.Context {
	if l == nil {
		return ctx
	}
	return log.Shim(ctx, l)
}
