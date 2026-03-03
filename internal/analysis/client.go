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
	apiKey string, jwtToken string, orgID int64, repositoryID string, useLocalPrompts, localPromptsOnly bool) (model.AnalysisOptions, error) {
	var rules []modelApi.AiPrompt

	if localPromptsOnly {
		// Skip API call entirely, use only local rules
		rules = getLocalOnlyRules()
		if debug {
			log.FromContext(ctx).Infof("Using %d local-only rules (skipping API)", len(rules))
		}
	} else {
		// Fetch rules from API
		datadogAuth, err := api.GetDatadogAuth()
		if err != nil {
			return model.AnalysisOptions{}, err
		}

		// Override with JWT token parameter if provided
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

		// When using local prompts, add stub rules for new prompts that don't exist in the API yet
		if useLocalPrompts {
			rules = appendLocalOnlyRules(rules, debug, log.FromContext(ctx))
		}
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
	useLocalPrompts, localPromptsOnly bool) (AnalysisSummary, error) {
	logger := log.NewDefaultLogger()
	ctx = ContextWithShimmedLogger(ctx, logger)

	opts, err := configure(ctx, directory, detectionModelStr, validationModelStr, debug, baseURL, requestTimeoutSec,
		fileConcurrency, writePrompts, isAIGateway, aiGuardEnabled, apiKey, jwtToken, orgID, repositoryID, useLocalPrompts, localPromptsOnly)
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

// getLocalOnlyRules returns the list of local-only rules for testing.
// This is used when -local-prompts-only is set to skip the API entirely.
func getLocalOnlyRules() []modelApi.AiPrompt {
	return buildLocalRules()
}

// appendLocalOnlyRules adds stub rules for prompts that only exist locally (not in the API yet).
// This enables testing new prompts before they are deployed to the API.
func appendLocalOnlyRules(existingRules []modelApi.AiPrompt, debug bool, logger log.DDSourceLogger) []modelApi.AiPrompt {
	localRules := buildLocalRules()

	// Check which local rules don't already exist in the API response
	existingIDs := make(map[string]bool)
	for _, rule := range existingRules {
		existingIDs[rule.ID] = true
	}

	addedCount := 0
	for _, localRule := range localRules {
		if !existingIDs[localRule.ID] {
			existingRules = append(existingRules, localRule)
			addedCount++
			if debug {
				logger.Infof("Added local-only rule: %s", localRule.ID)
			}
		}
	}

	if debug && addedCount > 0 {
		logger.Infof("Added %d local-only rules for testing", addedCount)
	}

	return existingRules
}

// buildLocalRules creates the list of local security rules for testing.
func buildLocalRules() []modelApi.AiPrompt {
	cweCmdi := "78"
	cweSqli := "89"
	cweXpathi := "643"
	cweXss := "79"
	cweWeakRandom := "330"
	cweWeakHash := "328"
	cweWeakCrypto := "327"
	cwePathTraversal := "22"
	cweLdapi := "90"
	cweTrustBoundary := "501"
	cweInsecureCookie := "614"

	return []modelApi.AiPrompt{
		// === JAVA RULES ===
		{
			ID:               "datadog/java-cmdi",
			Globs:            []string{"**/*.java"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweCmdi,
			ShortDescription: "Potential command injection",
			Description:      "Detects command injection vulnerabilities in Java code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"runtime", "exec", "processbuilder", "process", "shell", "bash", "cmd",
			},
			ResultKeywordsExclude: []string{"code injection", "script injection"},
		},
		{
			ID:               "datadog/java-sqli",
			Globs:            []string{"**/*.java"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweSqli,
			ShortDescription: "Potential SQL injection",
			Description:      "Detects SQL injection vulnerabilities in Java code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"database", "sql", "select", "update", "insert", "delete", "from",
				"connection", "statement", "preparedstatement", "executequery",
			},
			ResultKeywordsExclude: []string{"xpath injection", "ldap injection"},
		},
		{
			ID:               "datadog/java-xpathi",
			Globs:            []string{"**/*.java"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweXpathi,
			ShortDescription: "Potential XPath injection",
			Description:      "Detects XPath injection vulnerabilities in Java code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"xpath", "documentbuilderfactory", "compile", "xpathexpression",
			},
			ResultKeywordsExclude: []string{"sql injection", "ldap injection"},
		},
		{
			ID:               "datadog/java-xss",
			Globs:            []string{"**/*.java"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweXss,
			ShortDescription: "Potential cross-site scripting",
			Description:      "Detects XSS vulnerabilities in Java code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"getparameter", "getheader", "getwriter", "printwriter", "response",
				"xss", "<html", "<body", "<script", "<form", "<input", "<img", "<iframe", "<div", "<span", "<a",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		// === PYTHON RULES ===
		{
			ID:               "datadog/python-sqli",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweSqli,
			ShortDescription: "Potential SQL injection",
			Description:      "Detects SQL injection vulnerabilities in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"sqlite3", "cursor", "execute", "select", "update", "insert", "delete",
				"psycopg2", "sqlalchemy",
			},
			ResultKeywordsExclude: []string{"xpath injection", "ldap injection"},
		},
		{
			ID:               "datadog/python-xss",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweXss,
			ShortDescription: "Potential cross-site scripting",
			Description:      "Detects XSS vulnerabilities in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"render", "template", "response", "html", "jinja",
				"<html", "<body", "<script", "<form", "<input", "<img", "<iframe",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		{
			ID:               "datadog/python-cmdi",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweCmdi,
			ShortDescription: "Potential command injection",
			Description:      "Detects command injection vulnerabilities in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"subprocess", "os.system", "os.popen", "shell", "bash", "exec", "eval",
			},
			ResultKeywordsExclude: []string{"code injection", "script injection"},
		},
		{
			ID:               "datadog/python-weakrandom",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakRandom,
			ShortDescription: "Potential weak randomness",
			Description:      "Detects use of weak random number generation for security-sensitive operations in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"random", "random.random", "random.randint", "random.choice",
				"token", "password", "session", "secret",
			},
			ResultKeywordsExclude: []string{"test", "mock", "shuffle"},
		},
		// === GO RULES ===
		{
			ID:               "datadog/go-sqli",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweSqli,
			ShortDescription: "Potential SQL injection",
			Description:      "Detects SQL injection vulnerabilities in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"sql", "select", "update", "insert", "delete", "from", "query",
				"exec", "database/sql",
			},
			ResultKeywordsExclude: []string{"xpath injection", "ldap injection"},
		},
		{
			ID:               "datadog/go-xss",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweXss,
			ShortDescription: "Potential cross-site scripting",
			Description:      "Detects XSS vulnerabilities in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"responsewriter", "write", "fprintf", "template", "html",
				"<html", "<body", "<script", "<form", "<input", "<img", "<iframe", "<div", "<span",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		{
			ID:               "datadog/go-cmdi",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweCmdi,
			ShortDescription: "Potential command injection",
			Description:      "Detects command injection vulnerabilities in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"exec", "command", "shell", "bash", "os/exec",
			},
			ResultKeywordsExclude: []string{"code injection", "script injection"},
		},
		{
			ID:               "datadog/go-weakrandom",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakRandom,
			ShortDescription: "Potential weak randomness",
			Description:      "Detects use of weak random number generation for security-sensitive operations in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"math/rand", "rand.intn", "rand.int", "token", "password", "session", "secret",
			},
			ResultKeywordsExclude: []string{"test", "mock", "shuffle", "crypto/rand"},
		},
		// === JAVA ADDITIONAL RULES ===
		{
			ID:               "datadog/java-weakhash",
			Globs:            []string{"**/*.java"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakHash,
			ShortDescription: "Potential weak hash algorithm",
			Description:      "Detects use of weak hash algorithms (MD5, SHA-1) for security-sensitive operations in Java code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"messagedigest", "md5", "sha-1", "sha1", "digestutils", "password", "hash",
			},
			ResultKeywordsExclude: []string{"checksum", "cache", "etag"},
		},
		// === PYTHON ADDITIONAL RULES ===
		{
			ID:               "datadog/python-xpathi",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweXpathi,
			ShortDescription: "Potential XPath injection",
			Description:      "Detects XPath injection vulnerabilities in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"xpath", "lxml", "etree",
			},
			ResultKeywordsExclude: []string{"sql injection", "ldap injection"},
		},
		{
			ID:               "datadog/python-pathtraversal",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cwePathTraversal,
			ShortDescription: "Potential path traversal",
			Description:      "Detects path traversal vulnerabilities in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"open", "read", "write", "file", "path", "os.path",
				"send_file", "send_from_directory",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		{
			ID:               "datadog/python-ldapi",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweLdapi,
			ShortDescription: "Potential LDAP injection",
			Description:      "Detects LDAP injection vulnerabilities in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"ldap", "search", "bind", "ldap3", "python-ldap",
			},
			ResultKeywordsExclude: []string{"sql injection", "xpath injection"},
		},
		// === GO ADDITIONAL RULES ===
		{
			ID:               "datadog/go-xpathi",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweXpathi,
			ShortDescription: "Potential XPath injection",
			Description:      "Detects XPath injection vulnerabilities in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"xpath", "xmlquery",
			},
			ResultKeywordsExclude: []string{"sql injection", "ldap injection"},
		},
		{
			ID:               "datadog/go-pathtraversal",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cwePathTraversal,
			ShortDescription: "Potential path traversal",
			Description:      "Detects path traversal vulnerabilities in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"os.open", "os.readfile", "os.writefile", "filepath", "ioutil",
				"servefile", "http.dir",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		{
			ID:               "datadog/go-ldapi",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweLdapi,
			ShortDescription: "Potential LDAP injection",
			Description:      "Detects LDAP injection vulnerabilities in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"ldap", "search", "bind", "dial",
			},
			ResultKeywordsExclude: []string{"sql injection", "xpath injection"},
		},
		// === C# RULES ===
		{
			ID:               "datadog/csharp-trustboundary",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweTrustBoundary,
			ShortDescription: "Potential trust boundary violation",
			Description:      "Detects trust boundary violations in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"session", "httpcontext.session", "ihttpsessionfeature",
				"tempdata", "request.form", "request.query",
				"claimsprincipal", "httpcontext.user",
				"setstring", "setint32", "viewdata", "viewbag",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		{
			ID:               "datadog/csharp-pathtraversal",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cwePathTraversal,
			ShortDescription: "Potential path traversal",
			Description:      "Detects path traversal vulnerabilities in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"file.open", "file.read", "file.write", "file.delete",
				"filestream", "streamreader", "streamwriter",
				"path.combine", "path.getfullpath",
				"fileinfo", "directoryinfo", "physicalfile",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		{
			ID:               "datadog/csharp-weakhash",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakHash,
			ShortDescription: "Potential weak hash algorithm",
			Description:      "Detects use of weak hash algorithms (MD5, SHA-1) for security-sensitive operations in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"md5.create", "sha1.create", "md5cryptoserviceprovider",
				"sha1cryptoserviceprovider", "sha1managed", "password", "hash",
			},
			ResultKeywordsExclude: []string{"checksum", "cache", "etag"},
		},
		{
			ID:               "datadog/csharp-weakcrypto",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakCrypto,
			ShortDescription: "Potential weak cryptography",
			Description:      "Detects use of weak cryptographic algorithms in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"symmetricalgorithm", "aes.create", "des.create", "descryptoserviceprovider",
				"rc2cryptoserviceprovider", "ciphermode.ecb", "rijndael",
			},
			ResultKeywordsExclude: []string{"test", "mock"},
		},
		{
			ID:               "datadog/csharp-cmdi",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweCmdi,
			ShortDescription: "Potential command injection",
			Description:      "Detects command injection vulnerabilities in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"process.start", "processstartinfo", "cmd.exe", "powershell", "shell", "bash",
			},
			ResultKeywordsExclude: []string{"code injection", "script injection"},
		},
		{
			ID:               "datadog/csharp-ldapi",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweLdapi,
			ShortDescription: "Potential LDAP injection",
			Description:      "Detects LDAP injection vulnerabilities in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"directoryentry", "directorysearcher", "ldapconnection",
				"system.directoryservices", "findall", "findone",
			},
			ResultKeywordsExclude: []string{"sql injection", "xpath injection"},
		},
		{
			ID:               "datadog/csharp-xss",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweXss,
			ShortDescription: "Potential cross-site scripting",
			Description:      "Detects XSS vulnerabilities in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"html.raw", "htmlstring", "contentresult", "viewbag", "viewdata",
				"razorpage", "htmlencoder", "javascriptencoder",
				"<html", "<body", "<script",
			},
			ResultKeywordsExclude: []string{"sql injection", "command injection"},
		},
		// === FPR IMPROVEMENT RULES ===
		{
			ID:               "datadog/csharp-insecurecookie",
			Globs:            []string{"**/*.cs"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweInsecureCookie,
			ShortDescription: "Potential insecure cookie",
			Description:      "Detects cookies without Secure, HttpOnly, or SameSite attributes in C# code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"response.cookies.append", "response.cookies.add", "cookieoptions",
				"httpcontext.response.cookies",
			},
			ResultKeywordsExclude: []string{"sql injection", "xss"},
		},
		{
			ID:               "datadog/java-weakcrypto",
			Globs:            []string{"**/*.java"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakCrypto,
			ShortDescription: "Potential weak cryptography",
			Description:      "Detects use of weak cryptographic algorithms (DES, 3DES, RC4) in Java code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"cipher", "des", "ecb", "rc4", "arcfour", "secretkey",
				"ivparameterspec", "random", "keypairgenerator",
			},
			ResultKeywordsExclude: []string{"weak hash", "md5"},
		},
		{
			ID:               "datadog/python-weakcrypto",
			Globs:            []string{"**/*.py"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakCrypto,
			ShortDescription: "Potential weak cryptography",
			Description:      "Detects use of weak cryptographic algorithms (DES, 3DES, RC4) in Python code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"des", "ecb", "rc4", "aes", "crypto", "pycrypto", "cryptography", "hashlib",
			},
			ResultKeywordsExclude: []string{"weak hash", "md5"},
		},
		{
			ID:               "datadog/go-weakcrypto",
			Globs:            []string{"**/*.go"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweWeakCrypto,
			ShortDescription: "Potential weak cryptography",
			Description:      "Detects use of weak cryptographic algorithms (DES, RC4) in Go code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"cipher", "des", "ecb", "rc4", "aes", "crypto", "rand", "secretkey",
			},
			ResultKeywordsExclude: []string{"weak hash", "md5"},
		},
		{
			ID:               "datadog/java-ldapi",
			Globs:            []string{"**/*.java"},
			ExecutionMode:    modelApi.ExecutionModeAuto,
			Severity:         modelApi.SeverityWarning,
			Category:         modelApi.CategorySecurity,
			Cwe:              &cweLdapi,
			ShortDescription: "Potential LDAP injection",
			Description:      "Detects LDAP injection vulnerabilities in Java code",
			IsDefault:        true,
			IsTesting:        true,
			Version:          "0.0.1",
			FileSearchKeywords: []string{
				"ldap", "dircontext", "search", "ldapcontext", "ldaptemplate",
				"initialdircontext", "jndi",
			},
			ResultKeywordsExclude: []string{"sql injection", "xpath injection"},
		},
	}
}
