package model

import (
	"fmt"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

// AnalysisOptions contains all configuration options for the analysis (internal use only)
type AnalysisOptions struct {
	Directory         string
	DetectionModel    Model
	ValidationModel   Model
	Debug             bool
	OpenAIBaseURL     string
	RequestTimeoutSec int
	FileConcurrency   int
	WritePrompts      bool
	IsAIGateway       bool
	AIGuardEnabled    bool
	Rules             []api.AiPrompt
	OrgID             int64
	RepositoryID      string
	SkipIndexing      bool
	UseLocalPrompts   bool
	DatadogDriver     *DatadogDriverConfig
}

// Display prints the AnalysisOptions information to stdout
func (opts *AnalysisOptions) Display() {
	fmt.Println("=== Analysis Options ===")
	fmt.Printf("Directory:           %s\n", opts.Directory)
	fmt.Printf("Detection Model:     %s\n", opts.DetectionModel)
	fmt.Printf("Validation Model:    %s\n", opts.ValidationModel)
	fmt.Printf("Debug:               %t\n", opts.Debug)
	fmt.Printf("OpenAI Base URL:     %s\n", opts.OpenAIBaseURL)
	fmt.Printf("Request Timeout:     %d seconds\n", opts.RequestTimeoutSec)
	fmt.Printf("File Concurrency:    %d\n", opts.FileConcurrency)
	fmt.Printf("Write Prompts:       %t\n", opts.WritePrompts)
	fmt.Printf("AI Gateway Enabled:  %t\n", opts.IsAIGateway)
	fmt.Printf("AI Guard Enabled:    %t\n", opts.AIGuardEnabled)
	fmt.Printf("Organization ID:     %d\n", opts.OrgID)
	fmt.Printf("Repository ID:       %s\n", opts.RepositoryID)
	fmt.Printf("Skip Indexing:       %t\n", opts.SkipIndexing)
	fmt.Printf("Use Local Prompts:   %t\n", opts.UseLocalPrompts)
	fmt.Printf("Number of Rules:     %d\n", len(opts.Rules))
	fmt.Println("========================")
}
