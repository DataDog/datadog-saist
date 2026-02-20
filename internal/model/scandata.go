package model

import (
	"github.com/DataDog/datadog-saist/internal/model/api"
)

// ScanData contains all the information needed to execute a scan.
type ScanData struct {
	Model Model

	UserPrompt   string
	SystemPrompt string

	EngineVersion    string
	RelativeFilePath string
	FileHash         string

	// Content for verification
	FileText string
	// NumberedFileText caches the line-numbered version of FileText (computed once, reused for verification)
	NumberedFileText string

	// Rule
	Rule *api.AiPrompt
}

