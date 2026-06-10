package model

import (
	"github.com/DataDog/datadog-saist/internal/model/api"
)

// FileContent holds file text shared across all ScanData for the same file,
// avoiding duplicate string allocations when multiple rules apply to one file.
type FileContent struct {
	Text     string
	Numbered string
}

// ScanData contains all the information needed to execute a scan.
type ScanData struct {
	Model Model

	UserPrompt   string
	SystemPrompt string

	EngineVersion    string
	RelativeFilePath string
	FileHash         string

	// FileContent is shared across all ScanData built for the same file.
	FileContent *FileContent

	// Rule
	Rule *api.AiPrompt
}
