package model

import "github.com/DataDog/datadog-saist/internal/model/api"

type DetectionContextRelatedFile struct {
	Path    string
	Content string
}

type DetectionContext struct {
	ProjectContext      AiContextProject
	Language            Language
	RepositoryDirectory string
	Path                string
	Code                string
	RelatedFiles        []DetectionContextRelatedFile
	WritePrompts        bool
	Rule                api.AiPrompt

	// StrippedCode is the lowercased code with comments/docstrings stripped.
	// Pre-compute this once per file and reuse across multiple rule checks
	// to avoid redundant regex operations. If empty, it will be computed on demand.
	StrippedCode string
}
