package agenttools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/DataDog/datadog-saist/internal/clients"
)

// ResultMetadata contains the safe, content-free fields extracted from a tool
// result for telemetry.
type ResultMetadata struct {
	Truncated    bool
	Incomplete   bool
	Error        string
	StopReason   string
	FilesScanned int
	SearchScope  *SearchScopeMetadata
}

// SearchScopeMetadata contains the content-free search scope fields retained
// for replay telemetry.
type SearchScopeMetadata struct {
	Root                 string   `json:"root"`
	Priority             string   `json:"priority"`
	PathGlob             string   `json:"path_glob,omitempty"`
	SearchKind           string   `json:"search_kind"`
	Strategy             string   `json:"strategy"`
	ExcludedDirectories  []string `json:"excluded_directories"`
	HiddenPathsExcluded  bool     `json:"hidden_paths_excluded"`
	TextSymlinksExcluded bool     `json:"text_symlinks_excluded"`
	BinaryFilesExcluded  bool     `json:"binary_files_excluded"`
	MaxFileBytes         int64    `json:"max_file_bytes"`
}

// Definitions returns the read-only tool definitions offered to the model. The
// schemas are intentionally lenient (no additionalProperties:false) so they do
// not trip strict-mode validation on tool-offering turns.
func Definitions() []clients.ToolDefinition {
	return []clients.ToolDefinition{
		{
			Name: ToolSearchCode,
			Description: "Search file contents across the scan root for a regular expression " +
				"(falls back to a literal substring match if the pattern is invalid). " +
				"Every call must include a non-empty query. path_glob is optional: provide a repository-relative " +
				"glob to bound the search, or omit it to search the default scope (the configured priority subtree, " +
				"otherwise the entire scan root). " +
				"Use search_kind definition or reference for symbol lookups, which prefer the repository index. " +
				"Returns matching repository-relative paths, 1-based line numbers, trimmed snippets, files scanned, " +
				"search scope, and whether coverage was incomplete.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"minLength":   1,
						"pattern":     `\S`,
						"description": "Regular expression or literal text to search for.",
					},
					"path_glob": map[string]any{
						"type": "string",
						"description": "Optional repository-relative glob such as \"domains/team/**/*.go\" restricting paths. " +
							"When omitted or blank, the search covers the configured priority subtree, " +
							"or the entire scan root if none is configured.",
					},
					"search_kind": map[string]any{
						"type":        "string",
						"enum":        []string{"text", "definition", "reference"},
						"description": "Search intent. Definition and reference searches prefer the repository symbol index.",
					},
					"max_results": map[string]any{
						"type":        "integer",
						"description": "Maximum matches to return (default 50, max 200).",
					},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        ToolReadFile,
			Description: "Read a source file up to 1 MiB from the scan root, optionally a line range. Returns line-numbered content.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Repository-relative path.",
					},
					"start_line": map[string]any{
						"type":        "integer",
						"description": "1-based first line to return (optional).",
					},
					"end_line": map[string]any{
						"type":        "integer",
						"description": "1-based last line to return (optional).",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        ToolListDirectory,
			Description: "List the entries of a directory within the scan root. Returns each entry's name and type (file or dir).",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{
						"type":        "string",
						"description": "Repository-relative directory path (defaults to the scan root).",
					},
					"max_entries": map[string]any{
						"type":        "integer",
						"description": "Maximum entries to return (default 200, max 500).",
					},
				},
			},
		},
	}
}

// Execute runs the named tool with the given raw JSON arguments and returns a
// JSON result string suitable for feeding back to the model. Tool-level
// problems (bad arguments, missing files, sandbox escapes) are returned as
// structured JSON error strings rather than Go errors, so a misbehaving model
// never aborts the scan.
func Execute(sb *Sandbox, name, arguments string) string {
	return ExecuteContext(context.Background(), sb, name, arguments)
}

// ExecuteContext runs the named tool with cooperative context cancellation.
// Cancellation is returned as structured incomplete telemetry so callers can
// distinguish partial evidence from a complete tool result.
func ExecuteContext(ctx context.Context, sb *Sandbox, name, arguments string) string {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return canceledToolResult(ctx, sb, name, arguments)
	}
	return executeContext(ctx, sb, name, arguments)
}

func executeContext(ctx context.Context, sb *Sandbox, name, arguments string) string {
	switch name {
	case ToolSearchCode:
		return runSearchCodeContext(ctx, sb, arguments)
	case ToolReadFile:
		return runReadFileContext(ctx, sb, arguments)
	case ToolListDirectory:
		return runListDirectoryContext(ctx, sb, arguments)
	default:
		return toolError(fmt.Sprintf("unknown tool %q", name))
	}
}

func canceledToolResult(ctx context.Context, sb *Sandbox, name, arguments string) string {
	if name == ToolSearchCode {
		return runSearchCodeContext(ctx, sb, arguments)
	}
	return toolContextError(ctx.Err())
}

// InspectResult extracts telemetry fields from a serialized tool result. It
// never retains or returns the raw result content.
func InspectResult(output string) ResultMetadata {
	var envelope struct {
		Truncated    bool                 `json:"truncated"`
		Incomplete   bool                 `json:"incomplete"`
		Error        string               `json:"error"`
		StopReason   string               `json:"stop_reason"`
		FilesScanned int                  `json:"files_scanned"`
		SearchScope  *SearchScopeMetadata `json:"search_scope"`
	}
	if err := json.Unmarshal([]byte(output), &envelope); err != nil {
		return ResultMetadata{Error: fmt.Sprintf("invalid tool result JSON: %v", err)}
	}
	return ResultMetadata{
		Truncated:    envelope.Truncated,
		Incomplete:   envelope.Incomplete,
		Error:        envelope.Error,
		StopReason:   envelope.StopReason,
		FilesScanned: envelope.FilesScanned,
		SearchScope:  envelope.SearchScope,
	}
}

// toolError renders an error as a JSON string returned to the model.
func toolError(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

// toolContextError renders cancellation as an incomplete tool result.
func toolContextError(err error) string {
	return toolJSON(map[string]any{
		"error":       err.Error(),
		"incomplete":  true,
		"stop_reason": contextStopReason(err),
	})
}

func contextStopReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return StopReasonTimeout
	}
	return StopReasonCanceled
}

// toolJSON renders a tool result as a JSON string returned to the model.
func toolJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return toolError(fmt.Sprintf("failed to encode result: %v", err))
	}
	return string(b)
}
