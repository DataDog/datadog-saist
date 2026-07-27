package agenttools

import (
	"context"
	"path"
	"path/filepath"

	"github.com/DataDog/datadog-saist/internal/model"
)

// SymbolSearchKind selects which relationship a symbol lookup should return.
type SymbolSearchKind string

// SymbolIndex exposes paths from an existing repository symbol index. Paths
// must be relative to the sandbox root. Search still reads the indexed files
// to produce source-backed line matches for the model.
type SymbolIndex interface {
	LookupSymbol(symbol string, kind SymbolSearchKind) []string
}

// ProjectSymbolIndex adapts SAIST's existing tree-sitter tag index to the
// repository-tool lookup contract.
type ProjectSymbolIndex struct {
	project    *model.AiContextProject
	pathPrefix string
}

// NewProjectSymbolIndex wraps an existing project index. A nil project is
// valid and behaves like an empty index.
func NewProjectSymbolIndex(project *model.AiContextProject) *ProjectSymbolIndex {
	return &ProjectSymbolIndex{project: project}
}

// NewProjectSymbolIndexWithPrefix wraps an index whose paths are relative to a
// narrower scan directory under the repository-root sandbox.
func NewProjectSymbolIndexWithPrefix(project *model.AiContextProject, pathPrefix string) *ProjectSymbolIndex {
	return &ProjectSymbolIndex{
		project:    project,
		pathPrefix: path.Clean(filepath.ToSlash(pathPrefix)),
	}
}

// LookupSymbol returns unique repository-relative paths in index order.
func (index *ProjectSymbolIndex) LookupSymbol(symbol string, kind SymbolSearchKind) []string {
	return index.LookupSymbolContext(context.Background(), symbol, kind)
}

// LookupSymbolContext returns unique repository-relative paths while checking
// ctx before and during result construction.
func (index *ProjectSymbolIndex) LookupSymbolContext(ctx context.Context, symbol string,
	kind SymbolSearchKind) []string {
	if err := ctx.Err(); err != nil {
		return nil
	}
	if index == nil || index.project == nil {
		return nil
	}

	tagType := model.TagUnknown
	switch kind {
	case SymbolSearchDefinition:
		tagType = model.TagDefinition
	case SymbolSearchReference:
		tagType = model.TagReference
	default:
		return nil
	}

	tags := index.project.GetFilesForTagsAndType(symbol, tagType)
	if err := ctx.Err(); err != nil {
		return nil
	}
	paths := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if _, exists := seen[tag.Path]; exists {
			continue
		}
		indexedPath := filepath.ToSlash(tag.Path)
		if index.pathPrefix != "" && index.pathPrefix != "." {
			indexedPath = path.Join(index.pathPrefix, indexedPath)
		}
		seen[tag.Path] = struct{}{}
		paths = append(paths, indexedPath)
	}
	return paths
}
