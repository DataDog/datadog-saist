package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
)

//go:embed tree-sitter-tags/rust.scm
var rustTagsQuery []byte

func RustGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterrust.Language())
	// Rust has no xUnit-style setUp/tearDown naming convention to filter by name.
	return getTagsFromQuery(language, rustTagsQuery, nil, data)
}
