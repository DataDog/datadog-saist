package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
)

var RustFunctionsToNotRegister = map[string]struct{}{
	"setUp":    {},
	"tearDown": {},
}

//go:embed tree-sitter-tags/rust.scm
var rustTagsQuery []byte

func RustGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterrust.Language())
	return getTagsFromQuery(language, rustTagsQuery, RustFunctionsToNotRegister, data)
}
