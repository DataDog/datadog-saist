package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesittercpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"
)

//go:embed tree-sitter-tags/cpp.scm
var cppTagsQuery []byte

func CppGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesittercpp.Language())
	return getTagsFromQuery(language, cppTagsQuery, nil, data)
}
