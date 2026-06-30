package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterpython "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

var PythonFunctionsToNotRegister = map[string]struct{}{
	"setUp":    {},
	"tearDown": {},
}

var PythonLibraryToFrameworks = map[string]string{}

//go:embed tree-sitter-tags/python.scm
var pythonTagsQuery []byte

func PythonGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterpython.Language())
	return getTagsFromQuery(language, pythonTagsQuery, PythonFunctionsToNotRegister, data)
}
