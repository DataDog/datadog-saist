package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterjava "github.com/tree-sitter/tree-sitter-java/bindings/go"
)

var JavaFunctionsToNotRegister = map[string]struct{}{
	"setUp":    {},
	"tearDown": {},
}

var JavaLibraryToFrameworks = map[string]string{
	"springframework": "spring",
	"hibernate":       "hibernate",
	"jakarta":         "jakarta",
	"micronaut":       "micronaut",
}

//go:embed tree-sitter-tags/java.scm
var javaTagsQuery []byte

func JavaGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterjava.Language())
	return getTagsFromQuery(language, javaTagsQuery, JavaFunctionsToNotRegister, data)
}
