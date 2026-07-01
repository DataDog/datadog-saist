package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitterkotlin "github.com/tree-sitter-grammars/tree-sitter-kotlin/bindings/go"
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

var KotlinFunctionsToNotRegister = map[string]struct{}{
	"setUp":    {},
	"tearDown": {},
}

//go:embed tree-sitter-tags/kotlin.scm
var kotlinTagsQuery []byte

func KotlinGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterkotlin.Language())
	return getTagsFromQuery(language, kotlinTagsQuery, KotlinFunctionsToNotRegister, data)
}
