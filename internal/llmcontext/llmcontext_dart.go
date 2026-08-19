package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitterdart "github.com/UserNobody14/tree-sitter-dart/bindings/go"
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

var DartFunctionsToNotRegister = map[string]struct{}{
	"setUp":       {},
	"setUpAll":    {},
	"tearDown":    {},
	"tearDownAll": {},
}

//go:embed tree-sitter-tags/dart.scm
var dartTagsQuery []byte

func DartGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterdart.Language())
	return getTagsFromQuery(language, dartTagsQuery, DartFunctionsToNotRegister, data)
}
