package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterphp "github.com/tree-sitter/tree-sitter-php/bindings/go"
)

var PHPFunctionsToNotRegister = map[string]struct{}{
	"setUp":    {},
	"tearDown": {},
}

//go:embed tree-sitter-tags/php.scm
var phpTagsQuery []byte

func PHPGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterphp.LanguagePHP())
	return getTagsFromQuery(language, phpTagsQuery, PHPFunctionsToNotRegister, data)
}
