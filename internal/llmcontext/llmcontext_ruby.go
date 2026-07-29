package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
)

var RubyFunctionsToNotRegister = map[string]struct{}{
	"setup":    {},
	"teardown": {},
	"before":   {},
	"after":    {},
}

//go:embed tree-sitter-tags/ruby.scm
var rubyTagsQuery []byte

func RubyGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterruby.Language())
	return getTagsFromQuery(language, rubyTagsQuery, RubyFunctionsToNotRegister, data)
}
