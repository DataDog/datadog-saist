package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterelixir "github.com/tree-sitter/tree-sitter-elixir/bindings/go"
)

var ElixirFunctionsToNotRegister = map[string]struct{}{
	"setup":     {},
	"setup_all": {},
}

//go:embed tree-sitter-tags/elixir.scm
var elixirTagsQuery []byte

func ElixirGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterelixir.Language())
	return getTagsFromQuery(language, elixirTagsQuery, ElixirFunctionsToNotRegister, data)
}
