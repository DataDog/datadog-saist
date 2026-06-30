package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesittertypescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
)

var TypeScriptFunctionsToNotRegister = map[string]struct{}{
	"describe":   {},
	"it":         {},
	"test":       {},
	"beforeEach": {},
	"afterEach":  {},
	"beforeAll":  {},
	"afterAll":   {},
}

//go:embed tree-sitter-tags/typescript.scm
var typescriptTagsQuery []byte

func TypeScriptGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesittertypescript.LanguageTSX())
	return getTagsFromQuery(language, typescriptTagsQuery, TypeScriptFunctionsToNotRegister, data)
}
