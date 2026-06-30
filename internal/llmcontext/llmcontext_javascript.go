package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterjavascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
)

var JavaScriptFunctionsToNotRegister = map[string]struct{}{
	"describe":   {},
	"it":         {},
	"test":       {},
	"beforeEach": {},
	"afterEach":  {},
	"beforeAll":  {},
	"afterAll":   {},
}

//go:embed tree-sitter-tags/javascript.scm
var javascriptTagsQuery []byte

func JavaScriptGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterjavascript.Language())
	return getTagsFromQuery(language, javascriptTagsQuery, JavaScriptFunctionsToNotRegister, data)
}
