package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesittergo "github.com/tree-sitter/tree-sitter-go/bindings/go"
)

var GoFunctionsToNotRegister = map[string]struct{}{
	"setUp":    {},
	"tearDown": {},
}

var GoLibraryToFrameworks = map[string]string{
	"gin":   "gin",
	"echo":  "echo",
	"fiber": "fiber",
	"beego": "beego",
	"revel": "revel",
}

//go:embed tree-sitter-tags/go.scm
var goTagsQuery []byte

func GoGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesittergo.Language())
	return getTagsFromQuery(language, goTagsQuery, GoFunctionsToNotRegister, data)
}
