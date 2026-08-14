package llmcontext

import (
	_ "embed"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitterswift "github.com/alex-pinkus/tree-sitter-swift/bindings/go"
	treesitter "github.com/tree-sitter/go-tree-sitter"
)

var SwiftFunctionsToNotRegister = map[string]struct{}{
	"setUp":             {},
	"tearDown":          {},
	"setUpWithError":    {},
	"tearDownWithError": {},
}

//go:embed tree-sitter-tags/swift.scm
var swiftTagsQuery []byte

func SwiftGetTags(data GetFunctionData) ([]model.Tag, error) {
	language := treesitter.NewLanguage(treesitterswift.Language())
	return getTagsFromQuery(language, swiftTagsQuery, SwiftFunctionsToNotRegister, data)
}
