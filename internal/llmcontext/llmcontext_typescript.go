package llmcontext

import (
	_ "embed"
	"strings"

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
	res := make([]model.Tag, 0)

	query, err := treesitter.NewQuery(treesitter.NewLanguage(treesittertypescript.LanguageTSX()), string(typescriptTagsQuery))
	if err != nil {
		return res, err
	}
	defer query.Close()

	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()
	matches := queryCursor.Matches(query, data.root, nil)

	captureNames := query.CaptureNames()

	for {
		match := matches.Next()
		if match == nil {
			break
		}

		tagType := model.TagUnknown
		tagName := ""
		for _, capture := range match.Captures {
			captureName := captureNames[capture.Index]
			node := capture.Node
			if captureName == CaptureNameIdentifier {
				tagName = node.Utf8Text(data.code)
			}

			if strings.Contains(captureName, "definition") {
				tagType = model.TagDefinition
			}

			if strings.Contains(captureName, "reference") {
				tagType = model.TagReference
			}
		}

		if tagName != "" {
			if _, skip := TypeScriptFunctionsToNotRegister[tagName]; skip {
				continue
			}
			res = append(res, model.Tag{
				Type:     tagType,
				Name:     tagName,
				Path:     data.path,
				Language: data.language,
			})
		}
	}

	return res, nil
}
