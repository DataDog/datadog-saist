package llmcontext

import (
	_ "embed"
	"strings"

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

// nolint: dupl
func KotlinGetTags(data GetFunctionData) ([]model.Tag, error) {
	res := make([]model.Tag, 0)

	query, err := treesitter.NewQuery(treesitter.NewLanguage(treesitterkotlin.Language()), string(kotlinTagsQuery))
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
			if _, skip := KotlinFunctionsToNotRegister[tagName]; skip {
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
