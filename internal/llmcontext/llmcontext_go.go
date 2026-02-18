package llmcontext

import (
	_ "embed"
	"strings"

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
	res := make([]model.Tag, 0)

	query, err := treesitter.NewQuery(treesitter.NewLanguage(treesittergo.Language()), string(goTagsQuery))
	if err != nil {
		return res, err
	}
	defer query.Close()

	queryCursor := treesitter.NewQueryCursor()
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
