package llmcontext

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model"

	treesitter "github.com/tree-sitter/go-tree-sitter"

	treesittercpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"

	treesittergo "github.com/tree-sitter/tree-sitter-go/bindings/go"

	treesitterjava "github.com/tree-sitter/tree-sitter-java/bindings/go"

	treesitterpython "github.com/tree-sitter/tree-sitter-python/bindings/go"

	treesitterjavascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"

	treesittertypescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	treesitterkotlin "github.com/tree-sitter-grammars/tree-sitter-kotlin/bindings/go"

	treesitterphp "github.com/tree-sitter/tree-sitter-php/bindings/go"

	treesitterruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"

	treesitterrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"

	treesitterelixir "github.com/tree-sitter/tree-sitter-elixir/bindings/go"

	treesitterswift "github.com/alex-pinkus/tree-sitter-swift/bindings/go"

	treesitterdart "github.com/UserNobody14/tree-sitter-dart/bindings/go"
)

const (
	CaptureNameIdentifier = "name"
)

type GetFunctionData struct {
	root     *treesitter.Node
	path     string
	code     []byte
	language model.Language
}

type ContextRetriever struct {
	Language        *treesitter.Language
	FunctionGetTags func(GetFunctionData) ([]model.Tag, error)
}

var contextRetrievers = map[model.Language]ContextRetriever{
	model.Go: {
		Language:        treesitter.NewLanguage(treesittergo.Language()),
		FunctionGetTags: GoGetTags,
	},
	model.Java: {
		Language:        treesitter.NewLanguage(treesitterjava.Language()),
		FunctionGetTags: JavaGetTags,
	},
	model.Python: {
		Language:        treesitter.NewLanguage(treesitterpython.Language()),
		FunctionGetTags: PythonGetTags,
	},
	model.JavaScript: {
		Language:        treesitter.NewLanguage(treesitterjavascript.Language()),
		FunctionGetTags: JavaScriptGetTags,
	},
	model.TypeScript: {
		// TSX parser is a superset of TS; using it for all .ts/.tsx/.mts/.cts keeps
		// the retriever map keyed by language rather than per-extension.
		Language:        treesitter.NewLanguage(treesittertypescript.LanguageTSX()),
		FunctionGetTags: TypeScriptGetTags,
	},
	model.Kotlin: {
		Language:        treesitter.NewLanguage(treesitterkotlin.Language()),
		FunctionGetTags: KotlinGetTags,
	},
	model.PHP: {
		Language:        treesitter.NewLanguage(treesitterphp.LanguagePHP()),
		FunctionGetTags: PHPGetTags,
	},
	model.Ruby: {
		Language:        treesitter.NewLanguage(treesitterruby.Language()),
		FunctionGetTags: RubyGetTags,
	},
	model.Rust: {
		Language:        treesitter.NewLanguage(treesitterrust.Language()),
		FunctionGetTags: RustGetTags,
	},
	model.Elixir: {
		Language:        treesitter.NewLanguage(treesitterelixir.Language()),
		FunctionGetTags: ElixirGetTags,
	},
	model.Swift: {
		Language:        treesitter.NewLanguage(treesitterswift.Language()),
		FunctionGetTags: SwiftGetTags,
	},
	model.Dart: {
		Language:        treesitter.NewLanguage(treesitterdart.Language()),
		FunctionGetTags: DartGetTags,
	},
	model.Cpp: {
		Language:        treesitter.NewLanguage(treesittercpp.Language()),
		FunctionGetTags: CppGetTags,
	},
}

// getTagsFromQuery runs a tree-sitter query over data.root and converts the matched captures into tags
func getTagsFromQuery(
	language *treesitter.Language,
	queryBytes []byte,
	functionsToNotRegister map[string]struct{},
	data GetFunctionData,
) ([]model.Tag, error) {
	res := make([]model.Tag, 0)

	query, err := treesitter.NewQuery(language, string(queryBytes))
	if err != nil {
		return res, err
	}
	defer query.Close()

	queryCursor := treesitter.NewQueryCursor()
	defer queryCursor.Close()
	// Query predicates such as #any-of? need source text to resolve captures.
	matches := queryCursor.Matches(query, data.root, data.code)
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
			if _, skip := functionsToNotRegister[tagName]; skip {
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

func GetContextFromData(language model.Language, content []byte, filePath string) (*model.AiContextFile, error) {
	contextRetriever, ok := contextRetrievers[language]

	if !ok {
		return nil, model.ErrCannotGetContext
	}

	parser := treesitter.NewParser()
	defer parser.Close()

	_ = parser.SetLanguage(contextRetriever.Language)

	tree := parser.Parse(content, nil)
	defer tree.Close()

	root := tree.RootNode()

	getData := GetFunctionData{
		root:     root,
		path:     filePath,
		code:     content,
		language: language,
	}

	tags, err := contextRetriever.FunctionGetTags(getData)
	if err != nil {
		return nil, err
	}

	return &model.AiContextFile{
		Language: language,

		Tags: tags,
	}, nil
}

// maxIndexFileSize is the maximum file size accepted for tree-sitter indexing.
// Files larger than this cannot meaningfully contribute to the LLM prompt context
// and would allocate an oversized C-heap parse tree during indexing.
const maxIndexFileSize = 1024 * 1024 // 1 MB

func GetContextFromFile(rootDirectory, relativePath string) (*model.AiContextFile, error) {
	language := model.GetLanguage(relativePath)

	if language == model.LanguageUnknown {
		return nil, model.ErrInvalidLanguage
	}

	fullPath := path.Join(rootDirectory, relativePath)
	info, err := os.Stat(fullPath) // nolint: gosec
	if err != nil {
		return nil, err
	}
	if info.Size() > maxIndexFileSize {
		return nil, fmt.Errorf("file too large for indexing (%d bytes): %s", info.Size(), relativePath)
	}

	content, errReadFile := os.ReadFile(fullPath) // nolint: gosec
	if errReadFile != nil {
		return nil, errReadFile
	}

	return GetContextFromData(language, content, relativePath)
}
