package llmcontext

import (
	"os"
	"path"

	"github.com/DataDog/datadog-saist/internal/model"

	treesitter "github.com/tree-sitter/go-tree-sitter"

	treesittergo "github.com/tree-sitter/tree-sitter-go/bindings/go"

	treesitterjava "github.com/tree-sitter/tree-sitter-java/bindings/go"

	treesitterpython "github.com/tree-sitter/tree-sitter-python/bindings/go"
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

func GetContextFromFile(rootDirectory, relativePath string) (*model.AiContextFile, error) {
	language := model.GetLanguage(relativePath)

	if language == model.LanguageUnknown {
		return nil, model.ErrInvalidLanguage
	}

	content, errReadFile := os.ReadFile(path.Join(rootDirectory, relativePath)) // nolint: gosec
	if errReadFile != nil {
		return nil, errReadFile
	}

	return GetContextFromData(language, content, relativePath)
}
