package llmcontext

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/stretchr/testify/assert"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesitterjavascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	treesitterpython "github.com/tree-sitter/tree-sitter-python/bindings/go"
)

// Go tests

func TestGetContextFromFileGo(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "foo.go"),
		[]byte(`import "github.com/gin-gonic/gin"
func foo () {
   bar()
}`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "foo.go")
	assert.NoError(t, err)
	assert.Equal(t, llmContext.Language, model.Go)

	// tags
	assert.Len(t, llmContext.Tags, 3)
	assert.Equal(t, "\"github.com/gin-gonic/gin\"", llmContext.Tags[0].Name)
	assert.Equal(t, model.TagUnknown, llmContext.Tags[0].Type)
	assert.Equal(t, "foo", llmContext.Tags[1].Name)
	assert.Equal(t, model.TagDefinition, llmContext.Tags[1].Type)
	assert.Equal(t, "bar", llmContext.Tags[2].Name)
	assert.Equal(t, model.TagReference, llmContext.Tags[2].Type)

}

// Java tests

func TestGetContextFromFileJava(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "foo.java"),
		[]byte("import org.springframework.boot.SpringApplication;\nclass Foo{\npublic void greet(){\nfoobar(baz);\n}}"),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "foo.java")
	assert.NoError(t, err)
	assert.Equal(t, llmContext.Language, model.Java)

	// tags
	assert.Len(t, llmContext.Tags, 3)
	assert.Equal(t, "Foo", llmContext.Tags[0].Name)
	assert.Equal(t, model.TagDefinition, llmContext.Tags[0].Type)
	assert.Equal(t, "greet", llmContext.Tags[1].Name)
	assert.Equal(t, model.TagDefinition, llmContext.Tags[1].Type)
	assert.Equal(t, "foobar", llmContext.Tags[2].Name)
	assert.Equal(t, model.TagReference, llmContext.Tags[2].Type)
}

// Python tests

func TestGetContextFromFilePython(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "test.py"),
		[]byte("import os\nclass TestClass:\n    def test_method(self):\n        helper_function()\n\ndef helper_function():\n    pass\n\nhelper_function()\n"),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "test.py")
	assert.NoError(t, err)
	assert.Equal(t, llmContext.Language, model.Python)

	// tags (5 total: TestClass, test_method, helper_function def, helper_function ref, helper_function call)
	assert.Len(t, llmContext.Tags, 5)
	assert.Equal(t, "TestClass", llmContext.Tags[0].Name)
	assert.Equal(t, model.TagDefinition, llmContext.Tags[0].Type)
	assert.Equal(t, "test_method", llmContext.Tags[1].Name)
	assert.Equal(t, model.TagDefinition, llmContext.Tags[1].Type)
	assert.Equal(t, "helper_function", llmContext.Tags[2].Name)
	assert.Equal(t, model.TagReference, llmContext.Tags[2].Type)
	assert.Equal(t, "helper_function", llmContext.Tags[3].Name)
	assert.Equal(t, model.TagDefinition, llmContext.Tags[3].Type)
	assert.Equal(t, "helper_function", llmContext.Tags[4].Name)
	assert.Equal(t, model.TagReference, llmContext.Tags[4].Type)
}

func TestPythonGetTags_FunctionDefinitions(t *testing.T) {
	t.Parallel()
	code := `def function_one():
    pass

def function_two(param1, param2):
    return param1 + param2

async def async_function():
    pass

foo()

class SimpleClass:
    pass`

	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterpython.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "test.py",
		code:     []byte(code),
		language: model.Python,
	}

	tags, err := PythonGetTags(data)
	assert.NoError(t, err)
	assert.Len(t, tags, 5)

	assert.Equal(t, "function_one", tags[0].Name)
	assert.Equal(t, model.TagDefinition, tags[0].Type)
	assert.Equal(t, "test.py", tags[0].Path)
	assert.Equal(t, model.Python, tags[0].Language)

	assert.Equal(t, "function_two", tags[1].Name)
	assert.Equal(t, model.TagDefinition, tags[1].Type)

	assert.Equal(t, "async_function", tags[2].Name)
	assert.Equal(t, model.TagDefinition, tags[2].Type)

	assert.Equal(t, "foo", tags[3].Name)
	assert.Equal(t, model.TagReference, tags[3].Type)

	assert.Equal(t, "SimpleClass", tags[4].Name)
	assert.Equal(t, model.TagDefinition, tags[4].Type)
}

func TestPythonGetTags_FilteredFunctions(t *testing.T) {
	t.Parallel()
	code := `def setUp(self):
    pass

def tearDown(self):
    pass

def test_something(self):
    pass`

	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterpython.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "test.py",
		code:     []byte(code),
		language: model.Python,
	}

	tags, err := PythonGetTags(data)
	assert.NoError(t, err)
	assert.Len(t, tags, 1) // Only test_something should be included

	assert.Equal(t, "test_something", tags[0].Name)
	assert.Equal(t, model.TagDefinition, tags[0].Type)
}

func TestPythonGetTags_EmptyCode(t *testing.T) {
	t.Parallel()
	code := ``

	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterpython.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "test.py",
		code:     []byte(code),
		language: model.Python,
	}

	tags, err := PythonGetTags(data)
	assert.NoError(t, err)
	assert.Len(t, tags, 0)
}

// JavaScript tests

func TestGetContextFromFileJavaScript(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "app.js"),
		[]byte(`class Server {
  handleRequest(req) {
    processInput(req.body);
  }
}

function processInput(data) {
  return data;
}
`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "app.js")
	assert.NoError(t, err)
	assert.Equal(t, model.JavaScript, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handleRequest")
	assert.Contains(t, names, "processInput")
}

func TestJavaScriptGetTags_FunctionDefinitions(t *testing.T) {
	t.Parallel()
	code := `function greet(name) {
  return "hello " + name;
}

const farewell = (name) => "bye " + name;

class Greeter {
  sayHi() {
    greet("world");
  }
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterjavascript.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.js",
		code:     []byte(code),
		language: model.JavaScript,
	}

	tags, err := JavaScriptGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "greet")
	assert.Contains(t, names, "Greeter")
	assert.Contains(t, names, "sayHi")
}

func TestJavaScriptGetTags_FilteredFunctions(t *testing.T) {
	t.Parallel()
	code := `describe("suite", () => {
  it("does something", () => {});
  beforeEach(() => {});
  afterEach(() => {});
});

function actualCode() {}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterjavascript.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.js",
		code:     []byte(code),
		language: model.JavaScript,
	}

	tags, err := JavaScriptGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.NotContains(t, names, "describe")
	assert.NotContains(t, names, "it")
	assert.NotContains(t, names, "beforeEach")
	assert.NotContains(t, names, "afterEach")
	assert.Contains(t, names, "actualCode")
}

// Common stuff

func TestGetContextInvalidLanguage(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "foo.blabla"),
		[]byte("import foo\ndef greet(name):\n    print(f'Hello, {name}!')\n\ngreet('World')\n"),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "foo.blabla")
	assert.ErrorIs(t, err, model.ErrInvalidLanguage)
	assert.Nil(t, llmContext)
}
