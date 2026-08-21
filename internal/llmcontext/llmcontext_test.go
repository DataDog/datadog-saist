package llmcontext

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	treesitterdart "github.com/UserNobody14/tree-sitter-dart/bindings/go"
	treesitterswift "github.com/alex-pinkus/tree-sitter-swift/bindings/go"
	"github.com/stretchr/testify/assert"
	treesitterkotlin "github.com/tree-sitter-grammars/tree-sitter-kotlin/bindings/go"
	treesitter "github.com/tree-sitter/go-tree-sitter"
	treesittercpp "github.com/tree-sitter/tree-sitter-cpp/bindings/go"
	treesitterelixir "github.com/tree-sitter/tree-sitter-elixir/bindings/go"
	treesitterjavascript "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	treesitterphp "github.com/tree-sitter/tree-sitter-php/bindings/go"
	treesitterpython "github.com/tree-sitter/tree-sitter-python/bindings/go"
	treesitterruby "github.com/tree-sitter/tree-sitter-ruby/bindings/go"
	treesitterrust "github.com/tree-sitter/tree-sitter-rust/bindings/go"
	treesittertypescript "github.com/tree-sitter/tree-sitter-typescript/bindings/go"
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

// TypeScript tests

func TestGetContextFromFileTypeScript(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "app.ts"),
		[]byte(`interface Request {
  body: string;
}

class Server {
  handleRequest(req: Request): void {
    processInput(req.body);
  }
}

function processInput(data: string): string {
  return data;
}
`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "app.ts")
	assert.NoError(t, err)
	assert.Equal(t, model.TypeScript, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Request")
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handleRequest")
	assert.Contains(t, names, "processInput")
}

func TestTypeScriptGetTags_TypeScriptSpecificDefinitions(t *testing.T) {
	t.Parallel()
	code := `interface User {
  id: number;
  name: string;
}

type UserId = string | number;

enum Role {
  Admin,
  Viewer,
}

abstract class Base {
  abstract render(): void;
}

class Concrete extends Base {
  render(): void {}
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesittertypescript.LanguageTSX()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.ts",
		code:     []byte(code),
		language: model.TypeScript,
	}

	tags, err := TypeScriptGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "User")
	assert.Contains(t, names, "UserId")
	assert.Contains(t, names, "Role")
	assert.Contains(t, names, "Base")
	assert.Contains(t, names, "Concrete")
	assert.Contains(t, names, "render")
}

func TestTypeScriptGetTags_TSXComponents(t *testing.T) {
	t.Parallel()
	code := `import * as React from "react";

interface Props {
  label: string;
}

function Button(props: Props) {
  return <button>{props.label}</button>;
}

class Panel extends React.Component<Props> {
  render() {
    return <div>{this.props.label}</div>;
  }
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesittertypescript.LanguageTSX()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "Button.tsx",
		code:     []byte(code),
		language: model.TypeScript,
	}

	tags, err := TypeScriptGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Props")
	assert.Contains(t, names, "Button")
	assert.Contains(t, names, "Panel")
	assert.Contains(t, names, "render")
}

func TestTypeScriptGetTags_FilteredFunctions(t *testing.T) {
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
	parser.SetLanguage(treesitter.NewLanguage(treesittertypescript.LanguageTSX()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.ts",
		code:     []byte(code),
		language: model.TypeScript,
	}

	tags, err := TypeScriptGetTags(data)
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

// Kotlin tests

func TestGetContextFromFileKotlin(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "App.kt"),
		[]byte(`class Server {
    fun handleRequest(req: Request) {
        processInput(req.body)
    }
}

fun processInput(data: String): String {
    return data
}
`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "App.kt")
	assert.NoError(t, err)
	assert.Equal(t, model.Kotlin, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handleRequest")
	assert.Contains(t, names, "processInput")
}

func TestKotlinGetTags_Definitions(t *testing.T) {
	t.Parallel()
	code := `class Greeter {
    fun sayHi() {
        greet("world")
    }
}

object Config

fun greet(name: String): String {
    return "hello " + name
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterkotlin.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "App.kt",
		code:     []byte(code),
		language: model.Kotlin,
	}

	tags, err := KotlinGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Greeter")
	assert.Contains(t, names, "Config")
	assert.Contains(t, names, "sayHi")
	assert.Contains(t, names, "greet")
}

func TestKotlinGetTags_FilteredFunctions(t *testing.T) {
	t.Parallel()
	code := `class FooTest {
    fun setUp() {}
    fun tearDown() {}
    fun actualCode() {}
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterkotlin.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "FooTest.kt",
		code:     []byte(code),
		language: model.Kotlin,
	}

	tags, err := KotlinGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.NotContains(t, names, "setUp")
	assert.NotContains(t, names, "tearDown")
	assert.Contains(t, names, "actualCode")
}

// PHP tests

func TestGetContextFromFilePHP(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "app.php"),
		[]byte(`<?php
class Server {
    public function handleRequest($req) {
        processInput($req->body);
    }
}

function processInput($data) {
    return $data;
}
`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "app.php")
	assert.NoError(t, err)
	assert.Equal(t, model.PHP, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handleRequest")
	assert.Contains(t, names, "processInput")
}

func TestPHPGetTags_Definitions(t *testing.T) {
	t.Parallel()
	code := `<?php
class Greeter {
    public function sayHi() {
        greet("world");
    }
}

interface Salutation {
}

trait Friendly {
}

function greet(string $name): string {
    return "hello " . $name;
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterphp.LanguagePHP()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.php",
		code:     []byte(code),
		language: model.PHP,
	}

	tags, err := PHPGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Greeter")
	assert.Contains(t, names, "Salutation")
	assert.Contains(t, names, "Friendly")
	assert.Contains(t, names, "sayHi")
	assert.Contains(t, names, "greet")
}

func TestPHPGetTags_FilteredFunctions(t *testing.T) {
	t.Parallel()
	code := `<?php
class FooTest {
    public function setUp() {}
    public function tearDown() {}
    public function actualCode() {}
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterphp.LanguagePHP()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "FooTest.php",
		code:     []byte(code),
		language: model.PHP,
	}

	tags, err := PHPGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.NotContains(t, names, "setUp")
	assert.NotContains(t, names, "tearDown")
	assert.Contains(t, names, "actualCode")
}

func TestGetContextFromFileRuby(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "server.rb"),
		[]byte(`class Server
  def handle_request(req)
    process_input(req.body)
  end
end

def process_input(data)
  data
end
`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "server.rb")
	assert.NoError(t, err)
	assert.Equal(t, model.Ruby, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handle_request")
	assert.Contains(t, names, "process_input")
}

func TestRubyGetTags_SkipsTestSetupTeardown(t *testing.T) {
	t.Parallel()
	code := `class MyTest
  def setup; end
  def teardown; end
  def test_something; end
end
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterruby.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "my_test.rb",
		code:     []byte(code),
		language: model.Ruby,
	}

	tags, err := RubyGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.NotContains(t, names, "setup")
	assert.NotContains(t, names, "teardown")
	assert.Contains(t, names, "test_something")
}

// Rust tests

func TestGetContextFromFileRust(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "app.rs"),
		[]byte(`struct Server;

impl Server {
    fn handle_request(&self, req: &Request) {
        process_input(&req.body);
    }
}

fn process_input(data: &[u8]) -> &[u8] {
    data
}
`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "app.rs")
	assert.NoError(t, err)
	assert.Equal(t, model.Rust, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handle_request")
	assert.Contains(t, names, "process_input")
}

func TestRustGetTags_Definitions(t *testing.T) {
	t.Parallel()
	code := `struct Greeter;

trait Salutation {
}

impl Greeter {
    fn say_hi(&self) {
        greet("world");
    }
}

fn greet(name: &str) -> String {
    std::process::Command::new(name).spawn().unwrap();
    format!("hello {}", name)
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterrust.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.rs",
		code:     []byte(code),
		language: model.Rust,
	}

	tags, err := RustGetTags(data)
	assert.NoError(t, err)

	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Greeter")
	assert.Contains(t, names, "Salutation")
	assert.Contains(t, names, "say_hi")
	assert.Contains(t, names, "greet")
	assert.Contains(t, names, "new")
}

// Elixir tests

func TestGetContextFromFileElixir(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	err := os.WriteFile(
		filepath.Join(tmpDir, "server.ex"),
		[]byte(`defmodule Server do
  def handle_request(request) do
    process_input(request.body)
  end

  defp process_input(data), do: data
end
`),
		0644,
	)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "server.ex")
	assert.NoError(t, err)
	assert.Equal(t, model.Elixir, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handle_request")
	assert.Contains(t, names, "process_input")
}

func TestElixirGetTags_SkipsTestSetup(t *testing.T) {
	t.Parallel()
	code := `defmodule Example do
  def setup, do: :ok
  def setup_all, do: :ok
  def run, do: helper()
end
`
	parser := treesitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(treesitter.NewLanguage(treesitterelixir.Language()))

	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	data := GetFunctionData{
		root:     tree.RootNode(),
		path:     "example.ex",
		code:     []byte(code),
		language: model.Elixir,
	}

	tags, err := ElixirGetTags(data)
	assert.NoError(t, err)
	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.NotContains(t, names, "setup")
	assert.NotContains(t, names, "setup_all")
	assert.Contains(t, names, "run")
	assert.Contains(t, names, "helper")
}

func TestGetContextFromFileSwift(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "app.swift"), []byte(`class Server {
    func handleRequest(_ req: Request) {
        processInput(req.body)
    }
}

func processInput(_ data: Data) -> Data {
    return data
}
`), 0o644)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "app.swift")
	assert.NoError(t, err)
	assert.Equal(t, model.Swift, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handleRequest")
	assert.Contains(t, names, "processInput")
}

func TestSwiftGetTagsDefinitions(t *testing.T) {
	t.Parallel()
	code := `class Greeter {
    func sayHi() {
        greet(name: "world")
    }
}

protocol Salutation {}

func greet(name: String) -> String {
    return "hello " + name
}
`
	parser := treesitter.NewParser()
	defer parser.Close()
	assert.NoError(t, parser.SetLanguage(treesitter.NewLanguage(treesitterswift.Language())))
	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	tags, err := SwiftGetTags(GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.swift",
		code:     []byte(code),
		language: model.Swift,
	})
	assert.NoError(t, err)
	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Greeter")
	assert.Contains(t, names, "Salutation")
	assert.Contains(t, names, "sayHi")
	assert.Contains(t, names, "greet")
}

func TestDartGetTagsDefinitions(t *testing.T) {
	t.Parallel()
	code := []byte(`class Greeter {
  Greeter.named();
  String greet(String name) => 'hello $name';
}

dynamic main() {
  Greeter().greet('world');
  helper();
  final loaded = loadValue();
  final optional = client?.loadOptional();
  final greeter = Greeter.named();
  return sanitize(loaded);
}
`)
	parser := treesitter.NewParser()
	defer parser.Close()
	assert.NoError(t, parser.SetLanguage(treesitter.NewLanguage(treesitterdart.Language())))
	tree := parser.Parse(code, nil)
	defer tree.Close()

	tags, err := DartGetTags(GetFunctionData{
		root: tree.RootNode(), path: "app.dart", code: code, language: model.Dart,
	})
	assert.NoError(t, err)
	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Greeter")
	assert.Contains(t, names, "greet")
	assert.Contains(t, names, "main")
	assert.Contains(t, names, "helper")
	assert.Contains(t, names, "loadValue")
	assert.Contains(t, names, "loadOptional")
	assert.Contains(t, names, "sanitize")
	assert.Contains(t, names, "named")
	assert.True(t, slices.ContainsFunc(tags, func(tag model.Tag) bool {
		return tag.Name == "named" && tag.Type == model.TagDefinition
	}))
}

func TestGetContextFromFileCpp(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	err := os.WriteFile(filepath.Join(tmpDir, "server.cpp"), []byte(`class Server {
public:
    void handleRequest(const Request& request) {
        processInput(request.body());
    }
};

void processInput(std::string input) {}
`), 0o644)
	assert.NoError(t, err)

	llmContext, err := GetContextFromFile(tmpDir, "server.cpp")
	assert.NoError(t, err)
	assert.Equal(t, model.Cpp, llmContext.Language)

	names := make([]string, len(llmContext.Tags))
	for i, tag := range llmContext.Tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Server")
	assert.Contains(t, names, "handleRequest")
	assert.Contains(t, names, "processInput")
}

func TestCppGetTagsDefinitions(t *testing.T) {
	t.Parallel()
	code := `namespace app {
class Greeter {
public:
    void sayHi() { greet(); }
};

void greet() {}
}`
	parser := treesitter.NewParser()
	defer parser.Close()
	assert.NoError(t, parser.SetLanguage(treesitter.NewLanguage(treesittercpp.Language())))
	tree := parser.Parse([]byte(code), nil)
	defer tree.Close()

	tags, err := CppGetTags(GetFunctionData{
		root:     tree.RootNode(),
		path:     "app.cpp",
		code:     []byte(code),
		language: model.Cpp,
	})
	assert.NoError(t, err)
	names := make([]string, len(tags))
	for i, tag := range tags {
		names[i] = tag.Name
	}
	assert.Contains(t, names, "Greeter")
	assert.Contains(t, names, "sayHi")
	assert.Contains(t, names, "greet")
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
