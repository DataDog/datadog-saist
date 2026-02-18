package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetLanguageJavaFiles(t *testing.T) {
	assert.Equal(t, Java, GetLanguage("Example.java"))
	assert.Equal(t, Java, GetLanguage("src/main/java/Example.java"))
	assert.Equal(t, Java, GetLanguage("Example.JAVA"))
}

func TestGetLanguageGoFiles(t *testing.T) {
	assert.Equal(t, Go, GetLanguage("main.go"))
	assert.Equal(t, Go, GetLanguage("cmd/app/main.go"))
	assert.Equal(t, Go, GetLanguage("main.GO"))
	assert.Equal(t, Go, GetLanguage(".go"))
	assert.Equal(t, Go, GetLanguage("file.test.go"))
}

func TestGetLanguagePythonFiles(t *testing.T) {
	assert.Equal(t, Python, GetLanguage("script.py"))
	assert.Equal(t, Python, GetLanguage("src/utils/script.py"))
	assert.Equal(t, Python, GetLanguage("script.PY"))
}

func TestGetLanguageUnknownFiles(t *testing.T) {
	assert.Equal(t, LanguageUnknown, GetLanguage("README"))
	assert.Equal(t, LanguageUnknown, GetLanguage("document.txt"))
	assert.Equal(t, LanguageUnknown, GetLanguage("program.cpp"))
	assert.Equal(t, LanguageUnknown, GetLanguage(""))
	assert.Equal(t, LanguageUnknown, GetLanguage(".gitignore"))
}

func TestLanguageStringJava(t *testing.T) {
	assert.Equal(t, "Java", Java.String())
}

func TestLanguageStringGo(t *testing.T) {
	assert.Equal(t, "Go", Go.String())
}

func TestLanguageStringPython(t *testing.T) {
	assert.Equal(t, "Python", Python.String())
}

func TestLanguageStringUnknown(t *testing.T) {
	assert.Equal(t, "LanguageUnknown", LanguageUnknown.String())
}
