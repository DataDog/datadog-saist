package analysis

import (
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/DataDog/datadog-saist/internal/source"
)

func ShouldIgnorePath(path string) bool { return source.ShouldIgnorePath(path) }

func IsGeneratedFile(path string, language model.Language) (bool, error) {
	return source.IsGeneratedFile(path, language)
}

func IsTestFile(path string, language model.Language) (bool, error) {
	return source.IsTestFile(path, language)
}

func IsGeneratedFileFromContent(content []byte, path string, language model.Language) bool {
	return source.IsGeneratedFileFromContent(content, path, language)
}

func IsTestFileFromContent(content []byte, path string, language model.Language) bool {
	return source.IsTestFileFromContent(content, path, language)
}

func IsTestFileByContent(content []byte, path string, language model.Language) bool {
	return source.IsTestFileByContent(content, path, language)
}

func IsGeneratedFileByContent(content []byte, path string, language model.Language) bool {
	return source.IsGeneratedFileByContent(content, path, language)
}

func IsTestFileByPath(path string, language model.Language) bool {
	return source.IsTestFileByPath(path, language)
}

func IsGeneratedFileByPath(path string) bool { return source.IsGeneratedFileByPath(path) }
