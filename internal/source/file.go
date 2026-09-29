package source

import "github.com/DataDog/datadog-saist/internal/model"

type File struct {
	RelPath  string
	AbsPath  string
	Language model.Language
	Hash     string
}
