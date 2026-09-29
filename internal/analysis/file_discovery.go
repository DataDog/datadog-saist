package analysis

import "github.com/DataDog/datadog-saist/internal/source"

type fileMeta = source.File
type FileDiscoverer = source.FileDiscoverer

func NewFileDiscoverer(directory string, debug bool) *FileDiscoverer {
	return source.NewFileDiscoverer(directory, debug)
}

func CalculateFileHashFromBytes(content []byte) string {
	return source.CalculateFileHashFromBytes(content)
}
