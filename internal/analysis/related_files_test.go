package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestGetRelatedFiles_WithReferenceAndDefinition(t *testing.T) {

	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Create test files
	definitionFile := "src/utils.go"
	definitionContent := "func UtilFunction() { /* implementation */ }"
	definitionPath := filepath.Join(tmpDir, definitionFile)
	err := os.MkdirAll(filepath.Dir(definitionPath), 0755)
	assert.Nil(t, err)
	err = os.WriteFile(definitionPath, []byte(definitionContent), 0644)
	assert.Nil(t, err)

	// Create detection context
	detectionContext := model.DetectionContext{
		RepositoryDirectory: tmpDir,
		Path:                "main.go",
		ProjectContext: model.AiContextProject{
			Tags: map[string][]model.Tag{
				"UtilFunction": {
					{
						Name: "UtilFunction",
						Path: "main.go",
						Type: model.TagDefinition,
					},
					{
						Name: "UtilFunction",
						Path: definitionFile,
						Type: model.TagReference,
					},
				},
			},
			FileContext: map[string]model.AiContextFile{
				"main.go": {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "UtilFunction",
							Path: "main.go",
							Type: model.TagDefinition,
						},
					},
				},
				definitionFile: {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "UtilFunction",
							Path: definitionFile,
							Type: model.TagReference,
						},
					},
				},
			},
		},
	}

	// Test getRelatedFiles
	relatedFiles, err := getRelatedFiles(&detectionContext, log.NoopLogger())
	assert.Nil(t, err)
	assert.Len(t, relatedFiles, 1)
	assert.Equal(t, definitionFile, relatedFiles[0].Path)
	assert.Equal(t, definitionContent, relatedFiles[0].Content)
}

func TestGetRelatedFiles_DefinitionWithoutReference(t *testing.T) {

	tmpDir := t.TempDir()

	// Create detection context
	detectionContext := model.DetectionContext{
		RepositoryDirectory: tmpDir,
		Path:                "main.go",
		ProjectContext: model.AiContextProject{
			Tags: map[string][]model.Tag{
				"MissingFunction": {
					{
						Name: "MissingFunction",
						Path: "main.go",
						Type: model.TagDefinition,
					},
				},
			},
			FileContext: map[string]model.AiContextFile{
				"main.go": {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "MissingFunction",
							Path: "main.go",
							Type: model.TagDefinition,
						},
					},
				},
			},
		},
	}

	// Test getRelatedFiles
	relatedFiles, err := getRelatedFiles(&detectionContext, log.NoopLogger())
	assert.Nil(t, err)
	assert.Len(t, relatedFiles, 0)
}

func TestGetRelatedFiles_MultipleDefinitionsRankedByLocality(t *testing.T) {

	tmpDir := t.TempDir()

	// Create test files - one closer to the reference file, one farther
	closerFile := "src/helper.go"
	fartherFile := "vendor/external/helper.go"

	closerContent := "func SharedFunction() { /* closer implementation */ }"
	fartherContent := "func SharedFunction() { /* farther implementation */ }"

	// Create directories and files
	closerPath := filepath.Join(tmpDir, closerFile)
	err := os.MkdirAll(filepath.Dir(closerPath), 0755)
	assert.Nil(t, err)
	err = os.WriteFile(closerPath, []byte(closerContent), 0644)
	assert.Nil(t, err)

	fartherPath := filepath.Join(tmpDir, fartherFile)
	err = os.MkdirAll(filepath.Dir(fartherPath), 0755)
	assert.Nil(t, err)
	err = os.WriteFile(fartherPath, []byte(fartherContent), 0644)
	assert.Nil(t, err)

	// Create detection context
	detectionContext := model.DetectionContext{
		RepositoryDirectory: tmpDir,
		Path:                "src/main.go",
		ProjectContext: model.AiContextProject{
			Tags: map[string][]model.Tag{
				"SharedFunction": {
					{
						Name: "SharedFunction",
						Path: "src/main.go",
						Type: model.TagDefinition,
					},
					{
						Name: "SharedFunction",
						Path: closerFile,
						Type: model.TagReference,
					},
					{
						Name: "SharedFunction",
						Path: fartherFile,
						Type: model.TagReference,
					},
				},
			},
			FileContext: map[string]model.AiContextFile{
				"src/main.go": {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "SharedFunction",
							Path: "src/main.go",
							Type: model.TagDefinition,
						},
					},
				},
				closerFile: {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "SharedFunction",
							Path: closerFile,
							Type: model.TagReference,
						},
					},
				},
				fartherFile: {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "SharedFunction",
							Path: fartherFile,
							Type: model.TagDefinition,
						},
					},
				},
			},
		},
	}

	// Test getRelatedFiles - should return the closer file
	relatedFiles, err := getRelatedFiles(&detectionContext, log.NoopLogger())
	assert.Nil(t, err)
	assert.Len(t, relatedFiles, 1)
	assert.Equal(t, closerFile, relatedFiles[0].Path)
	assert.Equal(t, closerContent, relatedFiles[0].Content)
}

func TestGetRelatedFiles_CapsAtMaxRelatedFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Build a project context with more than maxRelatedFiles references
	tags := make(map[string][]model.Tag)
	fileContext := make(map[string]model.AiContextFile)

	fileContext["main.go"] = model.AiContextFile{
		Language: model.Go,
		Tags:     []model.Tag{},
	}
	mainFileTags := make([]model.Tag, 0)

	numFiles := maxRelatedFiles + 5 // More than the cap
	for i := 0; i < numFiles; i++ {
		funcName := fmt.Sprintf("Function%d", i)
		refFile := fmt.Sprintf("src/file%d.go", i)

		// Create the actual file on disk
		refPath := filepath.Join(tmpDir, refFile)
		err := os.MkdirAll(filepath.Dir(refPath), 0755)
		assert.Nil(t, err)
		err = os.WriteFile(refPath, []byte("func "+funcName+"() {}"), 0644)
		assert.Nil(t, err)

		mainFileTags = append(mainFileTags, model.Tag{Name: funcName, Path: "main.go", Type: model.TagDefinition})
		tags[funcName] = []model.Tag{
			{Name: funcName, Path: "main.go", Type: model.TagDefinition},
			{Name: funcName, Path: refFile, Type: model.TagReference},
		}
		fileContext[refFile] = model.AiContextFile{
			Language: model.Go,
			Tags:     []model.Tag{{Name: funcName, Path: refFile, Type: model.TagReference}},
		}
	}
	fileContext["main.go"] = model.AiContextFile{Language: model.Go, Tags: mainFileTags}

	detectionContext := model.DetectionContext{
		RepositoryDirectory: tmpDir,
		Path:                "main.go",
		ProjectContext:      model.AiContextProject{Tags: tags, FileContext: fileContext},
	}

	relatedFiles, err := getRelatedFiles(&detectionContext, log.NoopLogger())
	assert.Nil(t, err)
	assert.LessOrEqual(t, len(relatedFiles), maxRelatedFiles, "should not read more than maxRelatedFiles files")
}

func TestGetRelatedFiles_SkipsOversizedFiles(t *testing.T) {
	tmpDir := t.TempDir()

	oversizedFile := "src/huge.go"
	oversizedPath := filepath.Join(tmpDir, oversizedFile)
	err := os.MkdirAll(filepath.Dir(oversizedPath), 0755)
	assert.Nil(t, err)
	// Write a file larger than maxRelatedFileSize
	err = os.WriteFile(oversizedPath, make([]byte, maxRelatedFileSize+1), 0644)
	assert.Nil(t, err)

	detectionContext := model.DetectionContext{
		RepositoryDirectory: tmpDir,
		Path:                "main.go",
		ProjectContext: model.AiContextProject{
			Tags: map[string][]model.Tag{
				"BigFunction": {
					{Name: "BigFunction", Path: "main.go", Type: model.TagDefinition},
					{Name: "BigFunction", Path: oversizedFile, Type: model.TagReference},
				},
			},
			FileContext: map[string]model.AiContextFile{
				"main.go": {
					Language: model.Go,
					Tags:     []model.Tag{{Name: "BigFunction", Path: "main.go", Type: model.TagDefinition}},
				},
				oversizedFile: {
					Language: model.Go,
					Tags:     []model.Tag{{Name: "BigFunction", Path: oversizedFile, Type: model.TagReference}},
				},
			},
		},
	}

	relatedFiles, err := getRelatedFiles(&detectionContext, log.NoopLogger())
	assert.Nil(t, err)
	assert.Len(t, relatedFiles, 0, "oversized file should be skipped")
}

func TestGetRelatedFiles_FileReadError(t *testing.T) {

	tmpDir := t.TempDir()

	// Create detection context
	detectionContext := model.DetectionContext{
		RepositoryDirectory: tmpDir,
		Path:                "main.go",
		ProjectContext: model.AiContextProject{
			Tags: map[string][]model.Tag{
				"MissingFileFunction": {
					{
						Name: "MissingFileFunction",
						Path: "main.go",
						Type: model.TagReference,
					},
					{
						Name: "MissingFileFunction",
						Path: "nonexistent.go",
						Type: model.TagDefinition,
					},
				},
			},
			FileContext: map[string]model.AiContextFile{
				"main.go": {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "MissingFileFunction",
							Path: "main.go",
							Type: model.TagReference,
						},
					},
				},
				"nonexistent.go": {
					Language: model.Go,
					Tags: []model.Tag{
						{
							Name: "MissingFileFunction",
							Path: "nonexistent.go",
							Type: model.TagDefinition,
						},
					},
				},
			},
		},
	}

	// Test getRelatedFiles - should handle file read error gracefully
	relatedFiles, err := getRelatedFiles(&detectionContext, log.NoopLogger())
	assert.Nil(t, err)
	assert.Len(t, relatedFiles, 0) // Should continue despite file read error
}
