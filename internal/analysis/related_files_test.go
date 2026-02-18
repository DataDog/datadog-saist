package analysis

import (
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
