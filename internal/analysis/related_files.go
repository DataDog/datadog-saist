package analysis

import (
	"os"
	"path"
	"sync"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
)

// maxConcurrentFileReads limits parallel file I/O to prevent resource exhaustion
const maxConcurrentFileReads = 10

// Retrieves related files based on tag analysis.
// It reads file contents from the filesystem and returns them as DetectionContextRelatedFile structs.
// Files are read in parallel for better performance.
func getRelatedFiles(detectionContext *model.DetectionContext, logger log.DDSourceLogger) ([]model.DetectionContextRelatedFile, error) {
	// Phase 1: Collect all unique file paths to read (no I/O)
	filesToRead := collectRelatedFilePaths(detectionContext)

	if len(filesToRead) == 0 {
		return []model.DetectionContextRelatedFile{}, nil
	}

	// Phase 2: Read all files in parallel
	return readFilesParallel(detectionContext.RepositoryDirectory, filesToRead, logger)
}

// collectRelatedFilePaths collects all unique related file paths without reading them.
func collectRelatedFilePaths(detectionContext *model.DetectionContext) []string {
	tags := detectionContext.ProjectContext.GetTagsForFile(detectionContext.Path)
	includedFiles := make(map[string]struct{})
	var orderedFiles []string

	// Collect files from definition tags (looking for references)
	for _, tag := range tags {
		if tag.Type != model.TagDefinition {
			continue
		}

		references := detectionContext.ProjectContext.GetFilesForTagsAndType(tag.Name, model.TagReference)
		if len(references) == 0 {
			continue
		}

		orderedRefs := model.RankTagsPerLocality(references, detectionContext.Path)
		fileToInclude := orderedRefs[0].Path

		if fileToInclude == detectionContext.Path {
			continue
		}

		if _, exists := includedFiles[fileToInclude]; exists {
			continue
		}

		includedFiles[fileToInclude] = struct{}{}
		orderedFiles = append(orderedFiles, fileToInclude)
	}

	// Collect files from reference tags (looking for definitions)
	for _, tag := range tags {
		if tag.Type != model.TagReference {
			continue
		}

		definitions := detectionContext.ProjectContext.GetFilesForTagsAndType(tag.Name, model.TagDefinition)
		if len(definitions) == 0 {
			continue
		}

		orderedDefs := model.RankTagsPerLocality(definitions, detectionContext.Path)
		fileToInclude := orderedDefs[0].Path

		if fileToInclude == detectionContext.Path {
			continue
		}

		if _, exists := includedFiles[fileToInclude]; exists {
			continue
		}

		includedFiles[fileToInclude] = struct{}{}
		orderedFiles = append(orderedFiles, fileToInclude)
	}

	return orderedFiles
}

// readFilesParallel reads multiple files concurrently and returns their contents.
// Uses a semaphore to limit concurrent reads and prevent resource exhaustion.
func readFilesParallel(repoDir string, filePaths []string, logger log.DDSourceLogger) ([]model.DetectionContextRelatedFile, error) {
	if len(filePaths) == 0 {
		return []model.DetectionContextRelatedFile{}, nil
	}

	type fileResult struct {
		path    string
		content []byte
		err     error
	}

	resultCh := make(chan fileResult, len(filePaths))
	sem := make(chan struct{}, maxConcurrentFileReads)
	var wg sync.WaitGroup

	// Launch parallel reads with semaphore limiting concurrency
	for _, filePath := range filePaths {
		wg.Add(1)
		go func(fp string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			fullPath := path.Join(repoDir, fp)
			content, err := os.ReadFile(fullPath) // nolint: gosec
			resultCh <- fileResult{path: fp, content: content, err: err}
		}(filePath)
	}

	// Close channel when all reads complete
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results directly (order doesn't need to be preserved for related files)
	relatedFiles := make([]model.DetectionContextRelatedFile, 0, len(filePaths))
	for res := range resultCh {
		if res.err != nil {
			logger.Warnf("Error reading file '%s': %s", res.path, res.err)
			continue
		}
		relatedFiles = append(relatedFiles, model.DetectionContextRelatedFile{
			Path:    res.path,
			Content: string(res.content),
		})
	}

	return relatedFiles, nil
}
