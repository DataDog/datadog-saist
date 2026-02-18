// Package analysis provides file discovery and metadata generation for the SAIST engine.
// The FileDiscoverer handles scanning directories, filtering files, computing hashes, and
// detecting programming languages for security analysis.
package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/DataDog/datadog-saist/internal/log"
	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/karrick/godirwalk"
)

// FileDiscoverer handles file discovery and metadata generation
type FileDiscoverer struct {
	directory        string
	debug            bool
	respectGitignore bool
}

// NewFileDiscoverer creates a new file discoverer
func NewFileDiscoverer(directory string, debug bool) *FileDiscoverer {
	return &FileDiscoverer{
		directory: directory,
		debug:     debug,
	}
}

// candidate holds minimal info collected during directory walk (no file content)
type candidate struct {
	relPath string
	absPath string
	lang    model.Language
}

// fileDiscoveryWorkers is the number of parallel workers for reading/hashing files.
// Conservative value (16) to limit memory usage and I/O contention.
const fileDiscoveryWorkers = 16

// DiscoverFiles finds all analyzable files in the directory and returns metadata.
// Uses two phases: fast directory walk (no I/O), then parallel file read/hash.
func (fd *FileDiscoverer) DiscoverFiles(ctx context.Context) ([]fileMeta, error) {
	base := filepath.Clean(fd.directory)
	st, err := os.Stat(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("directory %q does not exist", base)
		}
		return nil, fmt.Errorf("stat %q: %w", base, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%q is not a directory", base)
	}

	// Phase 1: Collect candidate paths (no file I/O, just directory walking)
	candidates, err := fd.collectCandidates(ctx, base)
	if err != nil {
		return nil, err
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	// Phase 2: Parallel read + hash with bounded workers
	return fd.processFilesParallel(ctx, candidates)
}

// collectCandidates walks the directory and collects file paths without reading content.
// nolint: gocyclo
func (fd *FileDiscoverer) collectCandidates(ctx context.Context, base string) ([]candidate, error) {
	var matcher gitignore.Matcher
	if fd.respectGitignore {
		var patterns []gitignore.Pattern
		rootIgnore := filepath.Join(base, ".gitignore")
		if data, err := os.ReadFile(rootIgnore); err == nil { // nolint: gosec
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				patterns = append(patterns, gitignore.ParsePattern(line, nil))
			}
		}
		matcher = gitignore.NewMatcher(patterns)
	}

	candidates := make([]candidate, 0)

	err := godirwalk.Walk(base, &godirwalk.Options{
		Unsorted:            true,
		FollowSymbolicLinks: false,
		Callback: func(path string, de *godirwalk.Dirent) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			name := de.Name()
			if de.IsDir() {
				switch name {
				case ".git", "bazel-out", "bazel-bin", "bazel-testlogs", ".cache":
					return filepath.SkipDir
				}
				return nil
			}

			if de.ModeType()&os.ModeSymlink != 0 {
				return nil
			}

			rel, ok := safeRel(base, path)
			if !ok {
				return nil
			}

			if fd.respectGitignore && matcher != nil {
				if matcher.Match(splitPath(rel), false) {
					return nil
				}
			}

			// Skip obviously generated files by name (no I/O needed)
			if strings.HasSuffix(rel, ".pb.go") ||
				strings.HasSuffix(rel, "_pb2.py") ||
				strings.HasSuffix(rel, ".generated.go") {
				return nil
			}

			lang := model.GetLanguage(filepath.ToSlash(rel))
			if lang == model.LanguageUnknown {
				return nil
			}

			if ShouldIgnorePath(path) {
				return nil
			}

			candidates = append(candidates, candidate{
				relPath: rel,
				absPath: path,
				lang:    lang,
			})
			return nil
		},
		ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
			if fd.debug {
				log.FromContext(ctx).Debugf("walk error at %s: %v", path, err)
			}
			return godirwalk.SkipNode
		},
	})

	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, fmt.Errorf("walk %q: %w", base, err)
	}
	return candidates, nil
}

// processFilesParallel reads and hashes files in parallel with bounded concurrency.
func (fd *FileDiscoverer) processFilesParallel(ctx context.Context, candidates []candidate) ([]fileMeta, error) {
	numWorkers := fileDiscoveryWorkers
	if numWorkers > len(candidates) {
		numWorkers = len(candidates)
	}

	work := make(chan candidate, numWorkers)
	results := make(chan fileMeta, numWorkers)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range work {
				if ctx.Err() != nil {
					continue
				}
				if fm, ok := fd.processOneFile(ctx, c); ok {
					results <- fm
				}
			}
		}()
	}

	// Collector goroutine
	var files []fileMeta
	var collectorWg sync.WaitGroup
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		files = make([]fileMeta, 0, len(candidates))
		for fm := range results {
			files = append(files, fm)
		}
	}()

	// Feed work
	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}
		work <- c
	}
	close(work)

	wg.Wait()
	close(results)
	collectorWg.Wait()

	return files, ctx.Err()
}

// processOneFile reads a single file, checks filters, and returns metadata.
func (fd *FileDiscoverer) processOneFile(ctx context.Context, c candidate) (fileMeta, bool) {
	content, err := os.ReadFile(c.absPath)
	if err != nil {
		if fd.debug {
			log.FromContext(ctx).Debugf("read error for %s: %v", c.absPath, err)
		}
		return fileMeta{}, false
	}

	if IsGeneratedFileFromContent(content, c.absPath, c.lang) {
		return fileMeta{}, false
	}
	if IsTestFileFromContent(content, c.absPath, c.lang) {
		return fileMeta{}, false
	}

	h := CalculateFileHashFromBytes(content)

	return fileMeta{
		RelPath:  c.relPath,
		AbsPath:  c.absPath,
		Language: c.lang,
		Hash:     h,
	}, true
}

func safeRel(base, full string) (string, bool) {
	base = filepath.Clean(base)
	full = filepath.Clean(full)
	rel, err := filepath.Rel(base, full)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return rel, true
}

func splitPath(p string) []string {
	parts := []string{}
	for _, part := range strings.Split(p, string(os.PathSeparator)) {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

// CalculateFileHashFromBytes calculates the SHA256 hash from already-loaded content
func CalculateFileHashFromBytes(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}
