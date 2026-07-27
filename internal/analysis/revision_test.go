package analysis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func createRevisionTestRepository(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	runRevisionTestGit(t, root, "init")
	runRevisionTestGit(t, root, "config", "user.name", "Test")
	runRevisionTestGit(t, root, "config", "user.email", "test@example.com")
	filePath := filepath.Join(root, "source.go")
	assert.NoError(t, os.WriteFile(filePath, []byte("package source\n"), 0o600))
	runRevisionTestGit(t, root, "add", "source.go")
	runRevisionTestGit(t, root, "commit", "-m", "initial source")
	canonicalRoot, err := filepath.EvalSymlinks(root)
	assert.NoError(t, err)
	return canonicalRoot, runRevisionTestGit(t, root, "rev-parse", "HEAD")
}

func runRevisionTestGit(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	commandArguments := append([]string{"-C", root}, arguments...)
	output, err := exec.Command("git", commandArguments...).CombinedOutput()
	assert.NoError(t, err, string(output))
	return strings.TrimSpace(string(output))
}

func TestResolveSourceRevisionReturnsRepositoryMetadata(t *testing.T) {
	root, wantSHA := createRevisionTestRepository(t)
	scanRoot := filepath.Join(root, "nested")
	assert.NoError(t, os.Mkdir(scanRoot, 0o700))

	gotRoot, gotSHA, dirty, relativeScanRoot, err := resolveSourceRevision(context.Background(), scanRoot)

	assert.NoError(t, err)
	assert.Equal(t, root, gotRoot)
	assert.Equal(t, wantSHA, gotSHA)
	assert.False(t, dirty)
	assert.Equal(t, "nested", relativeScanRoot)
}

func TestResolveSourceRevisionDetectsDirtyTrackedFile(t *testing.T) {
	root, _ := createRevisionTestRepository(t)
	assert.NoError(t, os.WriteFile(filepath.Join(root, "source.go"), []byte("package changed\n"), 0o600))

	_, _, dirty, _, err := resolveSourceRevision(context.Background(), root)

	assert.NoError(t, err)
	assert.True(t, dirty)
}

func TestValidateCandidateExportPathRejectsRepositoryPath(t *testing.T) {
	repositoryRoot, _ := createRevisionTestRepository(t)

	err := validateCandidateExportPath(repositoryRoot, filepath.Join(repositoryRoot, "candidates.jsonl"))

	assert.EqualError(t, err, "candidate export path \""+
		filepath.Join(repositoryRoot, "candidates.jsonl")+"\" must be outside the source repository")
}

func TestValidateCandidateExportPathAllowsExternalPath(t *testing.T) {
	repositoryRoot, _ := createRevisionTestRepository(t)
	exportPath := filepath.Join(t.TempDir(), "candidates.jsonl")

	err := validateCandidateExportPath(repositoryRoot, exportPath)

	assert.NoError(t, err)
}

func TestValidateCandidateExportPathRejectsExternalSymlinkIntoRepository(t *testing.T) {
	repositoryRoot, _ := createRevisionTestRepository(t)
	targetPath := filepath.Join(repositoryRoot, "candidates.jsonl")
	assert.NoError(t, os.WriteFile(targetPath, nil, 0o600))
	linkPath := filepath.Join(t.TempDir(), "candidates.jsonl")
	assert.NoError(t, os.Symlink(targetPath, linkPath))

	err := validateCandidateExportPath(repositoryRoot, linkPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be outside the source repository")
}

func TestValidateCandidateExportPathRejectsExternalDanglingSymlinkIntoRepository(t *testing.T) {
	repositoryRoot, _ := createRevisionTestRepository(t)
	targetPath := filepath.Join(repositoryRoot, "future-candidates.jsonl")
	linkPath := filepath.Join(t.TempDir(), "candidates.jsonl")
	assert.NoError(t, os.Symlink(targetPath, linkPath))

	err := validateCandidateExportPath(repositoryRoot, linkPath)

	assert.ErrorContains(t, err, "resolve candidate export path against repository")
	assert.NoFileExists(t, targetPath)
}

func TestValidateCandidateExportPathRejectsInRepositoryDanglingSymlinkToExternalFile(t *testing.T) {
	repositoryRoot, _ := createRevisionTestRepository(t)
	externalTarget := filepath.Join(t.TempDir(), "future-candidates.jsonl")
	linkPath := filepath.Join(repositoryRoot, "candidates.jsonl")
	assert.NoError(t, os.Symlink(externalTarget, linkPath))

	err := validateCandidateExportPath(repositoryRoot, linkPath)

	assert.ErrorContains(t, err, "must be outside the source repository")
	assert.NoFileExists(t, externalTarget)
}
