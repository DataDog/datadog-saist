package agenttools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRunSearchCodeCapsFilesScanned verifies that search_code stops walking
// once it has read maxSearchFilesScanned files, even though none of them
// matched and the result's match limit was never reached. Without this cap, a
// scan root widened to an entire repository (see FindRepoRoot) lets one
// search_code call walk and read an unbounded number of files.
func TestRunSearchCodeCapsFilesScanned(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < maxSearchFilesScanned+1; i++ {
		name := filepath.Join(root, fmt.Sprintf("file%05d.txt", i))
		if err := os.WriteFile(name, []byte("nothing to see here\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	// A blank path_glob is accepted and searches the default scope. With no
	// search priority configured the default is the whole root ("**"), and the
	// file-scan budget still bounds the walk.
	unscoped := runSearchCode(sb, `{"query":"needle-not-present","path_glob":""}`)
	var unscopedResult searchResult
	if err := json.Unmarshal([]byte(unscoped), &unscopedResult); err != nil {
		t.Fatalf("unmarshal unscoped result: %v\noutput: %s", err, unscoped)
	}
	if unscopedResult.Error != "" || !unscopedResult.Incomplete || unscopedResult.StopReason != "file_limit" {
		t.Fatalf("expected a blank path_glob to search the default scope until the file cap, got %+v", unscopedResult)
	}
	if unscopedResult.SearchScope.PathGlob != "**" {
		t.Fatalf("expected default scope glob %q, got %q", "**", unscopedResult.SearchScope.PathGlob)
	}
	if unscopedResult.FilesScanned != maxSearchFilesScanned {
		t.Fatalf("unscoped files_scanned = %d, want %d", unscopedResult.FilesScanned, maxSearchFilesScanned)
	}

	out := runSearchCode(sb, `{"query":"needle-not-present","path_glob":"*.txt"}`)

	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if result.Truncated {
		t.Fatalf("expected no output truncation when there are no matches, got %+v", result)
	}
	if !result.Incomplete || result.StopReason != "file_limit" {
		t.Fatalf("expected incomplete file_limit coverage, got %+v", result)
	}
	if len(result.Matches) != 0 {
		t.Fatalf("expected no matches, got %d", len(result.Matches))
	}
	if result.FilesScanned != maxSearchFilesScanned {
		t.Fatalf("files_scanned = %d, want %d", result.FilesScanned, maxSearchFilesScanned)
	}
}

func TestGlobMatchesRecursiveGlobstar(t *testing.T) {
	pattern := "domains/team/**/*.go"
	assert.True(t, globMatches(pattern, "domains/team/main.go"),
		"globstar should match zero path segments")
	assert.True(t, globMatches(pattern, "domains/team/cmd/main.go"),
		"globstar should match one path segment")
	assert.True(t, globMatches(pattern, "domains/team/apps/api/main.go"),
		"globstar should match many path segments")
	assert.False(t, globMatches(pattern, "domains/other/main.go"),
		"globstar should reject a path outside its prefix")
	assert.False(t, globMatches(pattern, "domains/team/apps/api/main.py"),
		"globstar should reject the wrong extension")
	assert.True(t, globMatches("*.go", "domains/team/apps/api/main.go"),
		"basename-only glob behavior should remain compatible")
}

func TestRunSearchCodeSupportsRecursiveGlobstar(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"domains/team/main.go",
		"domains/team/apps/api/main.go",
		"domains/other/main.go",
	} {
		fullPath := filepath.Join(root, filepath.FromSlash(name))
		assert.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0o700))
		assert.NoError(t, os.WriteFile(fullPath, []byte("recursive-marker\n"), 0o600))
	}
	sb, err := NewSandbox(root)
	if !assert.NoError(t, err) {
		return
	}

	out := runSearchCode(sb, `{"query":"recursive-marker","path_glob":"domains/team/**/*.go"}`)
	var result searchResult
	if !assert.NoError(t, json.Unmarshal([]byte(out), &result)) {
		return
	}
	assert.False(t, result.Incomplete)
	if assert.Len(t, result.Matches, 2) {
		assert.Equal(t, "domains/team/apps/api/main.go", result.Matches[0].Path)
		assert.Equal(t, "domains/team/main.go", result.Matches[1].Path)
	}
}

func TestRunSearchCodeRejectsAbsolutePathGlob(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)

	out := runSearchCode(sb, `{"query":"marker","path_glob":"/domains/team/**/*.go"}`)
	var result searchResult
	assert.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.True(t, result.Incomplete)
	assert.Equal(t, StopReasonInvalidArguments, result.StopReason)
	assert.Contains(t, result.Error, "repository-relative")
	assert.Equal(t, "/domains/team/**/*.go", result.SearchScope.PathGlob)
}

func TestRunSearchCodeRejectsParentTraversingPathGlob(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)

	out := runSearchCode(sb, `{"query":"marker","path_glob":"domains/../**/*.go"}`)
	var result searchResult
	assert.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.True(t, result.Incomplete)
	assert.Equal(t, StopReasonInvalidArguments, result.StopReason)
	assert.Contains(t, result.Error, "parent path segment")
	assert.Equal(t, "domains/../**/*.go", result.SearchScope.PathGlob)
}

func TestRunSearchCodeRejectsEmptyPathGlobSegment(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)

	out := runSearchCode(sb, `{"query":"marker","path_glob":"domains//team/*.go"}`)
	var result searchResult
	assert.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.True(t, result.Incomplete)
	assert.Equal(t, StopReasonInvalidArguments, result.StopReason)
	assert.Contains(t, result.Error, "empty path segment")
	assert.Equal(t, "domains//team/*.go", result.SearchScope.PathGlob)
}

func TestRunSearchCodeRejectsCurrentDirectoryPathGlobSegment(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)

	out := runSearchCode(sb, `{"query":"marker","path_glob":"./domains/team/*.go"}`)
	var result searchResult
	assert.NoError(t, json.Unmarshal([]byte(out), &result))
	assert.True(t, result.Incomplete)
	assert.Equal(t, StopReasonInvalidArguments, result.StopReason)
	assert.Contains(t, result.Error, "current-directory path segment")
	assert.Equal(t, "./domains/team/*.go", result.SearchScope.PathGlob)
}

// TestRunSearchCodeReachesSharedDirBeforeExhaustingBigSiblingBranch verifies
// that search_code's tiered walk (see Sandbox.SearchPriority) reaches a
// repo-root shared directory even when the scan target's own top-level branch
// contains a sibling subtree bigger than the entire file-scan budget. A plain
// lexical walk from root would exhaust the budget inside that sibling
// (domains/aaa_bigsibling sorts before domains/target) and never reach libs/
// at all.
func TestRunSearchCodeReachesSharedDirBeforeExhaustingBigSiblingBranch(t *testing.T) {
	root := t.TempDir()

	bigSibling := filepath.Join(root, "domains", "aaa_bigsibling")
	if err := os.MkdirAll(bigSibling, 0o700); err != nil {
		t.Fatalf("mkdir bigSibling: %v", err)
	}
	for i := 0; i < maxSearchFilesScanned+100; i++ {
		name := filepath.Join(bigSibling, fmt.Sprintf("file%05d.txt", i))
		if err := os.WriteFile(name, []byte("nothing to see here\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	target := filepath.Join(root, "domains", "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "needle.txt"), []byte("findme\n"), 0o600); err != nil {
		t.Fatalf("write needle.txt: %v", err)
	}

	libs := filepath.Join(root, "libs")
	if err := os.MkdirAll(libs, 0o700); err != nil {
		t.Fatalf("mkdir libs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(libs, "shared.txt"), []byte("shared-marker\n"), 0o600); err != nil {
		t.Fatalf("write shared.txt: %v", err)
	}

	sb, err := NewSandboxWithPriority(root, target)
	if err != nil {
		t.Fatalf("NewSandboxWithPriority: %v", err)
	}

	out := runSearchCode(sb, `{"query":"shared-marker","path_glob":"*.txt"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 1 || result.Matches[0].Path != "libs/shared.txt" {
		t.Fatalf("expected to find libs/shared.txt despite the oversized domains/aaa_bigsibling branch, got %+v", result)
	}
}

func TestRunSearchCodeReportsCompleteNoMatch(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "visible.go"), []byte("package visible\n"), 0o600); err != nil {
		t.Fatalf("write visible.go: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runSearchCode(sb, `{"query":"missingSymbol","path_glob":"*.go"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 0 {
		t.Fatalf("expected no matches, got %+v", result.Matches)
	}
	if result.Truncated || result.Incomplete || result.Error != "" {
		t.Fatalf("expected a complete no-match result, got %+v", result)
	}
	if result.FilesScanned != 1 {
		t.Fatalf("files_scanned = %d, want 1", result.FilesScanned)
	}
	if result.SearchScope.Root != "." || result.SearchScope.PathGlob != "*.go" ||
		result.SearchScope.SearchKind != "text" || result.SearchScope.Strategy != "text" {
		t.Fatalf("unexpected search scope %+v", result.SearchScope)
	}
}

func TestRunSearchCodeReportsTruncatedResultsAsIncomplete(t *testing.T) {
	root := t.TempDir()
	content := "needle first\nneedle second\n"
	if err := os.WriteFile(filepath.Join(root, "matches.go"), []byte(content), 0o600); err != nil {
		t.Fatalf("write matches.go: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runSearchCode(sb, `{"query":"needle","path_glob":"*.go","max_results":1}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 1 {
		t.Fatalf("matches = %d, want 1", len(result.Matches))
	}
	if !result.Truncated || !result.Incomplete || result.StopReason != "result_limit" {
		t.Fatalf("expected truncated, incomplete result_limit metadata, got %+v", result)
	}
}

func TestRunSearchCodeDoesNotSearchHiddenPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("hidden-secret\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, ".metadata"), 0o700); err != nil {
		t.Fatalf("mkdir .metadata: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".metadata", "secret.txt"), []byte("hidden-secret\n"), 0o600); err != nil {
		t.Fatalf("write hidden secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("ordinary content\n"), 0o600); err != nil {
		t.Fatalf("write visible.txt: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runSearchCode(sb, `{"query":"hidden-secret","path_glob":"*"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 0 {
		t.Fatalf("hidden content was searchable: %+v", result.Matches)
	}
	if result.FilesScanned != 1 || result.Incomplete {
		t.Fatalf("unexpected coverage metadata %+v", result)
	}
	if !result.SearchScope.HiddenPathsExcluded {
		t.Fatalf("hidden path exclusion missing from search scope %+v", result.SearchScope)
	}
}

func TestRunSearchCodeMakesExcludedDirectoriesExplicit(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "vendor"), 0o700); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "vendor", "dependency.go"), []byte("excluded-needle\n"), 0o600); err != nil {
		t.Fatalf("write dependency: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runSearchCode(sb, `{"query":"excluded-needle","path_glob":"*.go"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 0 || result.Incomplete {
		t.Fatalf("unexpected excluded-directory result %+v", result)
	}
	if !containsString(result.SearchScope.ExcludedDirectories, "vendor") {
		t.Fatalf("vendor exclusion missing from scope %+v", result.SearchScope)
	}
}

func TestRunSearchCodeMakesTextSymlinkExclusionExplicit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "target.go"), []byte("symlink-needle\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "target.go"), filepath.Join(root, "linked.go")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runSearchCode(sb, `{"query":"symlink-needle","path_glob":"linked.go"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 0 || result.Incomplete {
		t.Fatalf("unexpected symlink search result %+v", result)
	}
	if !result.SearchScope.TextSymlinksExcluded {
		t.Fatalf("text symlink exclusion missing from scope %+v", result.SearchScope)
	}

	readOut := runReadFile(sb, `{"path":"linked.go"}`)
	if !strings.Contains(readOut, "symlink-needle") {
		t.Fatalf("contained symlink was not readable through validated descriptor %s", readOut)
	}
}

func TestRunSearchCodeMakesBinaryExclusionExplicit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "binary.dat"), []byte("binary-needle\x00tail"), 0o600); err != nil {
		t.Fatalf("write binary: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runSearchCode(sb, `{"query":"binary-needle","path_glob":"*"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 0 || result.Incomplete || result.FilesScanned != 0 {
		t.Fatalf("unexpected binary search result %+v", result)
	}
	if !result.SearchScope.BinaryFilesExcluded {
		t.Fatalf("binary exclusion missing from scope %+v", result.SearchScope)
	}
}

type recordingSymbolIndex struct {
	paths      []string
	lastSymbol string
	lastKind   SymbolSearchKind
}

func (index *recordingSymbolIndex) LookupSymbol(symbol string, kind SymbolSearchKind) []string {
	index.lastSymbol = symbol
	index.lastKind = kind
	return append([]string(nil), index.paths...)
}

func TestRunSearchCodePrefersSymbolIndex(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "definition.go"), []byte("func helper() {}\n"), 0o600); err != nil {
		t.Fatalf("write definition.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "unrelated.go"), []byte("helper()\n"), 0o600); err != nil {
		t.Fatalf("write unrelated.go: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	index := &recordingSymbolIndex{paths: []string{"definition.go"}}
	sb.SetSymbolIndex(index)

	out := runSearchCode(sb, `{"query":"helper","path_glob":"*.go","search_kind":"definition"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if index.lastSymbol != "helper" || index.lastKind != SymbolSearchDefinition {
		t.Fatalf("unexpected index lookup symbol=%q kind=%q", index.lastSymbol, index.lastKind)
	}
	if len(result.Matches) != 1 || result.Matches[0].Path != "definition.go" {
		t.Fatalf("unexpected indexed matches %+v", result.Matches)
	}
	if result.FilesScanned != 1 || result.SearchScope.Strategy != "symbol_index" {
		t.Fatalf("unexpected indexed search metadata %+v", result)
	}
}

func TestRunSearchCodeFallsBackWhenSymbolIndexHasNoMatch(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fallback.go"), []byte("helper()\n"), 0o600); err != nil {
		t.Fatalf("write fallback.go: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	sb.SetSymbolIndex(&recordingSymbolIndex{})

	out := runSearchCode(sb, `{"query":"helper","path_glob":"*.go","search_kind":"reference"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 1 || result.Matches[0].Path != "fallback.go" {
		t.Fatalf("unexpected fallback matches %+v", result.Matches)
	}
	if result.SearchScope.Strategy != "text_fallback" {
		t.Fatalf("strategy = %q, want text_fallback", result.SearchScope.Strategy)
	}
}

func TestRunSearchCodeFallsBackWhenIndexedPathIsStale(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "fallback.go"), []byte("helper()\n"), 0o600); err != nil {
		t.Fatalf("write fallback.go: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	sb.SetSymbolIndex(&recordingSymbolIndex{paths: []string{"deleted.go"}})

	out := runSearchCode(sb, `{"query":"helper","path_glob":"*.go","search_kind":"reference"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Matches) != 1 || result.Matches[0].Path != "fallback.go" {
		t.Fatalf("unexpected fallback matches %+v", result.Matches)
	}
	if result.SearchScope.Strategy != "text_fallback" || result.Incomplete {
		t.Fatalf("unexpected stale-index fallback metadata %+v", result)
	}
}

func TestRunListDirectoryHidesMetadata(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible.go"), []byte("package visible\n"), 0o600); err != nil {
		t.Fatalf("write visible.go: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runListDirectory(sb, `{}`)
	var result listResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Entries) != 1 || result.Entries[0].Name != "visible.go" {
		t.Fatalf("hidden metadata was listed: %+v", result.Entries)
	}
}

func TestRunReadFileRejectsHiddenMetadata(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("hidden-secret\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runReadFile(sb, `{"path":".env"}`)
	if strings.Contains(out, "hidden-secret") {
		t.Fatalf("hidden content leaked in output %s", out)
	}
	metadata := InspectResult(out)
	if metadata.Error == "" {
		t.Fatalf("expected hidden path error, got %s", out)
	}
}

func TestRunReadFileRejectsOversizedInput(t *testing.T) {
	root := t.TempDir()
	content := strings.Repeat("x", maxReadFileInputBytes+1)
	if err := os.WriteFile(filepath.Join(root, "oversized.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("write oversized file: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runReadFile(sb, `{"path":"oversized.txt"}`)
	metadata := InspectResult(out)
	if metadata.Error == "" || !strings.Contains(metadata.Error, "read limit") {
		t.Fatalf("expected oversized input error, got %s", out)
	}
	if strings.Contains(out, content[:100]) {
		t.Fatalf("oversized content leaked in output")
	}
}

func TestRunListDirectoryCapsCallerLimit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < maxListEntries+1; i++ {
		name := filepath.Join(root, fmt.Sprintf("entry%04d", i))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runListDirectory(sb, `{"max_entries":1000000}`)
	var result listResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Entries) != maxListEntries || !result.Truncated || !result.Incomplete ||
		result.StopReason != "result_limit" {
		t.Fatalf("unexpected bounded directory result %+v", result)
	}
	if result.EntriesScanned > maxListEntries+1 {
		t.Fatalf("entries_scanned = %d, want at most %d", result.EntriesScanned, maxListEntries+1)
	}
}

func TestRunListDirectoryCapsHiddenEntryWork(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < maxListEntriesScanned+1; i++ {
		name := filepath.Join(root, fmt.Sprintf(".hidden%05d", i))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runListDirectory(sb, `{}`)
	var result listResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if len(result.Entries) != 0 || result.EntriesScanned != maxListEntriesScanned ||
		!result.Incomplete || result.StopReason != "entry_limit" {
		t.Fatalf("unexpected hidden-entry bound %+v", result)
	}
}

func TestRunSearchCodeOmittedPathGlobSearchesDefaultScope(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("default-scope-marker\n"), 0o600); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	// No path_glob key at all: the omission is accepted and searches the default
	// scope (the whole root, reported as "**") rather than being rejected.
	out := runSearchCode(sb, `{"query":"default-scope-marker"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if result.Error != "" || result.Incomplete {
		t.Fatalf("expected an omitted path_glob to be accepted, got %+v", result)
	}
	if len(result.Matches) != 1 || result.Matches[0].Path != "main.go" {
		t.Fatalf("expected the default scope to find main.go, got %+v", result.Matches)
	}
	if result.SearchScope.PathGlob != "**" {
		t.Fatalf("expected default scope glob %q, got %q", "**", result.SearchScope.PathGlob)
	}
}

func TestRunSearchCodeOmittedPathGlobScopesToSearchPriority(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "domains", "target")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatalf("mkdir inside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inside, "inside.go"), []byte("priority-marker\n"), 0o600); err != nil {
		t.Fatalf("write inside.go: %v", err)
	}
	outside := filepath.Join(root, "libs")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "outside.go"), []byte("priority-marker\n"), 0o600); err != nil {
		t.Fatalf("write outside.go: %v", err)
	}
	sb, err := NewSandboxWithPriority(root, inside)
	if err != nil {
		t.Fatalf("NewSandboxWithPriority: %v", err)
	}

	// An omitted path_glob defaults to the configured search-priority subtree, so
	// only the file inside it matches even though an identical marker sits outside.
	out := runSearchCode(sb, `{"query":"priority-marker"}`)
	var result searchResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if result.Error != "" || result.Incomplete {
		t.Fatalf("expected the default priority scope to complete, got %+v", result)
	}
	if len(result.Matches) != 1 || result.Matches[0].Path != "domains/target/inside.go" {
		t.Fatalf("expected only the in-priority match, got %+v", result.Matches)
	}
	if result.SearchScope.PathGlob != "domains/target/**" {
		t.Fatalf("expected priority default glob %q, got %q", "domains/target/**", result.SearchScope.PathGlob)
	}
}

func TestRunReadFileReturnsUpTo64KiB(t *testing.T) {
	root := t.TempDir()
	// 300 lines of 400 characters each stays under the 400-line cap but is far
	// larger than 64 KiB, so the byte cap is the sole truncation cause. This
	// proves a single read now returns up to 64 KiB of output rather than the old
	// 16 KiB cap.
	content := strings.Repeat(strings.Repeat("x", 400)+"\n", 300)
	if err := os.WriteFile(filepath.Join(root, "big.txt"), []byte(content), 0o600); err != nil {
		t.Fatalf("write big.txt: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}

	out := runReadFile(sb, `{"path":"big.txt"}`)
	var result readFileResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("unmarshal result: %v\noutput: %s", err, out)
	}
	if !result.Truncated {
		t.Fatalf("expected the 64 KiB output cap to report truncation, got %+v", result)
	}
	if len(result.Content) <= 16*1024 {
		t.Fatalf("expected more than the old 16 KiB cap, got %d bytes", len(result.Content))
	}
	if len(result.Content) > 64*1024 {
		t.Fatalf("expected at most the 64 KiB cap, got %d bytes", len(result.Content))
	}
	// The byte cap, not the 400-line cap, bounded this read.
	if result.EndLine >= 400 {
		t.Fatalf("expected the byte cap to bound the read before the line cap, got end_line %d", result.EndLine)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
