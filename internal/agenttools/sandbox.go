// Package agenttools provides read-only, sandboxed tools that an AI detection or
// verification agent can call to resolve cross-file context during a scan. All
// file access is constrained to the scan root by Sandbox.
//
// This package deliberately does NOT import internal/analysis (whose file
// discoverer holds the canonical exclusion logic) because internal/analysis
// imports internal/agents, which imports this package. Importing analysis here
// would create a cycle. Instead it carries a small self-contained exclusion
// skip-list that mirrors the spirit of the scanner's exclusions.
package agenttools

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Sandbox constrains all tool file access to a single scan root. The root is
// stored as an absolute, symlink-evaluated path so containment checks compare
// canonical paths.
type Sandbox struct {
	root string
	// searchPriority is the subtree search_code walks before the rest of root.
	// It equals root when no separate priority was set.
	searchPriority string

	symbolIndexMu sync.RWMutex
	symbolIndex   SymbolIndex
}

// NewSandbox builds a sandbox rooted at the given directory. The root is made
// absolute and has its symlinks evaluated up front so later containment checks
// compare canonical paths.
func NewSandbox(root string) (*Sandbox, error) {
	abs, err := canonicalDir(root, "scan root")
	if err != nil {
		return nil, err
	}
	return &Sandbox{root: abs, searchPriority: abs}, nil
}

// NewSandboxWithPriority builds a sandbox rooted at root, but has search_code
// walk priority before the rest of root. priority is typically the original,
// narrower scan target a caller widened from via FindRepoRoot. Without
// prioritizing it, search_code's file-scan budget (maxSearchFilesScanned) can
// be exhausted entirely inside one large sibling of priority (for example a
// monorepo's domains/) before ever reaching a directory that sits next to it
// at the repo root (for example libs/), since filepath.WalkDir visits entries
// in lexical order regardless of which one actually matters for a given scan.
// priority must be root itself or a descendant of it.
func NewSandboxWithPriority(root, priority string) (*Sandbox, error) {
	abs, err := canonicalDir(root, "scan root")
	if err != nil {
		return nil, err
	}
	priorityAbs, err := canonicalDir(priority, "scan priority")
	if err != nil {
		return nil, err
	}
	if priorityAbs != abs && !strings.HasPrefix(priorityAbs, abs+string(filepath.Separator)) {
		return nil, fmt.Errorf("scan priority %q is not %q or a descendant of it", priority, root)
	}
	priorityRel, err := filepath.Rel(abs, priorityAbs)
	if err != nil {
		return nil, fmt.Errorf("resolve scan priority relative to root: %w", err)
	}
	if hasHiddenPathSegment(priorityRel) {
		return nil, fmt.Errorf("scan priority %q contains a hidden path segment", priority)
	}
	return &Sandbox{root: abs, searchPriority: priorityAbs}, nil
}

// canonicalDir resolves dir to an absolute, symlink-evaluated path and
// confirms it names an existing directory. label identifies dir in error
// messages (e.g. "scan root").
func canonicalDir(dir, label string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", label, err)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	abs = filepath.Clean(abs)
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat %s %q: %w", label, abs, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s %q is not a directory", label, abs)
	}
	return abs, nil
}

// Root returns the absolute, canonical scan root.
func (s *Sandbox) Root() string { return s.root }

// SearchPriority returns the subtree search_code walks before the rest of
// Root. It equals Root when no separate priority was set (see NewSandbox vs
// NewSandboxWithPriority).
func (s *Sandbox) SearchPriority() string { return s.searchPriority }

// SetSymbolIndex installs an optional repository symbol index used by
// definition and reference searches. Passing nil restores text-only search.
func (s *Sandbox) SetSymbolIndex(index SymbolIndex) {
	s.symbolIndexMu.Lock()
	defer s.symbolIndexMu.Unlock()
	s.symbolIndex = index
}

func (s *Sandbox) getSymbolIndex() SymbolIndex {
	s.symbolIndexMu.RLock()
	defer s.symbolIndexMu.RUnlock()
	return s.symbolIndex
}

// repoRootMarkers are files or directories whose presence identifies the top
// of a repository checkout. They are checked in the order listed at each
// directory level while walking up from a scan directory.
var repoRootMarkers = []string{".git", "WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel", "go.work"}

// FindRepoRoot walks up from start looking for a repo root marker so agentic
// tools can resolve cross-file context (e.g. a shared internal library) that
// lives outside the narrower directory a single scan targets. A scan root
// scoped to one subdirectory of a monorepo is a scope limit, not a security
// boundary. The process already has full read access to the checkout, so
// widening to the enclosing repository does not cross any privilege line.
//
// It returns the first ancestor directory containing a marker, or the
// canonicalized start directory if no marker is found before reaching the
// filesystem root (for example a shallow tarball extraction with no VCS
// metadata), so callers can sandbox exactly as before. If start itself cannot
// be resolved to an absolute path, start is returned as-is.
func FindRepoRoot(start string) string {
	abs, err := filepath.Abs(start)
	if err != nil {
		return start
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	canonicalStart := filepath.Clean(abs)
	cur := canonicalStart
	for {
		for _, marker := range repoRootMarkers {
			if _, err := os.Stat(filepath.Join(cur, marker)); err == nil {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return canonicalStart
		}
		cur = parent
	}
}

// Resolve maps a repository-relative path to an absolute path inside the scan
// root. It rejects absolute inputs and any path that escapes the root, whether
// via ".." segments or symlinks pointing outside the root. An empty path
// resolves to the root itself. The returned path is the symlink-resolved
// (canonical) path that was containment-checked, so callers read exactly what
// was validated rather than re-traversing symlinks at read time.
func (s *Sandbox) Resolve(rel string) (string, error) {
	if rel == "" {
		return s.root, nil
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("path %q must be relative to the scan root", rel)
	}
	if hasHiddenPathSegment(rel) {
		return "", fmt.Errorf("path %q contains a hidden path segment", rel)
	}
	// Clean the path as if rooted at the separator, which collapses any leading
	// ".." so it can never climb above the scan root, then join under the root.
	cleaned := filepath.Clean(string(filepath.Separator) + filepath.FromSlash(rel))
	abs := filepath.Join(s.root, cleaned)

	// Defend against symlink escapes by evaluating the longest existing prefix.
	real, err := resolveExistingPrefix(abs)
	if err != nil {
		return "", err
	}
	if real != s.root && !strings.HasPrefix(real, s.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the scan root", rel)
	}
	realRel, err := filepath.Rel(s.root, real)
	if err != nil {
		return "", fmt.Errorf("resolve path %q relative to scan root: %w", rel, err)
	}
	if hasHiddenPathSegment(realRel) {
		return "", fmt.Errorf("path %q resolves through a hidden path segment", rel)
	}
	return real, nil
}

// Open resolves and opens a repository-relative path, then validates the
// already opened descriptor's actual target. Callers must read from the
// returned descriptor instead of reopening its pathname. This closes the
// check-then-open race where a contained path is replaced by an escaping
// symlink after Resolve returns.
func (s *Sandbox) Open(rel string) (*os.File, string, error) {
	resolved, err := s.Resolve(rel)
	if err != nil {
		return nil, "", err
	}

	file, err := os.Open(resolved) // nolint:gosec // resolved is sandbox-contained and the descriptor is revalidated below
	if err != nil {
		return nil, "", err
	}

	openedPath, err := openedFilePath(file)
	if err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("validate opened path %q: %w", rel, err)
	}
	openedPath = filepath.Clean(openedPath)
	if openedPath != s.root && !strings.HasPrefix(openedPath, s.root+string(filepath.Separator)) {
		_ = file.Close()
		return nil, "", fmt.Errorf("path %q opened outside the scan root", rel)
	}
	openedRel, err := filepath.Rel(s.root, openedPath)
	if err != nil {
		_ = file.Close()
		return nil, "", fmt.Errorf("resolve opened path %q relative to scan root: %w", rel, err)
	}
	if hasHiddenPathSegment(openedRel) {
		_ = file.Close()
		return nil, "", fmt.Errorf("path %q opened through a hidden path segment", rel)
	}
	return file, filepath.ToSlash(openedRel), nil
}

// hasHiddenPathSegment reports whether a repository-relative path contains a
// dot-prefixed file or directory. The navigation segments "." and ".." are
// handled separately by normalization and containment checks.
func hasHiddenPathSegment(path string) bool {
	for _, segment := range strings.FieldsFunc(filepath.ToSlash(path), func(r rune) bool {
		return r == '/'
	}) {
		if strings.HasPrefix(segment, ".") && segment != "." && segment != ".." {
			return true
		}
	}
	return false
}

func isHiddenName(name string) bool {
	return strings.HasPrefix(name, ".") && name != "." && name != ".."
}

// resolveExistingPrefix evaluates symlinks on the longest existing ancestor of p
// and re-appends the non-existent remainder. This lets containment be checked
// even for paths that do not exist yet (such as a read of a missing file).
func resolveExistingPrefix(p string) (string, error) {
	p = filepath.Clean(p)
	remainder := ""
	cur := p
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			if remainder == "" {
				return real, nil
			}
			return filepath.Join(real, remainder), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Reached the filesystem root without finding an existing prefix.
			return p, nil
		}
		remainder = filepath.Join(filepath.Base(cur), remainder)
		cur = parent
	}
}

// excludedDirs are directory names the tools never descend into. This mirrors
// the spirit of the scanner's file-discovery exclusions without importing the
// analysis package (which would create an import cycle).
var excludedDirs = map[string]bool{
	".git":           true,
	".hg":            true,
	".svn":           true,
	".cache":         true,
	".idea":          true,
	".vscode":        true,
	"node_modules":   true,
	"vendor":         true,
	"bazel-out":      true,
	"bazel-bin":      true,
	"bazel-testlogs": true,
	"dist":           true,
	"build":          true,
	"target":         true,
	"__pycache__":    true,
	".venv":          true,
	"venv":           true,
}

// isExcludedDir reports whether a directory of the given base name should be
// skipped by the tools.
func isExcludedDir(name string) bool {
	return excludedDirs[name]
}

// looksBinary reports whether a content chunk appears to be binary (contains a
// NUL byte) so the tools skip non-text files.
func looksBinary(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}
