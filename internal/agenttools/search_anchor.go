package agenttools

import (
	"context"
	pathpkg "path"
	"path/filepath"
	"strings"
)

// searchAnchorContextKey is the private key under which a search anchor is stored
// on a context. Using an unexported struct type prevents collisions with keys set
// by other packages.
type searchAnchorContextKey struct{}

// WithSearchAnchor returns a context that biases search_code's default scope,
// used only when a call omits path_glob, toward anchorDir. anchorDir is the
// repository-root-relative directory most relevant to the current investigation,
// typically the directory of the flagged file. When an anchor is present,
// search_code starts at that subtree and widens toward the scan root only when
// nearby scopes are too sparse (see runAdaptiveSearch).
//
// The anchor is stored per call on the context rather than on the sandbox, so the
// same sandbox can serve many candidates concurrently without shared mutable
// state. anchorDir is normalized to a clean, slash-separated, repository-relative
// directory. An empty, absolute, or parent-traversing value clears the anchor so
// search_code keeps its deterministic default scope.
func WithSearchAnchor(ctx context.Context, anchorDir string) context.Context {
	return context.WithValue(ctx, searchAnchorContextKey{}, normalizeSearchAnchor(anchorDir))
}

// normalizeSearchAnchor sanitizes a caller-supplied anchor directory into a
// clean, slash-separated, repository-relative path. It returns "" for any value
// that cannot be trusted as a scope (blank, root, absolute, or containing an
// empty, current-directory, or parent path segment), which callers treat as "no
// anchor".
func normalizeSearchAnchor(anchorDir string) string {
	anchorDir = strings.TrimSpace(filepath.ToSlash(anchorDir))
	if anchorDir == "" || pathpkg.IsAbs(anchorDir) {
		return ""
	}
	anchorDir = pathpkg.Clean(anchorDir)
	if anchorDir == "." || anchorDir == "/" {
		return ""
	}
	for _, segment := range strings.Split(anchorDir, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ""
		}
	}
	return anchorDir
}

// searchAnchorFromContext returns the normalized search anchor carried by ctx, or
// "" when none is set.
func searchAnchorFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	anchor, _ := ctx.Value(searchAnchorContextKey{}).(string)
	return anchor
}
