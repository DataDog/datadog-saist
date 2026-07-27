package agenttools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeSearchTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o600))
	}
}

func TestNormalizeSearchAnchor(t *testing.T) {
	assert.Equal(t, "a/b", normalizeSearchAnchor("a/b"))
	assert.Equal(t, "a/b", normalizeSearchAnchor("a/b/"))
	assert.Equal(t, "a/b", normalizeSearchAnchor("./a/b"))
	assert.Equal(t, "", normalizeSearchAnchor(""))
	assert.Equal(t, "", normalizeSearchAnchor("   "))
	assert.Equal(t, "", normalizeSearchAnchor("."))
	assert.Equal(t, "", normalizeSearchAnchor("/abs/path"))
	assert.Equal(t, "", normalizeSearchAnchor("../escape"))
	assert.Equal(t, "", normalizeSearchAnchor("a/../../escape"))
}

func TestSearchAnchorContextRoundTrip(t *testing.T) {
	assert.Equal(t, "", searchAnchorFromContext(context.Background()))

	ctx := WithSearchAnchor(context.Background(), "a/b")
	assert.Equal(t, "a/b", searchAnchorFromContext(ctx))

	// An untrusted anchor is cleared rather than trusted as a scope.
	ctx = WithSearchAnchor(context.Background(), "/abs")
	assert.Equal(t, "", searchAnchorFromContext(ctx))
}

func TestAdaptiveSearchGlobs(t *testing.T) {
	assert.Equal(t, []string{"a/b/c/**", "a/b/**", "a/**", "**"}, adaptiveSearchGlobs("a/b/c"))
	assert.Equal(t, []string{"a/**", "**"}, adaptiveSearchGlobs("a"))

	// Deep paths are capped at adaptiveSearchMaxLocalScopes local scopes and then
	// jump straight to the whole root, so no ancestor level is re-walked endlessly.
	assert.Equal(t, []string{"a/b/c/d/e/**", "a/b/c/d/**", "a/b/c/**", "**"},
		adaptiveSearchGlobs("a/b/c/d/e"))
}

func TestGlobFixedPrefixDir(t *testing.T) {
	cases := map[string]string{
		"a/b/c/**":             "a/b/c",
		"a/b/**/*.go":          "a/b",
		"domains/team/**/*.go": "domains/team",
		"a/*.go":               "a",
		"a/b/c.go":             "a/b",
		"**":                   "",
		"*.go":                 "",
		"foo":                  "",
	}
	for pattern, want := range cases {
		assert.Equal(t, want, globFixedPrefixDir(pattern), "pattern %q", pattern)
	}
}

// TestSearchCodeAdaptivePrefersLocalScope verifies that when the anchored subtree
// already holds enough matches, the search stops there and never widens.
func TestSearchCodeAdaptivePrefersLocalScope(t *testing.T) {
	root := t.TempDir()
	writeSearchTree(t, root, map[string]string{
		"a/b/c/one.go":   "marker\n",
		"a/b/c/two.go":   "marker\n",
		"a/b/c/three.go": "marker\n", // adaptiveSearchMinMatches (3) local matches
		"a/b/other.go":   "marker\n",
		"z/top.go":       "marker\n",
	})
	sb, err := NewSandbox(root)
	require.NoError(t, err)

	ctx := WithSearchAnchor(context.Background(), "a/b/c")
	out := runSearchCodeContext(ctx, sb, `{"query":"marker"}`)
	var result searchResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))

	assert.Equal(t, "a/b/c/**", result.SearchScope.PathGlob)
	assert.Len(t, result.Matches, 3)
	for _, m := range result.Matches {
		assert.True(t, strings.HasPrefix(m.Path, "a/b/c/"), "unexpected out-of-scope match %s", m.Path)
	}
}

// TestSearchCodeAdaptiveWidensWhenLocalScopeSparse verifies that a below-threshold
// anchored subtree widens to the next ancestor that reaches the threshold.
func TestSearchCodeAdaptiveWidensWhenLocalScopeSparse(t *testing.T) {
	root := t.TempDir()
	writeSearchTree(t, root, map[string]string{
		"a/b/c/only.go":  "marker\n", // one local match, below threshold
		"a/b/d/two.go":   "marker\n",
		"a/b/d/three.go": "marker\n", // a/b/** now holds three matches
		"z/top.go":       "marker\n",
	})
	sb, err := NewSandbox(root)
	require.NoError(t, err)

	ctx := WithSearchAnchor(context.Background(), "a/b/c")
	out := runSearchCodeContext(ctx, sb, `{"query":"marker"}`)
	var result searchResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))

	assert.Equal(t, "a/b/**", result.SearchScope.PathGlob)
	assert.Len(t, result.Matches, 3)
}

// TestSearchCodeAdaptiveReachesRootWhenNeeded verifies that a query whose only
// matches live outside the anchor subtree widens all the way to the scan root.
func TestSearchCodeAdaptiveReachesRootWhenNeeded(t *testing.T) {
	root := t.TempDir()
	writeSearchTree(t, root, map[string]string{
		"a/b/c/flagged.go": "nothing here\n",
		"z/one.go":         "marker\n",
		"z/two.go":         "marker\n",
		"z/three.go":       "marker\n",
	})
	sb, err := NewSandbox(root)
	require.NoError(t, err)

	ctx := WithSearchAnchor(context.Background(), "a/b/c")
	out := runSearchCodeContext(ctx, sb, `{"query":"marker"}`)
	var result searchResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))

	assert.Equal(t, "**", result.SearchScope.PathGlob)
	assert.Len(t, result.Matches, 3)
}

// TestSearchCodeAdaptiveReturnsWidestWhenThresholdUnmet verifies that when no
// scope reaches the threshold, the widest (whole-root) result is returned so no
// coverage is lost.
func TestSearchCodeAdaptiveReturnsWidestWhenThresholdUnmet(t *testing.T) {
	root := t.TempDir()
	writeSearchTree(t, root, map[string]string{
		"a/b/c/flagged.go": "nothing here\n",
		"z/one.go":         "marker\n",
		"z/two.go":         "marker\n", // two total matches, below threshold
	})
	sb, err := NewSandbox(root)
	require.NoError(t, err)

	ctx := WithSearchAnchor(context.Background(), "a/b/c")
	out := runSearchCodeContext(ctx, sb, `{"query":"marker"}`)
	var result searchResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))

	assert.Equal(t, "**", result.SearchScope.PathGlob)
	assert.Len(t, result.Matches, 2)
}

// TestSearchCodeWithoutAnchorKeepsDefaultScope verifies that omitting path_glob
// without a context anchor still searches the deterministic default scope.
func TestSearchCodeWithoutAnchorKeepsDefaultScope(t *testing.T) {
	root := t.TempDir()
	writeSearchTree(t, root, map[string]string{
		"a/b/c/one.go": "marker\n",
		"z/top.go":     "marker\n",
	})
	sb, err := NewSandbox(root)
	require.NoError(t, err)

	out := runSearchCodeContext(context.Background(), sb, `{"query":"marker"}`)
	var result searchResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))

	assert.Equal(t, "**", result.SearchScope.PathGlob)
	assert.Len(t, result.Matches, 2)
}

// TestSearchCodeExplicitGlobIgnoresAnchor verifies that a caller-supplied
// path_glob is honored exactly, even when the context carries an anchor.
func TestSearchCodeExplicitGlobIgnoresAnchor(t *testing.T) {
	root := t.TempDir()
	writeSearchTree(t, root, map[string]string{
		"a/b/c/one.go": "marker\n",
		"z/one.go":     "marker\n",
		"z/two.go":     "marker\n",
	})
	sb, err := NewSandbox(root)
	require.NoError(t, err)

	ctx := WithSearchAnchor(context.Background(), "a/b/c")
	out := runSearchCodeContext(ctx, sb, `{"query":"marker","path_glob":"z/**"}`)
	var result searchResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))

	assert.Equal(t, "z/**", result.SearchScope.PathGlob)
	assert.Len(t, result.Matches, 2)
	for _, m := range result.Matches {
		assert.True(t, strings.HasPrefix(m.Path, "z/"), "unexpected out-of-scope match %s", m.Path)
	}
}

// TestSearchCodeScopedGlobWalksOnlyPrefixSubtree verifies that a multi-segment
// glob returns exactly the files under its fixed prefix, including nested ones,
// and excludes same-named files elsewhere. This exercises the fixed-prefix walk.
func TestSearchCodeScopedGlobWalksOnlyPrefixSubtree(t *testing.T) {
	root := t.TempDir()
	writeSearchTree(t, root, map[string]string{
		"a/b/keep.go":   "marker\n",
		"a/b/x/keep.go": "marker\n",
		"z/keep.go":     "marker\n", // same base name, outside the prefix
	})
	sb, err := NewSandbox(root)
	require.NoError(t, err)

	out := runSearchCode(sb, `{"query":"marker","path_glob":"a/b/**"}`)
	var result searchResult
	require.NoError(t, json.Unmarshal([]byte(out), &result))

	assert.Len(t, result.Matches, 2)
	for _, m := range result.Matches {
		assert.True(t, strings.HasPrefix(m.Path, "a/b/"), "unexpected out-of-scope match %s", m.Path)
	}
}
