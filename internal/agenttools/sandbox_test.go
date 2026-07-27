package agenttools

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestSandbox builds a sandbox over a fresh temp dir containing a file and a
// subdirectory, and returns the sandbox plus its canonical root.
func newTestSandbox(t *testing.T) (*Sandbox, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "inside.txt"), []byte("hello\nworld\n"), 0o600); err != nil {
		t.Fatalf("write inside.txt: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	sb, err := NewSandbox(root)
	if err != nil {
		t.Fatalf("NewSandbox: %v", err)
	}
	return sb, sb.Root()
}

func TestResolveAllowsPathsInsideRoot(t *testing.T) {
	sb, root := newTestSandbox(t)

	cases := map[string]string{
		"file at root":     "inside.txt",
		"subdirectory":     "sub",
		"empty is root":    "",
		"dot is root":      ".",
		"normalized climb": "sub/../inside.txt", // stays inside
	}
	for name, rel := range cases {
		t.Run(name, func(t *testing.T) {
			abs, err := sb.Resolve(rel)
			if err != nil {
				t.Fatalf("Resolve(%q) returned error: %v", rel, err)
			}
			if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
				t.Fatalf("Resolve(%q) = %q, want inside root %q", rel, abs, root)
			}
		})
	}
}

func TestResolveRejectsAbsolutePaths(t *testing.T) {
	sb, _ := newTestSandbox(t)
	if _, err := sb.Resolve("/etc/passwd"); err == nil {
		t.Fatal("Resolve(\"/etc/passwd\") should reject absolute paths")
	}
}

func TestResolveRejectsHiddenFile(t *testing.T) {
	sb, _ := newTestSandbox(t)
	if _, err := sb.Resolve(".env"); err == nil {
		t.Fatal("Resolve should reject a hidden file")
	}
}

func TestResolveRejectsHiddenDirectorySegment(t *testing.T) {
	sb, _ := newTestSandbox(t)
	if _, err := sb.Resolve("src/.metadata/config"); err == nil {
		t.Fatal("Resolve should reject a hidden directory segment")
	}
}

func TestResolveRejectsSymlinkIntoHiddenPath(t *testing.T) {
	sb, root := newTestSandbox(t)
	hiddenDir := filepath.Join(root, ".metadata")
	if err := os.Mkdir(hiddenDir, 0o700); err != nil {
		t.Fatalf("mkdir hidden dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDir, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write hidden secret: %v", err)
	}
	if err := os.Symlink(hiddenDir, filepath.Join(root, "visible-link")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	if _, err := sb.Resolve("visible-link/secret.txt"); err == nil {
		t.Fatal("Resolve should reject a symlink into a hidden path")
	}
}

func TestResolveNeutralizesParentEscape(t *testing.T) {
	sb, root := newTestSandbox(t)
	// A "../" climb must never resolve above the root. The lexical climb is
	// collapsed, so the path is contained (it points at a non-existent file
	// under root rather than escaping).
	abs, err := sb.Resolve("../../../../etc/passwd")
	if err != nil {
		// Returning an error is also acceptable containment behavior.
		return
	}
	if abs != root && !strings.HasPrefix(abs, root+string(filepath.Separator)) {
		t.Fatalf("Resolve(parent escape) = %q escaped root %q", abs, root)
	}
}

func TestResolveRejectsSymlinkEscape(t *testing.T) {
	sb, root := newTestSandbox(t)

	// Create an external directory with a secret file, then a symlink inside the
	// root that points at it. Resolving through the symlink must be rejected.
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	link := filepath.Join(root, "evil")
	if err := os.Symlink(external, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	if _, err := sb.Resolve("evil/secret.txt"); err == nil {
		t.Fatal("Resolve through a symlink pointing outside root should be rejected")
	}
}

func TestOpenReadsValidatedDescriptorAfterPathReplacement(t *testing.T) {
	sb, root := newTestSandbox(t)
	external := t.TempDir()
	externalPath := filepath.Join(external, "secret.txt")
	if err := os.WriteFile(externalPath, []byte("external secret"), 0o600); err != nil {
		t.Fatalf("write external file: %v", err)
	}

	file, openedRel, err := sb.Open("inside.txt")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer file.Close()
	if openedRel != "inside.txt" {
		t.Fatalf("opened path = %q, want inside.txt", openedRel)
	}

	originalPath := filepath.Join(root, "inside.txt")
	if err := os.Rename(originalPath, filepath.Join(root, "moved.txt")); err != nil {
		t.Fatalf("rename original file: %v", err)
	}
	if err := os.Symlink(externalPath, originalPath); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	content, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read opened descriptor: %v", err)
	}
	if strings.Contains(string(content), "external secret") || !strings.Contains(string(content), "hello") {
		t.Fatalf("descriptor read unexpected content %q", content)
	}
}

func TestOpenRejectsSymlinkEscape(t *testing.T) {
	sb, root := newTestSandbox(t)
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if err := os.Symlink(filepath.Join(external, "secret.txt"), filepath.Join(root, "escape")); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	if file, _, err := sb.Open("escape"); err == nil {
		file.Close()
		t.Fatal("Open through an escaping symlink should fail")
	}
}

func TestNewSandboxRejectsNonDirectory(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewSandbox(file); err == nil {
		t.Fatal("NewSandbox on a file should error")
	}
}

// canonical resolves dir the same way NewSandbox does, so tests can compare
// against what FindRepoRoot is expected to return on this platform (macOS
// temp dirs are themselves behind a symlink).
func canonical(t *testing.T, dir string) string {
	t.Helper()
	sb, err := NewSandbox(dir)
	if err != nil {
		t.Fatalf("NewSandbox(%q): %v", dir, err)
	}
	return sb.Root()
}

func TestFindRepoRootWalksUpToNearestMarker(t *testing.T) {
	repoRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(repoRoot, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	scanDir := filepath.Join(repoRoot, "domains", "synthetics", "apps")
	if err := os.MkdirAll(scanDir, 0o755); err != nil {
		t.Fatalf("mkdir scanDir: %v", err)
	}

	got := FindRepoRoot(scanDir)
	want := canonical(t, repoRoot)
	if got != want {
		t.Fatalf("FindRepoRoot(%q) = %q, want %q", scanDir, got, want)
	}
}

func TestFindRepoRootPrefersNearestAncestorMarker(t *testing.T) {
	outerRoot := t.TempDir()
	if err := os.Mkdir(filepath.Join(outerRoot, "WORKSPACE"), 0o755); err != nil {
		t.Fatalf("mkdir WORKSPACE: %v", err)
	}
	innerRoot := filepath.Join(outerRoot, "vendor", "nested-module")
	if err := os.MkdirAll(filepath.Join(innerRoot, "go.work"), 0o755); err != nil {
		t.Fatalf("mkdir nested go.work: %v", err)
	}
	scanDir := filepath.Join(innerRoot, "pkg")
	if err := os.Mkdir(scanDir, 0o755); err != nil {
		t.Fatalf("mkdir scanDir: %v", err)
	}

	got := FindRepoRoot(scanDir)
	want := canonical(t, innerRoot)
	if got != want {
		t.Fatalf("FindRepoRoot(%q) = %q, want nearest marker at %q", scanDir, got, want)
	}
}

func TestFindRepoRootFallsBackWhenNoMarkerFound(t *testing.T) {
	// t.TempDir() trees contain no repo-root markers, so walking up from a
	// child should return the child itself, unchanged.
	parent := t.TempDir()
	scanDir := filepath.Join(parent, "child")
	if err := os.Mkdir(scanDir, 0o755); err != nil {
		t.Fatalf("mkdir scanDir: %v", err)
	}

	got := FindRepoRoot(scanDir)
	want := canonical(t, scanDir)
	if got != want {
		t.Fatalf("FindRepoRoot(%q) = %q, want unchanged %q (no marker exists up to filesystem root)", scanDir, got, want)
	}
}
