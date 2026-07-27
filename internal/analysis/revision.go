package analysis

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func resolveSourceRevision(ctx context.Context, directory string) (string, string, bool, string, error) {
	root, err := runGit(ctx, directory, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", false, "", fmt.Errorf("resolve source repository root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", "", false, "", fmt.Errorf("resolve source repository path: %w", err)
	}
	repositorySHA, err := runGit(ctx, root, "rev-parse", "HEAD")
	if err != nil {
		return "", "", false, "", fmt.Errorf("resolve source repository HEAD: %w", err)
	}
	status, err := runGit(ctx, root, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return "", "", false, "", fmt.Errorf("read source repository status: %w", err)
	}

	scanRoot, err := filepath.Rel(root, directory)
	if err != nil {
		return "", "", false, "", fmt.Errorf("resolve scan root relative to repository: %w", err)
	}
	if scanRoot == ".." || strings.HasPrefix(scanRoot, ".."+string(filepath.Separator)) {
		return "", "", false, "", fmt.Errorf("scan root %q is outside repository %q", directory, root)
	}

	return root, repositorySHA, status != "", filepath.ToSlash(scanRoot), nil
}

func runGit(ctx context.Context, directory string, arguments ...string) (string, error) {
	commandArguments := append([]string{"-C", directory}, arguments...)
	output, err := exec.CommandContext(ctx, "git", commandArguments...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed, %w, output %q",
			strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func validateCandidateExportPath(repositoryRoot, exportPath string) error {
	_, inside, err := resolvePathOutsideBoundary(repositoryRoot, exportPath)
	if err != nil {
		return fmt.Errorf("resolve candidate export path against repository, %w", err)
	}
	if inside {
		return fmt.Errorf("candidate export path %q must be outside the source repository", exportPath)
	}
	return nil
}

func pathInsideRoot(root, candidate string) (bool, error) {
	relativePath, err := filepath.Rel(root, candidate)
	if err != nil {
		return false, err
	}
	return relativePath != ".." &&
		!strings.HasPrefix(relativePath, ".."+string(filepath.Separator)), nil
}

// resolvePathOutsideBoundary checks both the lexical path and its resolved
// filesystem destination. Lexical containment prevents a path inside the
// boundary from escaping through a symlink. Resolved containment prevents an
// external path from redirecting back into the boundary.
func resolvePathOutsideBoundary(root, candidate string) (string, bool, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", false, fmt.Errorf("resolve boundary root, %w", err)
	}
	absoluteCandidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", false, fmt.Errorf("resolve boundary candidate, %w", err)
	}
	inside, err := pathInsideRoot(absoluteRoot, absoluteCandidate)
	if err != nil {
		return "", false, err
	}
	if inside {
		return absoluteCandidate, true, nil
	}

	resolvedRoot, err := resolveBoundaryPath(absoluteRoot)
	if err != nil {
		return "", false, fmt.Errorf("resolve boundary root, %w", err)
	}
	resolvedCandidate, err := resolveBoundaryPath(absoluteCandidate)
	if err != nil {
		return "", false, fmt.Errorf("resolve boundary candidate, %w", err)
	}
	inside, err = pathInsideRoot(resolvedRoot, resolvedCandidate)
	if err != nil {
		return "", false, err
	}
	return resolvedCandidate, inside, nil
}

// resolveBoundaryPath evaluates the longest existing prefix and appends any
// missing suffix. If an existing symlink component cannot be resolved, the
// path is rejected instead of treating its lexical parent as the destination.
func resolveBoundaryPath(filePath string) (string, error) {
	absolutePath, err := filepath.Abs(filePath)
	if err != nil {
		return "", err
	}
	current := filepath.Clean(absolutePath)
	missing := make([]string, 0)
	for {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			resolved, resolveErr := filepath.EvalSymlinks(current)
			if resolveErr != nil {
				return "", resolveErr
			}
			for index := len(missing) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, missing[index])
			}
			return filepath.Clean(resolved), nil
		}
		if !os.IsNotExist(statErr) {
			return "", statErr
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", statErr
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}
