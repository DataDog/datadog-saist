// Package agenttools exposes a small, read-only repository tool surface.
package agenttools

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/DataDog/datadog-saist/internal/clients"
)

const (
	maxFileBytes    = 1 << 20
	maxReadBytes    = 64 << 10
	maxReadLines    = 400
	maxSearchFiles  = 5000
	maxSearchResult = 50
)

type Sandbox struct{ root string }

func NewSandbox(root string) (*Sandbox, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, err
	}
	return &Sandbox{root: resolved}, nil
}

func Definitions() []clients.ToolDefinition {
	return []clients.ToolDefinition{
		{Name: "search_code", Description: "Search repository source text. query is a regular expression or literal text.", Parameters: map[string]any{"type": "object", "properties": map[string]any{"query": map[string]any{"type": "string"}, "max_results": map[string]any{"type": "integer"}}, "required": []string{"query"}}},
		{Name: "read_file", Description: "Read a repository-relative source file with line numbers.", Parameters: map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}, "start_line": map[string]any{"type": "integer"}, "end_line": map[string]any{"type": "integer"}}, "required": []string{"path"}}},
		{Name: "list_directory", Description: "List a repository-relative directory.", Parameters: map[string]any{"type": "object", "properties": map[string]any{"path": map[string]any{"type": "string"}}}},
	}
}

func Execute(sandbox *Sandbox, name, arguments string) string {
	var values map[string]any
	if err := json.Unmarshal([]byte(arguments), &values); err != nil {
		return result(map[string]any{"error": "invalid arguments"})
	}
	switch name {
	case "read_file":
		return sandbox.readFile(stringValue(values, "path"), intValue(values, "start_line"), intValue(values, "end_line"))
	case "list_directory":
		return sandbox.listDirectory(stringValue(values, "path"))
	case "search_code":
		return sandbox.searchCode(stringValue(values, "query"), intValue(values, "max_results"))
	default:
		return result(map[string]any{"error": "unknown tool"})
	}
}

func (s *Sandbox) resolve(path string) (string, error) {
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("absolute paths are not allowed")
	}
	target := filepath.Clean(filepath.Join(s.root, path))
	if target != s.root && !strings.HasPrefix(target, s.root+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes repository root")
	}
	info, err := os.Lstat(target)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("symlinks are not allowed")
	}
	return target, nil
}

func (s *Sandbox) readFile(path string, start, end int) string {
	if path == "" {
		return result(map[string]any{"error": "path is required"})
	}
	target, err := s.resolve(path)
	if err != nil {
		return result(map[string]any{"error": err.Error()})
	}
	info, err := os.Stat(target)
	if err != nil || info.Size() > maxFileBytes {
		return result(map[string]any{"error": "file is unavailable or too large"})
	}
	data, err := os.ReadFile(target)
	if err != nil || bytesBinary(data) {
		return result(map[string]any{"error": "file is unreadable or binary"})
	}
	lines := strings.Split(string(data), "\n")
	if start <= 0 {
		start = 1
	}
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if end-start+1 > maxReadLines {
		end = start + maxReadLines - 1
	}
	content := make([]string, 0, end-start+1)
	for line := start; line <= end; line++ {
		content = append(content, fmt.Sprintf("%d: %s", line, lines[line-1]))
	}
	joined := strings.Join(content, "\n")
	if len(joined) > maxReadBytes {
		joined = joined[:maxReadBytes]
	}
	return result(map[string]any{"path": filepath.ToSlash(path), "content": joined, "truncated": len(joined) >= maxReadBytes})
}

func (s *Sandbox) listDirectory(path string) string {
	if path == "" {
		path = "."
	}
	target, err := s.resolve(path)
	if err != nil {
		return result(map[string]any{"error": err.Error()})
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return result(map[string]any{"error": err.Error()})
	}
	values := make([]map[string]any, 0, len(entries))
	for index, entry := range entries {
		if index >= 200 {
			break
		}
		if ignored(entry.Name()) {
			continue
		}
		values = append(values, map[string]any{"name": entry.Name(), "type": entry.Type().String()})
	}
	return result(map[string]any{"path": filepath.ToSlash(path), "entries": values})
}

func (s *Sandbox) searchCode(query string, limit int) string {
	if query == "" {
		return result(map[string]any{"error": "query is required"})
	}
	if limit <= 0 || limit > maxSearchResult {
		limit = maxSearchResult
	}
	re, err := regexp.Compile(query)
	if err != nil {
		re = regexp.MustCompile(regexp.QuoteMeta(query))
	}
	matches := make([]map[string]any, 0, limit)
	files := 0
	_ = filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || len(matches) >= limit || files >= maxSearchFiles {
			return nil
		}
		if path != s.root && ignored(entry.Name()) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil || info.Size() > maxFileBytes {
			return nil
		}
		files++
		data, err := os.ReadFile(path)
		if err != nil || bytesBinary(data) {
			return nil
		}
		for line, text := range strings.Split(string(data), "\n") {
			if re.MatchString(text) {
				relative, _ := filepath.Rel(s.root, path)
				matches = append(matches, map[string]any{"path": filepath.ToSlash(relative), "line": line + 1, "snippet": trim(text, 200)})
				if len(matches) >= limit {
					break
				}
			}
		}
		return nil
	})
	return result(map[string]any{"matches": matches, "files_scanned": files, "truncated": files >= maxSearchFiles})
}

func ignored(name string) bool {
	return strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" || name == "dist" || name == "build"
}
func bytesBinary(value []byte) bool {
	for _, item := range value {
		if item == 0 {
			return true
		}
	}
	return false
}
func trim(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}
func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}
func intValue(values map[string]any, key string) int {
	value, _ := values[key].(float64)
	return int(value)
}
func result(value any) string { data, _ := json.Marshal(value); return string(data) }
