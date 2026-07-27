package agenttools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type searchMatch struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

type searchScope struct {
	Root                 string   `json:"root"`
	Priority             string   `json:"priority"`
	PathGlob             string   `json:"path_glob,omitempty"`
	SearchKind           string   `json:"search_kind"`
	Strategy             string   `json:"strategy"`
	ExcludedDirectories  []string `json:"excluded_directories"`
	HiddenPathsExcluded  bool     `json:"hidden_paths_excluded"`
	TextSymlinksExcluded bool     `json:"text_symlinks_excluded"`
	BinaryFilesExcluded  bool     `json:"binary_files_excluded"`
	MaxFileBytes         int64    `json:"max_file_bytes"`
}

type searchResult struct {
	Matches      []searchMatch `json:"matches"`
	FilesScanned int           `json:"files_scanned"`
	SearchScope  searchScope   `json:"search_scope"`
	Truncated    bool          `json:"truncated"`
	Incomplete   bool          `json:"incomplete"`
	StopReason   string        `json:"stop_reason,omitempty"`
	Error        string        `json:"error,omitempty"`
}

type searchArguments struct {
	Query      string `json:"query"`
	PathGlob   string `json:"path_glob"`
	SearchKind string `json:"search_kind"`
	MaxResults int    `json:"max_results"`
}

type readFileResult struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
}

type dirEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type listResult struct {
	Path           string     `json:"path"`
	Entries        []dirEntry `json:"entries"`
	EntriesScanned int        `json:"entries_scanned"`
	Truncated      bool       `json:"truncated"`
	Incomplete     bool       `json:"incomplete"`
	StopReason     string     `json:"stop_reason,omitempty"`
	Error          string     `json:"error,omitempty"`
}

type contextSymbolIndex interface {
	LookupSymbolContext(context.Context, string, SymbolSearchKind) []string
}

// runSearchCode searches file contents under the scan root for a regular
// expression (falling back to a literal substring match when the pattern is
// invalid) and returns matching paths, line numbers, and trimmed snippets.
//
// The walk is tiered around the sandbox's search priority (see
// Sandbox.SearchPriority). The priority subtree is walked first, then every
// other top-level entry of the root, then whatever is left of the priority's
// own top-level branch. Without this ordering, a plain lexical walk from the
// root can exhaust the whole maxSearchFilesScanned budget inside one large
// sibling of the priority directory (for example a monorepo's domains/)
// before ever reaching a shared directory that sits next to it (for example a
// repo-root libs/).
func runSearchCode(sb *Sandbox, arguments string) string {
	return runSearchCodeContext(context.Background(), sb, arguments)
}

func runSearchCodeContext(ctx context.Context, sb *Sandbox, arguments string) string {
	var args searchArguments
	parseErr := json.Unmarshal([]byte(arguments), &args)
	args.Query = strings.TrimSpace(args.Query)
	args.PathGlob = filepath.ToSlash(strings.TrimSpace(args.PathGlob))
	args.SearchKind = strings.TrimSpace(args.SearchKind)
	if args.SearchKind == "" {
		args.SearchKind = "text"
	}
	result := newSearchResult(sb, args)
	if markSearchContext(ctx, &result) {
		return toolJSON(result)
	}
	if parseErr != nil {
		result.Error = fmt.Sprintf("invalid arguments, %v", parseErr)
		result.Incomplete = true
		result.StopReason = StopReasonInvalidArguments
		return toolJSON(result)
	}
	if args.Query == "" {
		result.Error = "query is required"
		result.Incomplete = true
		result.StopReason = StopReasonInvalidArguments
		return toolJSON(result)
	}
	if args.SearchKind != "text" && args.SearchKind != string(SymbolSearchDefinition) &&
		args.SearchKind != string(SymbolSearchReference) {
		result.Error = fmt.Sprintf("unsupported search_kind %q", args.SearchKind)
		result.Incomplete = true
		result.StopReason = StopReasonInvalidArguments
		return toolJSON(result)
	}
	// A caller-supplied path_glob is validated and searched exactly as given.
	if args.PathGlob != "" {
		if err := validateGlobPattern(args.PathGlob); err != nil {
			result.Error = fmt.Sprintf("invalid path_glob %q: %v", args.PathGlob, err)
			result.Incomplete = true
			result.StopReason = StopReasonInvalidArguments
			return toolJSON(result)
		}
		return toolJSON(searchForGlob(ctx, sb, args))
	}

	// An omitted path_glob is not an error. When the context carries a search
	// anchor (see WithSearchAnchor), the default scope is chosen adaptively: start
	// at the anchor's own subtree and widen toward the scan root only when nearby
	// scopes are too sparse. Otherwise fall back to the deterministic default
	// scope (the configured priority subtree when set, else the whole scan root).
	// The effective glob is always recorded in SearchScope.PathGlob so the
	// evidence record is unambiguous. The generated default is always valid.
	if anchor := searchAnchorFromContext(ctx); anchor != "" {
		return toolJSON(runAdaptiveSearch(ctx, sb, args, adaptiveSearchGlobs(anchor)))
	}
	args.PathGlob = defaultSearchGlob(sb)
	return toolJSON(searchForGlob(ctx, sb, args))
}

// searchForGlob runs one search for a fully-resolved args.PathGlob and returns a
// fresh result. It prefers the repository symbol index for definition and
// reference searches, falling back to a text walk, and reports the exact scope
// bookkeeping the tool returns to the model.
func searchForGlob(ctx context.Context, sb *Sandbox, args searchArguments) searchResult {
	result := newSearchResult(sb, args)
	if markSearchContext(ctx, &result) {
		return result
	}

	limit := args.MaxResults
	if limit <= 0 {
		limit = defaultSearchResults
	}
	if limit > maxSearchResults {
		limit = maxSearchResults
	}

	matchLine := searchLineMatcher(args)
	if args.SearchKind != "text" {
		if index := sb.getSymbolIndex(); index != nil {
			if markSearchContext(ctx, &result) {
				return result
			}
			indexedPaths := lookupSymbol(ctx, index, args.Query, SymbolSearchKind(args.SearchKind))
			if markSearchContext(ctx, &result) {
				return result
			}
			if len(indexedPaths) > 0 {
				result.SearchScope.Strategy = "symbol_index"
				runIndexedSearch(ctx, sb, args, indexedPaths, matchLine, limit, &result)
				if markSearchContext(ctx, &result) {
					return result
				}
				if len(result.Matches) > 0 {
					return result
				}
				result = newSearchResult(sb, args)
			}
		}
		result.SearchScope.Strategy = "text_fallback"
	}

	runTextSearch(ctx, sb, args, matchLine, limit, &result)
	markSearchContext(ctx, &result)
	return result
}

// adaptiveSearchGlobs builds the ordered narrow-to-wide scope chain for an
// omitted path_glob given a normalized anchor directory. It starts at the
// anchor's own subtree and walks up its ancestors, capped at
// adaptiveSearchMaxLocalScopes local scopes, then always ends at the whole scan
// root ("**") so coverage is never lost. Scopes that cannot form a valid glob
// are skipped, and duplicates are removed while preserving order.
func adaptiveSearchGlobs(anchor string) []string {
	globs := make([]string, 0, adaptiveSearchMaxLocalScopes+1)
	segments := strings.Split(anchor, "/")
	for depth := len(segments); depth >= 1 && len(globs) < adaptiveSearchMaxLocalScopes; depth-- {
		candidate := strings.Join(segments[:depth], "/") + "/**"
		if validateGlobPattern(candidate) == nil {
			globs = append(globs, candidate)
		}
	}
	globs = append(globs, "**")
	return dedupeStrings(globs)
}

// runAdaptiveSearch searches the given narrow-to-wide scopes and returns the
// result for the narrowest scope that yields at least adaptiveSearchMinMatches
// matches. When no scope reaches the threshold it returns the widest scope's
// result, which (ending at "**") is the most complete. It stops early if the
// context is canceled mid-walk.
func runAdaptiveSearch(ctx context.Context, sb *Sandbox, args searchArguments, globs []string) searchResult {
	var last searchResult
	for _, glob := range globs {
		scoped := args
		scoped.PathGlob = glob
		last = searchForGlob(ctx, sb, scoped)
		if ctx.Err() != nil {
			return last
		}
		if len(last.Matches) >= adaptiveSearchMinMatches {
			return last
		}
	}
	return last
}

// dedupeStrings returns values with duplicates removed, preserving first-seen
// order.
func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	deduped := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		deduped = append(deduped, value)
	}
	return deduped
}

func lookupSymbol(ctx context.Context, index SymbolIndex, symbol string, kind SymbolSearchKind) []string {
	if contextIndex, ok := index.(contextSymbolIndex); ok {
		return contextIndex.LookupSymbolContext(ctx, symbol, kind)
	}
	return index.LookupSymbol(symbol, kind)
}

func newSearchResult(sb *Sandbox, args searchArguments) searchResult {
	priority := relForDisplay(sb, sb.SearchPriority())
	if priority == "" {
		priority = "."
	}
	return searchResult{
		Matches: []searchMatch{},
		SearchScope: searchScope{
			Root:                 ".",
			Priority:             priority,
			PathGlob:             args.PathGlob,
			SearchKind:           args.SearchKind,
			Strategy:             "text",
			ExcludedDirectories:  excludedDirectoryNames(),
			HiddenPathsExcluded:  true,
			TextSymlinksExcluded: true,
			BinaryFilesExcluded:  true,
			MaxFileBytes:         maxScanFileBytes,
		},
	}
}

// defaultSearchGlob returns the deterministic path scope search_code applies
// when the caller omits path_glob. It scopes to the configured search-priority
// subtree when one is set (the narrower original scan target), otherwise to the
// entire scan root. The returned value is a valid path_glob that both drives
// matching and is reported back as SearchScope.PathGlob. If the priority path
// cannot be expressed as a valid glob (for example a directory name containing
// glob metacharacters), it falls back to the whole scan root so the default is
// always valid and never rejects.
func defaultSearchGlob(sb *Sandbox) string {
	priority := sb.SearchPriority()
	if priority == sb.Root() {
		return "**"
	}
	priorityRel := relForDisplay(sb, priority)
	if priorityRel == "" || priorityRel == "." {
		return "**"
	}
	candidate := priorityRel + "/**"
	if validateGlobPattern(candidate) != nil {
		return "**"
	}
	return candidate
}

// globFixedPrefixDir returns the leading fixed (wildcard-free) directory prefix
// of a path glob, or "" when the glob has none. It lets a scoped walk start at
// the smallest subtree that can contain any match instead of the whole root.
// Single-segment globs return "" because search_code also matches them against
// each file's base name anywhere in the tree, so no directory prefix is safe.
func globFixedPrefixDir(pattern string) string {
	segments := strings.Split(filepath.ToSlash(pattern), "/")
	if len(segments) < 2 {
		return ""
	}
	prefix := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "**" || strings.ContainsAny(segment, "*?[") {
			break
		}
		prefix = append(prefix, segment)
	}
	// An all-fixed multi-segment glob names an exact file; its last segment is the
	// file name, not a directory, so drop it before treating the rest as a scope.
	if len(prefix) == len(segments) {
		prefix = prefix[:len(prefix)-1]
	}
	if len(prefix) == 0 {
		return ""
	}
	return strings.Join(prefix, "/")
}

func excludedDirectoryNames() []string {
	names := make([]string, 0, len(excludedDirs))
	for name := range excludedDirs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func searchLineMatcher(args searchArguments) func(string) bool {
	if args.SearchKind != "text" {
		return func(line string) bool {
			return strings.Contains(line, args.Query)
		}
	}
	if compiled, err := regexp.Compile(args.Query); err == nil {
		return compiled.MatchString
	}
	return func(line string) bool {
		return strings.Contains(line, args.Query)
	}
}

func runIndexedSearch(ctx context.Context, sb *Sandbox, args searchArguments, indexedPaths []string,
	matchLine func(string) bool, limit int, result *searchResult) {
	attempted := 0
	seen := make(map[string]struct{}, len(indexedPaths))
	for _, indexedPath := range indexedPaths {
		if markSearchContext(ctx, result) {
			return
		}
		if result.Incomplete && result.StopReason == "result_limit" {
			return
		}
		abs, err := sb.Resolve(indexedPath)
		if err != nil {
			markSearchIncomplete(result, "invalid_index_path")
			continue
		}
		rel := relForDisplay(sb, abs)
		if _, exists := seen[rel]; exists {
			continue
		}
		seen[rel] = struct{}{}
		if args.PathGlob != "" && !globMatches(args.PathGlob, rel) {
			continue
		}
		if scanSearchFile(ctx, sb, rel, matchLine, limit, &attempted, result) {
			return
		}
	}
}

func runTextSearch(ctx context.Context, sb *Sandbox, args searchArguments, matchLine func(string) bool,
	limit int, result *searchResult) {
	root := sb.Root()
	attempted := 0
	done := false

	// walk scans everything under walkRoot, skipping any entry whose path
	// relative to root satisfies skip. It stops as soon as the shared file-scan
	// budget or match limit is reached, after which every later call is a no-op.
	walk := func(walkRoot string, skip func(rel string) bool) {
		if done || markSearchContext(ctx, result) {
			done = true
			return
		}
		walkErr := filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
			if markSearchContext(ctx, result) {
				done = true
				return filepath.SkipAll
			}
			if err != nil {
				markSearchIncomplete(result, "walk_error")
				return nil // skip unreadable entries
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)

			if d.IsDir() {
				if path == walkRoot {
					return nil
				}
				if isHiddenName(d.Name()) || isExcludedDir(d.Name()) || (skip != nil && skip(rel)) {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if isHiddenName(d.Name()) {
				return nil
			}
			if skip != nil && skip(rel) {
				return nil
			}

			if args.PathGlob != "" && !globMatches(args.PathGlob, rel) {
				return nil
			}

			if scanSearchFile(ctx, sb, rel, matchLine, limit, &attempted, result) {
				done = true
				return filepath.SkipAll
			}
			return nil
		})
		if markSearchContext(ctx, result) {
			done = true
			return
		}
		if walkErr != nil {
			markSearchIncomplete(result, "walk_error")
		}
	}

	// Fixed-prefix fast path: when the glob has a concrete leading directory, only
	// that subtree can contain a match, so walk it directly instead of the whole
	// tree. This changes cost, not results, and makes narrow (including adaptive)
	// scopes cheap on large repositories. A prefix that does not resolve to a
	// directory falls through to the full tiered walk below.
	if prefix := globFixedPrefixDir(args.PathGlob); prefix != "" {
		prefixAbs := filepath.Join(root, filepath.FromSlash(prefix))
		if info, statErr := os.Stat(prefixAbs); statErr == nil && info.IsDir() {
			walk(prefixAbs, nil)
			return
		}
	}

	priority := sb.SearchPriority()
	priorityRel, relErr := filepath.Rel(root, priority)
	if priority == root || relErr != nil {
		walk(root, nil)
		return
	}
	priorityRel = filepath.ToSlash(priorityRel)
	priorityBranch := priorityRel
	if idx := strings.Index(priorityRel, "/"); idx >= 0 {
		priorityBranch = priorityRel[:idx]
	}

	// Tier 1 is the original, narrower scan target. This is exactly what the
	// sandbox covered before it was widened to root, so it is walked first and
	// in full (budget permitting).
	walk(priority, nil)

	// Tier 2 covers every top-level entry of root except priorityBranch, i.e. the
	// directories widening the sandbox exists to reach (shared libraries etc).
	walk(root, func(rel string) bool {
		return rel == priorityBranch || strings.HasPrefix(rel, priorityBranch+"/")
	})

	// Tier 3 covers whatever is left of priorityBranch. It has the lowest priority since tier 1
	// already covered the part of it that mattered most.
	walk(filepath.Join(root, priorityBranch), func(rel string) bool {
		return rel == priorityRel || strings.HasPrefix(rel, priorityRel+"/")
	})
}

func scanSearchFile(ctx context.Context, sb *Sandbox, rel string, matchLine func(string) bool, limit int,
	attempted *int, result *searchResult) bool {
	if markSearchContext(ctx, result) {
		return true
	}
	if *attempted >= maxSearchFilesScanned {
		markSearchIncomplete(result, "file_limit")
		return true
	}
	(*attempted)++

	file, openedRel, err := sb.Open(rel)
	if err != nil {
		if markSearchContext(ctx, result) {
			return true
		}
		markSearchIncomplete(result, "open_error")
		return false
	}
	defer file.Close()
	if markSearchContext(ctx, result) {
		return true
	}

	info, err := file.Stat()
	if err != nil {
		if markSearchContext(ctx, result) {
			return true
		}
		markSearchIncomplete(result, "stat_error")
		return false
	}
	if !info.Mode().IsRegular() {
		return false
	}
	if info.Size() > maxScanFileBytes {
		markSearchIncomplete(result, "file_too_large")
		return false
	}
	if markSearchContext(ctx, result) {
		return true
	}

	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, maxScanFileBytes+1))
	if err != nil {
		if markSearchContext(ctx, result) {
			return true
		}
		markSearchIncomplete(result, "read_error")
		return false
	}
	if markSearchContext(ctx, result) {
		return true
	}
	if len(data) > maxScanFileBytes {
		markSearchIncomplete(result, "file_too_large")
		return false
	}
	if looksBinary(data[:min(len(data), binarySniffBytes)]) {
		return false
	}
	result.FilesScanned++

	for i, line := range strings.Split(string(data), "\n") {
		if markSearchContext(ctx, result) {
			return true
		}
		if !matchLine(line) {
			continue
		}
		result.Matches = append(result.Matches, searchMatch{
			Path:    openedRel,
			Line:    i + 1,
			Snippet: trimSnippet(line),
		})
		if len(result.Matches) >= limit {
			result.Truncated = true
			markSearchIncomplete(result, "result_limit")
			return true
		}
	}
	return false
}

func markSearchContext(ctx context.Context, result *searchResult) bool {
	err := ctx.Err()
	if err == nil {
		return false
	}
	result.Incomplete = true
	result.StopReason = contextStopReason(err)
	result.Error = err.Error()
	return true
}

func markSearchIncomplete(result *searchResult, reason string) {
	result.Incomplete = true
	if result.StopReason == "" {
		result.StopReason = reason
	}
}

// runReadFile reads a file (optionally a line range) from the scan root and
// returns line-numbered content using the same "N: line" format the scanner
// shows the model elsewhere.
func runReadFile(sb *Sandbox, arguments string) string {
	return runReadFileContext(context.Background(), sb, arguments)
}

func runReadFileContext(ctx context.Context, sb *Sandbox, arguments string) string {
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}
	var args struct {
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}
	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return toolError(fmt.Sprintf("invalid arguments: %v", err))
	}
	if args.Path == "" {
		return toolError("path is required")
	}
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}

	file, openedRel, err := sb.Open(args.Path)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return toolContextError(ctxErr)
		}
		return toolError(err.Error())
	}
	defer file.Close()
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}

	info, err := file.Stat()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return toolContextError(ctxErr)
		}
		return toolError(fmt.Sprintf("cannot read %q: %v", args.Path, err))
	}
	if !info.Mode().IsRegular() {
		return toolError(fmt.Sprintf("%q is a directory. Use list_directory", args.Path))
	}
	if info.Size() > maxReadFileInputBytes {
		return toolError(fmt.Sprintf("%q exceeds the %d-byte read limit", args.Path, maxReadFileInputBytes))
	}
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}
	data, err := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: file}, maxReadFileInputBytes+1))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return toolContextError(ctxErr)
		}
		return toolError(fmt.Sprintf("cannot read %q: %v", args.Path, err))
	}
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}
	if len(data) > maxReadFileInputBytes {
		return toolError(fmt.Sprintf("%q exceeds the %d-byte read limit", args.Path, maxReadFileInputBytes))
	}
	if looksBinary(data[:min(len(data), binarySniffBytes)]) {
		return toolError(fmt.Sprintf("%q appears to be a binary file", args.Path))
	}

	lines := strings.Split(string(data), "\n")
	total := len(lines)

	start := args.StartLine
	if start < 1 {
		start = 1
	}
	if start > total {
		start = total
	}
	end := args.EndLine
	if end <= 0 || end > total {
		end = total
	}
	if end < start {
		end = start
	}

	// A single read returns at most maxReadFileLines lines and at most
	// maxReadFileBytes (64 KiB) of output, whichever bound is reached first. Both
	// set Truncated so the model knows to request the next range.
	truncated := false
	if end-start+1 > maxReadFileLines {
		end = start + maxReadFileLines - 1
		truncated = true
	}

	var b strings.Builder
	last := start
	for i := start; i <= end; i++ {
		if err := ctx.Err(); err != nil {
			return toolContextError(err)
		}
		entry := fmt.Sprintf("%d: %s\n", i, lines[i-1])
		if b.Len()+len(entry) > maxReadFileBytes {
			truncated = true
			break
		}
		b.WriteString(entry)
		last = i
	}

	return toolJSON(readFileResult{
		Path:      openedRel,
		StartLine: start,
		EndLine:   last,
		Content:   b.String(),
		Truncated: truncated,
	})
}

// runListDirectory lists the entries of a directory within the scan root.
func runListDirectory(sb *Sandbox, arguments string) string {
	return runListDirectoryContext(context.Background(), sb, arguments)
}

func runListDirectoryContext(ctx context.Context, sb *Sandbox, arguments string) string {
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}
	var args struct {
		Path       string `json:"path"`
		MaxEntries int    `json:"max_entries"`
	}
	if strings.TrimSpace(arguments) != "" {
		if err := json.Unmarshal([]byte(arguments), &args); err != nil {
			return toolError(fmt.Sprintf("invalid arguments: %v", err))
		}
	}

	limit := args.MaxEntries
	if limit <= 0 {
		limit = defaultListEntries
	}
	if limit > maxListEntries {
		limit = maxListEntries
	}
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}

	directory, openedRel, err := sb.Open(args.Path)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return toolContextError(ctxErr)
		}
		return toolError(err.Error())
	}
	defer directory.Close()
	if err := ctx.Err(); err != nil {
		return toolContextError(err)
	}

	info, err := directory.Stat()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return toolContextError(ctxErr)
		}
		return toolError(fmt.Sprintf("cannot list %q: %v", args.Path, err))
	}
	if !info.IsDir() {
		return toolError(fmt.Sprintf("%q is not a directory", args.Path))
	}
	result := listResult{Path: openedRel, Entries: []dirEntry{}}
	for result.EntriesScanned < maxListEntriesScanned {
		if markListContext(ctx, &result) {
			return toolJSON(result)
		}
		batchSize := min(128, maxListEntriesScanned-result.EntriesScanned)
		entries, readErr := directory.ReadDir(batchSize)
		if markListContext(ctx, &result) {
			return toolJSON(result)
		}
		for _, entry := range entries {
			if markListContext(ctx, &result) {
				return toolJSON(result)
			}
			result.EntriesScanned++
			if isHiddenName(entry.Name()) {
				continue
			}
			if len(result.Entries) >= limit {
				result.Truncated = true
				result.Incomplete = true
				result.StopReason = "result_limit"
				return toolJSON(result)
			}
			typ := "file"
			if entry.IsDir() {
				typ = "dir"
			}
			result.Entries = append(result.Entries, dirEntry{Name: entry.Name(), Type: typ})
		}
		if readErr == io.EOF {
			return toolJSON(result)
		}
		if readErr != nil {
			return toolError(fmt.Sprintf("cannot list %q: %v", args.Path, readErr))
		}
	}
	result.Incomplete = true
	result.StopReason = "entry_limit"
	return toolJSON(result)
}

func markListContext(ctx context.Context, result *listResult) bool {
	err := ctx.Err()
	if err == nil {
		return false
	}
	result.Incomplete = true
	result.StopReason = contextStopReason(err)
	result.Error = err.Error()
	return true
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

// globMatches reports whether pattern matches either the full relative path or
// its base name, so a glob like "*.go" works regardless of directory depth.
// A complete ** segment matches zero or more path segments.
func globMatches(pattern, rel string) bool {
	pattern = filepath.ToSlash(pattern)
	rel = filepath.ToSlash(rel)
	patternSegments := strings.Split(pattern, "/")
	relSegments := strings.Split(rel, "/")

	type matchState struct {
		patternIndex int
		pathIndex    int
	}
	known := make(map[matchState]bool)
	memo := make(map[matchState]bool)
	var matches func(int, int) bool
	matches = func(patternIndex, pathIndex int) bool {
		state := matchState{patternIndex: patternIndex, pathIndex: pathIndex}
		if known[state] {
			return memo[state]
		}
		known[state] = true

		matched := false
		switch {
		case patternIndex == len(patternSegments):
			matched = pathIndex == len(relSegments)
		case patternSegments[patternIndex] == "**":
			matched = matches(patternIndex+1, pathIndex) ||
				(pathIndex < len(relSegments) && matches(patternIndex, pathIndex+1))
		case pathIndex < len(relSegments):
			segmentMatched, _ := pathpkg.Match(patternSegments[patternIndex], relSegments[pathIndex])
			matched = segmentMatched && matches(patternIndex+1, pathIndex+1)
		}
		memo[state] = matched
		return matched
	}

	if matches(0, 0) {
		return true
	}
	if len(patternSegments) != 1 {
		return false
	}
	matched, _ := pathpkg.Match(pattern, pathpkg.Base(rel))
	return matched
}

func validateGlobPattern(pattern string) error {
	normalized := filepath.ToSlash(pattern)
	if pathpkg.IsAbs(normalized) {
		return fmt.Errorf("path_glob must be repository-relative")
	}
	for _, segment := range strings.Split(normalized, "/") {
		if segment == "" {
			return fmt.Errorf("path_glob cannot contain an empty path segment")
		}
		if segment == "." {
			return fmt.Errorf("path_glob cannot contain a current-directory path segment")
		}
		if segment == ".." {
			return fmt.Errorf("path_glob cannot contain a parent path segment")
		}
		if segment == "**" {
			continue
		}
		if _, err := pathpkg.Match(segment, "probe"); err != nil {
			return err
		}
	}
	return nil
}

// trimSnippet trims surrounding whitespace and caps a snippet at a readable
// length on a rune boundary.
func trimSnippet(line string) string {
	line = strings.TrimSpace(line)
	runes := []rune(line)
	if len(runes) > snippetMaxRunes {
		return string(runes[:snippetMaxRunes]) + "..."
	}
	return line
}

// relForDisplay renders an absolute path inside the sandbox as a root-relative,
// slash-separated path for display back to the model.
func relForDisplay(sb *Sandbox, abs string) string {
	rel, err := filepath.Rel(sb.Root(), abs)
	if err != nil {
		return abs
	}
	return filepath.ToSlash(rel)
}
