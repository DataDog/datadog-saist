package agenttools

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSearchCodeDefinitionMakesPathGlobOptional(t *testing.T) {
	definitions := Definitions()

	var searchCodeParameters any
	for _, definition := range definitions {
		if definition.Name == ToolSearchCode {
			searchCodeParameters = definition.Parameters
			break
		}
	}

	if assert.NotNil(t, searchCodeParameters) {
		parameters, ok := searchCodeParameters.(map[string]any)
		if !assert.True(t, ok) {
			return
		}

		// path_glob is no longer required: an omitted glob is valid and searches
		// the runtime default scope.
		assert.ElementsMatch(t, []string{"query"}, parameters["required"])

		properties, ok := parameters["properties"].(map[string]any)
		if assert.True(t, ok) {
			pathGlob, ok := properties["path_glob"].(map[string]any)
			if assert.True(t, ok) {
				// No minLength/pattern, so an omitted or blank glob is schema-valid
				// and agrees with the runtime default.
				assert.NotContains(t, pathGlob, "minLength")
				assert.NotContains(t, pathGlob, "pattern")
				// The parameter stays documented.
				assert.Contains(t, pathGlob, "description")
			}
		}
	}
}

func TestSearchCodeDefinitionRequiresNonemptyQuery(t *testing.T) {
	definitions := Definitions()

	var searchCodeParameters any
	for _, definition := range definitions {
		if definition.Name == ToolSearchCode {
			searchCodeParameters = definition.Parameters
			break
		}
	}

	if assert.NotNil(t, searchCodeParameters) {
		parameters, ok := searchCodeParameters.(map[string]any)
		if !assert.True(t, ok) {
			return
		}

		assert.ElementsMatch(t, []string{"query"}, parameters["required"])

		properties, ok := parameters["properties"].(map[string]any)
		if assert.True(t, ok) {
			query, ok := properties["query"].(map[string]any)
			if assert.True(t, ok) {
				assert.Equal(t, 1, query["minLength"])
				assert.Equal(t, `\S`, query["pattern"])
			}
		}
	}
}

func TestInspectResultReadsSuccessfulMetadata(t *testing.T) {
	metadata := InspectResult(`{"matches":[],"truncated":false}`)

	assert.False(t, metadata.Truncated)
	assert.Empty(t, metadata.Error)
}

func TestInspectResultReadsTruncation(t *testing.T) {
	metadata := InspectResult(`{"content":"not retained","truncated":true}`)

	assert.True(t, metadata.Truncated)
	assert.Empty(t, metadata.Error)
}

func TestInspectResultReadsIncompleteCoverage(t *testing.T) {
	metadata := InspectResult(`{"matches":[],"files_scanned":17,"truncated":false,"incomplete":true,"stop_reason":"file_limit","search_scope":{"root":".","priority":"domains/team","path_glob":"*.go","search_kind":"text","strategy":"text","excluded_directories":["vendor"],"hidden_paths_excluded":true,"text_symlinks_excluded":true,"binary_files_excluded":true,"max_file_bytes":1048576}}`)

	assert.False(t, metadata.Truncated)
	assert.True(t, metadata.Incomplete)
	assert.Empty(t, metadata.Error)
	assert.Equal(t, "file_limit", metadata.StopReason)
	assert.Equal(t, 17, metadata.FilesScanned)
	if assert.NotNil(t, metadata.SearchScope) {
		assert.Equal(t, ".", metadata.SearchScope.Root)
		assert.Equal(t, "domains/team", metadata.SearchScope.Priority)
		assert.Equal(t, "*.go", metadata.SearchScope.PathGlob)
		assert.Equal(t, []string{"vendor"}, metadata.SearchScope.ExcludedDirectories)
		assert.True(t, metadata.SearchScope.HiddenPathsExcluded)
		assert.True(t, metadata.SearchScope.TextSymlinksExcluded)
		assert.True(t, metadata.SearchScope.BinaryFilesExcluded)
	}
}

func TestInspectResultReadsToolError(t *testing.T) {
	metadata := InspectResult(`{"error":"path is unavailable"}`)

	assert.False(t, metadata.Truncated)
	assert.Equal(t, "path is unavailable", metadata.Error)
}

func TestInspectResultReportsMalformedJSON(t *testing.T) {
	metadata := InspectResult(`{"truncated":`)

	assert.False(t, metadata.Truncated)
	assert.Contains(t, metadata.Error, "invalid tool result JSON")
}

func TestExecutePreservesContextFreeCompatibility(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)

	output := Execute(sb, ToolListDirectory, `{}`)
	metadata := InspectResult(output)

	assert.False(t, metadata.Incomplete)
	assert.Empty(t, metadata.Error)
}

func TestExecuteContextReportsSearchTimeout(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	output := ExecuteContext(ctx, sb, ToolSearchCode,
		`{"query":"needle","path_glob":"**/*.go"}`)
	metadata := InspectResult(output)

	assert.True(t, metadata.Incomplete)
	assert.Equal(t, StopReasonTimeout, metadata.StopReason)
	assert.Equal(t, context.DeadlineExceeded.Error(), metadata.Error)
	if assert.NotNil(t, metadata.SearchScope) {
		assert.Equal(t, "**/*.go", metadata.SearchScope.PathGlob)
	}
}

func TestExecuteContextPrioritizesSearchCancellationOverMalformedArguments(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	output := ExecuteContext(ctx, sb, ToolSearchCode, `{`)
	metadata := InspectResult(output)

	assert.True(t, metadata.Incomplete)
	assert.Equal(t, StopReasonCanceled, metadata.StopReason)
	assert.Equal(t, context.Canceled.Error(), metadata.Error)
}

func TestExecuteContextReportsReadCancellation(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	output := ExecuteContext(ctx, sb, ToolReadFile, `{"path":"inside.go"}`)
	metadata := InspectResult(output)

	assert.True(t, metadata.Incomplete)
	assert.Equal(t, StopReasonCanceled, metadata.StopReason)
	assert.Equal(t, context.Canceled.Error(), metadata.Error)
}

func TestExecuteContextReportsDirectoryCancellation(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	output := ExecuteContext(ctx, sb, ToolListDirectory, `{}`)
	metadata := InspectResult(output)

	assert.True(t, metadata.Incomplete)
	assert.Equal(t, StopReasonCanceled, metadata.StopReason)
	assert.Equal(t, context.Canceled.Error(), metadata.Error)
}

type blockingRegistrySymbolIndex struct{}

func (index *blockingRegistrySymbolIndex) LookupSymbol(_ string, _ SymbolSearchKind) []string {
	return nil
}

func (index *blockingRegistrySymbolIndex) LookupSymbolContext(ctx context.Context, _ string,
	_ SymbolSearchKind) []string {
	<-ctx.Done()
	return nil
}

func TestExecuteContextReturnsWhenSearchDependencyBlocks(t *testing.T) {
	sb, err := NewSandbox(t.TempDir())
	assert.NoError(t, err)
	sb.SetSymbolIndex(&blockingRegistrySymbolIndex{})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()

	output := ExecuteContext(ctx, sb, ToolSearchCode,
		`{"query":"needle","path_glob":"**/*.go","search_kind":"definition"}`)
	elapsed := time.Since(started)
	metadata := InspectResult(output)

	assert.Less(t, elapsed, time.Second)
	assert.True(t, metadata.Incomplete)
	assert.Equal(t, StopReasonTimeout, metadata.StopReason)
	assert.Equal(t, context.DeadlineExceeded.Error(), metadata.Error)
}
