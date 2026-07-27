package agents

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DataDog/datadog-saist/internal/agenttools"
	"github.com/DataDog/datadog-saist/internal/clients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExploreForEvidenceAnchorsSearchAtFlaggedDirectory proves the end-to-end
// wiring: an omitted path_glob during exploration is scoped to the flagged file's
// directory. The flagged file sits under a/b/c and that subtree holds enough
// matches, so the adaptive default scope resolves to a/b/c/** rather than the
// whole scan root that an unanchored search would use.
func TestExploreForEvidenceAnchorsSearchAtFlaggedDirectory(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"a/b/c/flagged.go",
		"a/b/c/one.go",
		"a/b/c/two.go",
		"a/b/c/three.go",
		"z/faraway.go",
	} {
		full := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o700))
		require.NoError(t, os.WriteFile(full, []byte("marker\n"), 0o600))
	}
	sb, err := agenttools.NewSandbox(root)
	require.NoError(t, err)

	fake := &fakeToolClient{
		fn: func(call int, _ []clients.Message, _ []clients.ToolDefinition) *clients.ToolGenerateResponse {
			if call == 0 {
				return &clients.ToolGenerateResponse{
					ToolCalls: []clients.ToolCall{
						{ID: "s1", Name: "search_code", Arguments: `{"query":"marker"}`},
					},
				}
			}
			return &clients.ToolGenerateResponse{}
		},
	}
	agent := agenticAgent(sb)
	agent.verificationLLMClient = fake

	result, err := agent.exploreForEvidence(context.Background(), "sys", "user", "a/b/c/flagged.go",
		&VerificationTelemetry{})
	require.NoError(t, err)
	require.Len(t, result.Events, 1)

	var decoded struct {
		SearchScope struct {
			PathGlob string `json:"path_glob"`
		} `json:"search_scope"`
		Matches []struct {
			Path string `json:"path"`
		} `json:"matches"`
	}
	require.NoError(t, json.Unmarshal([]byte(result.Events[0].Result), &decoded))

	assert.Equal(t, "a/b/c/**", decoded.SearchScope.PathGlob,
		"an omitted path_glob must anchor at the flagged file's directory")
	require.NotEmpty(t, decoded.Matches)
	for _, m := range decoded.Matches {
		assert.True(t, strings.HasPrefix(m.Path, "a/b/c/"), "match escaped the anchored scope: %s", m.Path)
	}
}
