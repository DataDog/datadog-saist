package analysis

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestConfigureReplayUsesManifestRulesAndSourceRevision(t *testing.T) {
	repositoryRoot, repositorySHA := createRevisionTestRepository(t)
	replayPath := filepath.Join(t.TempDir(), "candidates.jsonl")

	opts, err := configure(
		context.Background(),
		repositoryRoot,
		model.OpenAIGPT5MiniName,
		model.OpenAIGPT5MiniName,
		false,
		"",
		30,
		1,
		false,
		false,
		false,
		"",
		"",
		1,
		"repository",
		false,
		false,
		false,
		6,
		16,
		"",
		replayPath,
		false,
	)

	assert.NoError(t, err)
	assert.Empty(t, opts.Rules)
	assert.Equal(t, repositoryRoot, opts.RepositoryRoot)
	assert.Equal(t, repositorySHA, opts.RepositorySHA)
	assert.False(t, opts.RepositoryDirty)
	assert.Equal(t, replayPath, opts.ReplayCandidatesPath)
}
