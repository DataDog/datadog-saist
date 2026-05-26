package utils

import (
	"testing"

	"github.com/DataDog/datadog-saist/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestInferLanguagesFromGlobs(t *testing.T) {
	tests := []struct {
		name  string
		globs []string
		want  []model.Language
	}{
		{
			name:  "go",
			globs: []string{"**/*.go"},
			want:  []model.Language{model.Go},
		},
		{
			name:  "java",
			globs: []string{"**/*.java"},
			want:  []model.Language{model.Java},
		},
		{
			name:  "python",
			globs: []string{"**/*.py"},
			want:  []model.Language{model.Python},
		},
		{
			name:  "python alt extension",
			globs: []string{"**/*.py3"},
			want:  []model.Language{model.Python},
		},
		{
			name:  "csharp",
			globs: []string{"**/*.cs"},
			want:  []model.Language{model.CSharp},
		},
		{
			name:  "javascript single extension",
			globs: []string{"**/*.js"},
			want:  []model.Language{model.JavaScript},
		},
		{
			name:  "javascript multi-extension dedupes to one language",
			globs: []string{"**/*.js", "**/*.jsx", "**/*.mjs"},
			want:  []model.Language{model.JavaScript},
		},
		{
			name:  "mixed languages",
			globs: []string{"**/*.go", "**/*.py"},
			want:  []model.Language{model.Go, model.Python},
		},
		{
			name:  "universal glob returns empty (caller treats as all-language)",
			globs: []string{"**/*"},
			want:  []model.Language{},
		},
		{
			name:  "nil glob list returns empty",
			globs: nil,
			want:  []model.Language{},
		},
		{
			name:  "unknown extension returns empty",
			globs: []string{"**/*.rs"},
			want:  []model.Language{},
		},
		{
			name:  "uppercase glob still matches",
			globs: []string{"**/*.GO"},
			want:  []model.Language{model.Go},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := InferLanguagesFromGlobs(tc.globs)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}
