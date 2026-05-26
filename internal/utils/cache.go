package utils

import (
	"path/filepath"

	"github.com/DataDog/datadog-saist/internal/model"
)

// InferLanguagesFromGlobs returns the set of languages whose extensions are
// referenced by any of the provided glob patterns. Globs that don't pin a
// specific language extension (e.g. "**/*") return an empty slice — callers
// treat those rules as universal/all-language.
func InferLanguagesFromGlobs(globs []string) []model.Language {
	seen := map[model.Language]struct{}{}
	for _, g := range globs {
		lang := model.GetLanguage("file" + filepath.Ext(g))
		if lang != model.LanguageUnknown {
			seen[lang] = struct{}{}
		}
	}

	out := make([]model.Language, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	return out
}
