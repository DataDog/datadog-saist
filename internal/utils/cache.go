package utils

import (
	"strings"

	"github.com/DataDog/datadog-saist/internal/model"
)

func InferLanguagesFromGlobs(globs []string) []model.Language {
	// Extremely lightweight inference; extend as you add rules.
	// We return a set-like slice without duplicates.
	seen := map[model.Language]struct{}{}
	add := func(l model.Language) {
		if l != model.LanguageUnknown {
			seen[l] = struct{}{}
		}
	}

	for _, g := range globs {
		s := strings.ToLower(g)
		switch {
		case strings.Contains(s, ".go"):
			add(model.Go)
		case strings.Contains(s, ".java"):
			add(model.Java)
		case strings.Contains(s, ".py"):
			add(model.Python)
			// add more as needed
		}
	}

	out := make([]model.Language, 0, len(seen))
	for l := range seen {
		out = append(out, l)
	}
	return out
}
