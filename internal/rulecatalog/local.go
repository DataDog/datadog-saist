package rulecatalog

import (
	"fmt"
	"io/fs"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

// languageGlobs maps the language token in a rule filename (the second segment
// of `datadog-{language}-{rule}.md`) to the file globs the rule should match.
var languageGlobs = map[string][]string{
	"go":         {"**/*.go"},
	"java":       {"**/*.java"},
	"python":     {"**/*.py"},
	"csharp":     {"**/*.cs"},
	"javascript": {"**/*.js", "**/*.jsx", "**/*.mjs"},
	"typescript": {"**/*.ts", "**/*.tsx", "**/*.mts", "**/*.cts"},
	"kotlin":     {"**/*.kt", "**/*.kts"},
	"php":        {"**/*.php", "**/*.phtml", "**/*.php3", "**/*.php4", "**/*.php5"},
	"ruby":       {"**/*.rb"},
	"rust":       {"**/*.rs"},
	"elixir":     {"**/*.ex", "**/*.exs"},
	"swift":      {"**/*.swift"},
	"dart":       {"**/*.dart"},
	"cpp":        {"**/*.cc", "**/*.cpp", "**/*.cxx", "**/*.c++", "**/*.hh", "**/*.hpp", "**/*.hxx", "**/*.h++"},
}

// Load derives rule IDs and language globs from markdown filenames.
func Load(rulesFS fs.FS) ([]api.AiPrompt, error) {
	entries, err := fs.ReadDir(rulesFS, ".")
	if err != nil {
		return nil, fmt.Errorf("reading rule directory: %w", err)
	}
	var rules []api.AiPrompt
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		content, err := fs.ReadFile(rulesFS, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		name := strings.TrimSuffix(entry.Name(), ".md")
		rules = append(rules, api.AiPrompt{
			ID:       strings.Replace(name, "-", "/", 1),
			Content:  string(content),
			Globs:    GlobsForFilename(name),
			Severity: api.SeverityError,
			Category: api.CategorySecurity,
		})
	}
	return rules, nil
}

func GlobsForFilename(name string) []string {
	parts := strings.SplitN(name, "-", 3)
	if len(parts) >= 2 {
		if g, ok := languageGlobs[parts[1]]; ok {
			return g
		}
	}
	return []string{"**/*"}
}
