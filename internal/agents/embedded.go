package agents

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

//go:embed *.md
var EmbeddedAgentRules embed.FS

// languageGlobs maps the language token in a rule filename (the second segment
// of `datadog-{language}-{rule}.md`) to the file globs the rule should match.
var languageGlobs = map[string][]string{
	"go":     {"**/*.go"},
	"java":   {"**/*.java"},
	"python": {"**/*.py"},
}

// LoadLocalRules returns one api.AiPrompt per embedded *.md file in this
// package. The filename (without extension) is converted to a rule ID by
// replacing the first dash with a slash: "datadog-go-sqli.md" -> "datadog/go-sqli".
// When the language token in the filename maps to a known glob, the rule is
// scoped to that language; otherwise it falls back to "**/*".
func LoadLocalRules() ([]api.AiPrompt, error) {
	entries, err := fs.ReadDir(EmbeddedAgentRules, ".")
	if err != nil {
		return nil, fmt.Errorf("reading embedded agent rules: %w", err)
	}
	var rules []api.AiPrompt
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		content, err := EmbeddedAgentRules.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}
		name := strings.TrimSuffix(entry.Name(), ".md")
		rules = append(rules, api.AiPrompt{
			ID:       strings.Replace(name, "-", "/", 1),
			Content:  string(content),
			Globs:    globsForFilename(name),
			Severity: api.SeverityError,
			Category: api.CategorySecurity,
		})
	}
	return rules, nil
}

func globsForFilename(name string) []string {
	parts := strings.SplitN(name, "-", 3)
	if len(parts) >= 2 {
		if g, ok := languageGlobs[parts[1]]; ok {
			return g
		}
	}
	return []string{"**/*"}
}
