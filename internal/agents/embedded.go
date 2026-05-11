package agents

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

//go:embed *.md
var EmbeddedAgentRules embed.FS

// LoadLocalRules returns one api.AiPrompt per embedded *.md file in this
// package. The filename (without extension) is converted to a rule ID by
// replacing the first dash with a slash: "datadog-go-sqli.md" -> "datadog/go-sqli".
// Each rule runs on every file (Globs="**/*") with default Severity and Category.
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
			Globs:    []string{"**/*"},
			Severity: api.SeverityError,
			Category: api.CategorySecurity,
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}
