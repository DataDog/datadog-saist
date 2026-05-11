package agents

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

//go:embed *.md
var embeddedAgentRules embed.FS

type localRuleFrontmatter struct {
	ID                    string   `yaml:"id"`
	ShortDescription      string   `yaml:"short_description"`
	Description           string   `yaml:"description"`
	Severity              string   `yaml:"severity"`
	Category              string   `yaml:"category"`
	Cwe                   string   `yaml:"cwe"`
	Globs                 []string `yaml:"globs"`
	Directories           []string `yaml:"directories"`
	ExecutionMode         string   `yaml:"execution_mode"`
	FileSearchKeywords    []string `yaml:"file_search_keywords"`
	ResultKeywordsExclude []string `yaml:"result_keywords_exclude"`
	Version               string   `yaml:"version"`
}

var frontmatterDelimiter = []byte("---")

// LoadLocalRules returns one api.AiPrompt per embedded *.md file that carries
// YAML frontmatter. Files without frontmatter are returned in the skipped slice;
// malformed frontmatter is returned as an error rather than skipped silently.
func LoadLocalRules() ([]api.AiPrompt, []string, error) {
	entries, err := fs.ReadDir(embeddedAgentRules, ".")
	if err != nil {
		return nil, nil, fmt.Errorf("reading embedded agent rules: %w", err)
	}

	var rules []api.AiPrompt
	var skipped []string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		raw, err := embeddedAgentRules.ReadFile(entry.Name())
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
		}

		front, body, ok := splitFrontmatter(raw)
		if !ok {
			skipped = append(skipped, entry.Name())
			continue
		}

		var fm localRuleFrontmatter
		if err := yaml.Unmarshal(front, &fm); err != nil {
			return nil, nil, fmt.Errorf("parsing frontmatter in %s: %w", entry.Name(), err)
		}
		if fm.ID == "" {
			return nil, nil, fmt.Errorf("frontmatter in %s is missing required field 'id'", entry.Name())
		}

		rules = append(rules, fm.toAiPrompt(string(body)))
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	sort.Strings(skipped)
	return rules, skipped, nil
}

func splitFrontmatter(raw []byte) ([]byte, []byte, bool) {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if !bytes.HasPrefix(trimmed, frontmatterDelimiter) {
		return nil, raw, false
	}
	rest := trimmed[len(frontmatterDelimiter):]
	// Require the opening delimiter to be on its own line.
	if len(rest) == 0 || (rest[0] != '\n' && rest[0] != '\r') {
		return nil, raw, false
	}
	closeIdx := bytes.Index(rest, append([]byte("\n"), frontmatterDelimiter...))
	if closeIdx < 0 {
		return nil, raw, false
	}
	front := rest[:closeIdx]
	body := rest[closeIdx+1+len(frontmatterDelimiter):]
	body = bytes.TrimLeft(body, "\r\n")
	return front, body, true
}

func (fm localRuleFrontmatter) toAiPrompt(body string) api.AiPrompt {
	prompt := api.AiPrompt{
		ID:                    fm.ID,
		ShortDescription:      fm.ShortDescription,
		Description:           fm.Description,
		Content:               body,
		Globs:                 fm.Globs,
		Directories:           fm.Directories,
		Severity:              api.Severity(fm.Severity),
		Category:              api.Category(fm.Category),
		FileSearchKeywords:    fm.FileSearchKeywords,
		ResultKeywordsExclude: fm.ResultKeywordsExclude,
		Version:               fm.Version,
	}
	if fm.Cwe != "" {
		cwe := fm.Cwe
		prompt.Cwe = &cwe
	}
	if fm.ExecutionMode != "" {
		prompt.ExecutionMode = api.ExecutionMode(fm.ExecutionMode)
	} else {
		prompt.ExecutionMode = api.ExecutionModeAuto
	}
	return prompt
}
