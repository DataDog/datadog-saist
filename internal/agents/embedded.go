package agents

import (
	"embed"
	"strings"
)

//go:embed *.md
var EmbeddedAgentRules embed.FS

// GetEmbeddedAgentRule returns the content of an embedded agent rule file.
// The ruleID is converted to a filename by replacing "/" with "-" and appending ".md".
// For example: "datadog/go-cmdi" -> "datadog-go-cmdi.md"
func GetEmbeddedAgentRule(ruleID string) (string, error) {
	filename := strings.ReplaceAll(ruleID, "/", "-") + ".md"
	content, err := EmbeddedAgentRules.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(content), nil
}
