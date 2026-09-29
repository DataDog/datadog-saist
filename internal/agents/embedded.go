package agents

import (
	"embed"
	"github.com/DataDog/datadog-saist/internal/model/api"
	"github.com/DataDog/datadog-saist/internal/rulecatalog"
)

//go:embed *.md
var EmbeddedAgentRules embed.FS

func LoadLocalRules() ([]api.AiPrompt, error) {
	return rulecatalog.Load(EmbeddedAgentRules)
}

func globsForFilename(name string) []string {
	return rulecatalog.GlobsForFilename(name)
}
