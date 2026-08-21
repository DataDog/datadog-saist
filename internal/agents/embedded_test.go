package agents

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadLocalRules(t *testing.T) {
	rules, err := LoadLocalRules()
	assert.Nil(t, err)
	assert.NotEmpty(t, rules)

	ids := make(map[string]bool)
	for i := range rules {
		ids[rules[i].ID] = true
	}
	assert.True(t, ids["datadog/go-sqli"], "expected datadog-go-sqli.md to produce ID datadog/go-sqli")
}

func TestGlobsForCppRule(t *testing.T) {
	globs := globsForFilename("datadog-cpp-cmdi")
	assert.Contains(t, globs, "**/*.cpp")
	assert.Contains(t, globs, "**/*.hpp")
	assert.NotContains(t, globs, "**/*.c")
	assert.NotContains(t, globs, "**/*.cp")
}
