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
	assert.True(t, ids["datadog/kotlin-sqli"], "expected datadog-kotlin-sqli.md to produce ID datadog/kotlin-sqli")
	assert.True(t, ids["datadog/swift-sqli"], "expected datadog-swift-sqli.md to produce ID datadog/swift-sqli")
}
