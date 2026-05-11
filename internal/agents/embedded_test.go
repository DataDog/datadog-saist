package agents

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadLocalRules(t *testing.T) {
	rules, err := LoadLocalRules()
	assert.Nil(t, err)
	assert.NotEmpty(t, rules)
}
