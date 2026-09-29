package rulecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func snapshotFixture(t *testing.T) []byte {
	t.Helper()
	raw := json.RawMessage(`[{"id":"datadog/go-sqli","content":"Full prompt","rule_version":"0.0.2","file_search_keywords":["sql"],"cwe":"89"}]`)
	digest := sha256.Sum256(raw)
	data, err := json.MarshalIndent(struct {
		Provenance
		Rules json.RawMessage `json:"rules"`
	}{Provenance{SchemaVersion: 1, Source: "shared-catalog", Policy: "all", RuleCount: 1, RulesSHA256: hex.EncodeToString(digest[:])}, raw}, "", "  ")
	assert.NoError(t, err)
	return data
}

func TestSnapshotPreservesMetadataAndValidatesDigest(t *testing.T) {
	rules, provenance, err := LoadJSON(snapshotFixture(t))
	if !assert.NoError(t, err) || !assert.Len(t, rules, 1) {
		return
	}
	assert.Equal(t, "Full prompt", rules[0].Content)
	assert.Equal(t, []string{"sql"}, rules[0].FileSearchKeywords)
	assert.Equal(t, "0.0.2", rules[0].Version)
	if assert.NotNil(t, rules[0].Cwe) {
		assert.Equal(t, "89", *rules[0].Cwe)
	}
	assert.Equal(t, 1, provenance.RuleCount)
	assert.NotEmpty(t, provenance.RulesSHA256)
}

func TestSnapshotRejectsModifiedContent(t *testing.T) {
	data := strings.Replace(string(snapshotFixture(t)), "Full prompt", "Altered prompt", 1)
	_, _, err := LoadJSON([]byte(data))
	assert.ErrorContains(t, err, "checksum mismatch")
}

func TestSnapshotRejectsUnsupportedVersion(t *testing.T) {
	data := strings.Replace(string(snapshotFixture(t)), `"schema_version": 1`, `"schema_version": 2`, 1)
	_, _, err := LoadJSON([]byte(data))
	assert.ErrorContains(t, err, "unsupported")
}

func TestSnapshotRejectsCountMismatch(t *testing.T) {
	data := strings.Replace(string(snapshotFixture(t)), `"rule_count": 1`, `"rule_count": 2`, 1)
	_, _, err := LoadJSON([]byte(data))
	assert.ErrorContains(t, err, "count mismatch")
}

func TestUnversionedArraysRemainSupported(t *testing.T) {
	rules, provenance, err := LoadJSON([]byte(`[{"id":"custom/rule"}]`))
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.Equal(t, "unversioned-array", provenance.Source)
}

func TestDuplicateRulesAreRejected(t *testing.T) {
	_, _, err := LoadJSON([]byte(`[{"id":"same"},{"id":"same"}]`))
	assert.ErrorContains(t, err, "duplicate")
}
