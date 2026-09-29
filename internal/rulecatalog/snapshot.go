package rulecatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/DataDog/datadog-saist/internal/model/api"
)

type Provenance struct {
	SchemaVersion int    `json:"schema_version,omitempty"`
	Source        string `json:"source"`
	Policy        string `json:"policy,omitempty"`
	Language      string `json:"language,omitempty"`
	RuleCount     int    `json:"rule_count"`
	RulesSHA256   string `json:"rules_sha256"`
}

func LoadJSON(data []byte) ([]api.AiPrompt, Provenance, error) {
	var provenance Provenance
	var raw json.RawMessage
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, provenance, fmt.Errorf("empty rule snapshot")
	}
	if data[0] == '[' {
		provenance.Source = "unversioned-array"
		raw = data
	} else {
		var envelope struct {
			Provenance
			Rules json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, provenance, err
		}
		provenance = envelope.Provenance
		raw = envelope.Rules
		if provenance.SchemaVersion != SnapshotSchemaVersion {
			return nil, provenance, fmt.Errorf("unsupported rule snapshot version %d", provenance.SchemaVersion)
		}
		if provenance.Source == "" || provenance.Policy == "" {
			return nil, provenance, fmt.Errorf("snapshot lacks source or policy")
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, provenance, err
	}
	sum := sha256.Sum256(compact.Bytes())
	digest := hex.EncodeToString(sum[:])
	if provenance.SchemaVersion != 0 && provenance.RulesSHA256 != digest {
		return nil, provenance, fmt.Errorf("rule snapshot checksum mismatch")
	}
	var rules []api.AiPrompt
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, provenance, err
	}
	if len(rules) == 0 {
		return nil, provenance, fmt.Errorf("snapshot contains no rules")
	}
	if provenance.SchemaVersion != 0 && provenance.RuleCount != len(rules) {
		return nil, provenance, fmt.Errorf("rule snapshot count mismatch")
	}
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule.ID == "" || seen[rule.ID] {
			return nil, provenance, fmt.Errorf("empty or duplicate rule ID %q", rule.ID)
		}
		seen[rule.ID] = true
	}
	provenance.RuleCount = len(rules)
	provenance.RulesSHA256 = digest
	return rules, provenance, nil
}
