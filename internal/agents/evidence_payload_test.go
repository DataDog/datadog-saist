package agents

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSerializeEvidencePayloadIsDeterministicAndCanonical(t *testing.T) {
	// Same logical arguments, different key order, must canonicalize identically.
	eventsA := []EvidenceEvent{
		NewEvidenceEvent(1, "call_1", "search_code", `{"pattern":"Query","path_glob":"internal/**/*.go"}`, "executed", `{"matches":[]}`),
	}
	eventsB := []EvidenceEvent{
		NewEvidenceEvent(1, "call_1", "search_code", `{"path_glob":"internal/**/*.go","pattern":"Query"}`, "executed", `{"matches":[]}`),
	}

	a1, err := SerializeEvidencePayload(eventsA)
	require.NoError(t, err)
	a2, err := SerializeEvidencePayload(eventsA)
	require.NoError(t, err)
	b, err := SerializeEvidencePayload(eventsB)
	require.NoError(t, err)

	assert.Equal(t, a1, a2, "serialization must be deterministic")
	assert.Equal(t, a1, b, "argument key order must not change the serialization")
	assert.Equal(t, EvidencePayloadHash(a1), EvidencePayloadHash(b), "canonical payloads must hash equally")
}

func TestEvidencePayloadPreservesResultBytesForByte(t *testing.T) {
	// Result content with newlines, quotes, and unicode must round-trip exactly.
	raw := "line one\n\t\"quoted\"\r\nunicode: é✓ end"
	events := []EvidenceEvent{
		NewEvidenceEvent(1, "call_1", "read_file", `{"path":"a.go"}`, "executed", raw),
	}
	payload, err := SerializeEvidencePayload(events)
	require.NoError(t, err)

	var decoded EvidencePayload
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Len(t, decoded.Events, 1)
	assert.Equal(t, raw, decoded.Events[0].Result, "result content must reconstruct byte-for-byte")
	assert.Equal(t, len([]byte(raw)), decoded.Events[0].ResultBytes)
}

func TestEvidencePayloadPreservesOrder(t *testing.T) {
	events := []EvidenceEvent{
		NewEvidenceEvent(1, "c1", "list_directory", `{"path":"."}`, "executed", `{"entries":["a"]}`),
		NewEvidenceEvent(2, "c2", "read_file", `{"path":"a.go"}`, "executed", `{"content":"x"}`),
		NewEvidenceEvent(3, "c3", "search_code", `{"pattern":"y"}`, "duplicate", `{"note":"duplicate"}`),
	}
	payload, err := SerializeEvidencePayload(events)
	require.NoError(t, err)

	var decoded EvidencePayload
	require.NoError(t, json.Unmarshal(payload, &decoded))
	require.Len(t, decoded.Events, 3)
	assert.Equal(t, 1, decoded.Events[0].Sequence)
	assert.Equal(t, "c2", decoded.Events[1].ToolCallID)
	assert.Equal(t, "duplicate", decoded.Events[2].Disposition)
}

func TestCanonicalizeNonJSONArgumentsPreserved(t *testing.T) {
	event := NewEvidenceEvent(1, "c1", "read_file", "not-json", "invalid_arguments", `{"error":"bad"}`)
	// Non-JSON arguments are preserved verbatim as a JSON string.
	assert.Equal(t, `"not-json"`, string(event.Arguments))
}

func TestEvidenceEnvelopeIsDataOnly(t *testing.T) {
	payload, err := SerializeEvidencePayload([]EvidenceEvent{
		NewEvidenceEvent(1, "c1", "read_file", `{"path":"a.go"}`, "executed", `{"content":"x"}`),
	})
	require.NoError(t, err)
	envelope := RenderEvidenceEnvelope(payload)

	assert.True(t, strings.HasPrefix(envelope, EvidenceEnvelopeHeader), "envelope must start with the header")
	assert.Contains(t, envelope, string(payload), "envelope must contain the exact payload")

	// The header frames data and must not instruct the decision.
	lowerHeader := strings.ToLower(EvidenceEnvelopeHeader)
	for _, directive := range []string{"confirm", "reject", "verdict", "keep", "omit", "true positive", "false positive"} {
		assert.NotContains(t, lowerHeader, directive, "envelope header must not contain a decision directive")
	}
}

func TestEmptyEvidencePayloadSerializes(t *testing.T) {
	payload, err := SerializeEvidencePayload(nil)
	require.NoError(t, err)
	var decoded EvidencePayload
	require.NoError(t, json.Unmarshal(payload, &decoded))
	assert.Equal(t, evidencePayloadVersion, decoded.Version)
	assert.Empty(t, decoded.Events)
}
