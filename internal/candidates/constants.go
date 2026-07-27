package candidates

const (
	SchemaVersion     = 1
	candidateIDDomain = "datadog-saist-candidate-v1"
	maxJSONLLineBytes = 16 << 20

	DetectionModeStandard DetectionMode = "standard"
	DetectionModeAgentic  DetectionMode = "agentic"
)
