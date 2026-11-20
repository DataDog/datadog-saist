package sarif

const toolName = "datadog-ai-static-analyzer"
const toolInformationURI = "https://github.com/DataDog/datadog-saist"

const ruleSuccessTag = "RULE_SUCCESS"
const ruleFailureTag = "RULE_FAILURE"
const ruleSkippedTag = "RULE_SKIPPED"
const inputTokensTag = "DATADOG_SAIST_INPUT_TOKENS"   // nolint: gosec
const outputTokensTag = "DATADOG_SAIST_OUTPUT_TOKENS" // nolint: gosec
const cweTag = "CWE"
const ruleTypeTag = "DATADOG_RULE_TYPE"
const tagsKey = "tags"
const confidenceTag = "DATADOG_CONFIDENCE"
const confidenceReasonTag = "DATADOG_CONFIDENCE_REASON"
const highConfidence = "HIGH"
